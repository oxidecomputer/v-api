// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use http::Method;
use hyper::{body::Bytes, header::HeaderValue, header::AUTHORIZATION};
use newtype_uuid::TypedUuid;
use oauth2::{
    basic::BasicClient, url::ParseError, AuthUrl, ClientId, ClientSecret, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, RedirectUrl, RevocationUrl, TokenUrl,
};
use reqwest::Request;
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};
use thiserror::Error;
use tracing::instrument;
use v_model::{OAuthClient, OAuthClientId};

use crate::{
    authn::{key::RawKey, Verify},
    secrets::OpenApiSecretString,
};

use super::{is_redirect_uri_valid, UserInfo, UserInfoError, UserInfoProvider};

pub mod client;
pub mod flow;
pub mod remote;

#[derive(Debug, Error)]
pub enum OAuthProviderError {
    #[error("Unable to instantiate invalid provider")]
    FailToCreateInvalidProvider,
    #[error("Missing redirect URI")]
    MissingRedirectUri,
    #[error("Failed to parse URL")]
    UrlParseError(#[from] ParseError),
    #[error("Provider does not support web clients")]
    WebClientNotSupported,
}

#[derive(Debug)]
pub enum ClientType {
    Device,
    Web,
    WebPkce,
}

pub type WebClient = BasicClient<
    // HasAuthUrl
    EndpointSet,
    // HasDeviceAuthUrl
    EndpointNotSet,
    // HasIntrospectionUrl
    EndpointNotSet,
    // HasRevocationUrl
    EndpointMaybeSet,
    // HasTokenUrl
    EndpointSet,
>;

pub trait OAuthProvider: ExtractUserInfo + Debug + Send + Sync {
    fn name(&self) -> OAuthProviderName;
    fn initialize_headers(&self, request: &mut Request);
    fn client(&self) -> &reqwest::Client;
    fn user_info_endpoints(&self) -> Vec<&str>;

    fn authz_code_flow_info(&self) -> Option<&OAuthProviderAuthorizationCodeInfo>;
    fn authz_code_pkce_flow_info(&self) -> Option<&OAuthProviderAuthorizationCodePkceInfo>;
    fn device_code_flow_info(&self) -> Option<&OAuthProviderDeviceInfo>;

    fn default_scopes(&self) -> &[String];

    /// Whether the remote OAuth provider supports PKCE (RFC 7636). Providers must
    /// explicitly declare this. This controls whether v-api sends a PKCE challenge
    /// to the remote provider during the authorization code exchange. Note: clients
    /// calling v-api are always required to use PKCE regardless of this setting.
    fn supports_pkce(&self) -> bool;

    fn as_web_client(&self) -> Result<WebClient, OAuthProviderError> {
        match self.authz_code_flow_info() {
            Some(info) => {
                let client = BasicClient::new(ClientId::new(info.remote.client_id.clone()))
                    .set_auth_uri(AuthUrl::new(info.remote.auth_url_endpoint.clone())?)
                    .set_token_uri(TokenUrl::new(info.remote.token_endpoint.clone())?)
                    .set_revocation_url_option(
                        info.remote
                            .revocation_endpoint
                            .as_ref()
                            .map(|url| RevocationUrl::new(url.to_string()))
                            .transpose()?,
                    )
                    .set_redirect_uri(RedirectUrl::new(info.redirect_endpoint.to_string())?)
                    .set_client_secret(ClientSecret::new(
                        info.remote.client_secret.0.expose_secret().to_string(),
                    ));

                Ok(client)
            }
            None => Err(OAuthProviderError::WebClientNotSupported),
        }
    }
}

pub trait ExtractUserInfo {
    fn extract_user_info(&self, data: &[Bytes]) -> Result<UserInfo, UserInfoError>;
}

// Trait describing an factory function for constructing an OAuthProvider
pub trait OAuthProviderFn: Fn() -> Box<dyn OAuthProvider + Send + Sync> + Send + Sync {}
impl<T> OAuthProviderFn for T where T: Fn() -> Box<dyn OAuthProvider + Send + Sync> + Send + Sync {}

// Add a blanket implementation of the user information extractor for all OAuth providers. This
// handles the common calling code to the provider's user information calling code and then
// delegates the deserialization/information extraction to the provider.
#[async_trait]
impl<T> UserInfoProvider for T
where
    T: OAuthProvider + ExtractUserInfo + Send + Sync + ?Sized,
{
    #[instrument(skip(token))]
    async fn get_user_info(&self, token: &str) -> Result<UserInfo, UserInfoError> {
        tracing::trace!("Requesting user information from OAuth provider");

        let mut responses = vec![];

        for endpoint in self.user_info_endpoints() {
            let mut request = Request::new(Method::GET, endpoint.parse().unwrap());
            self.initialize_headers(&mut request);

            let headers = request.headers_mut();
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
            );

            let response = self.client().execute(request).await?;
            let status = response.status();

            tracing::trace!(?status, "Received response from OAuth provider");

            if !status.is_success() {
                tracing::error!(?status, endpoint, "User info endpoint returned non-success status");
                return Err(UserInfoError::UnexpectedStatus {
                    endpoint: endpoint.to_string(),
                    status,
                });
            }

            let bytes = response.bytes().await?;
            responses.push(bytes);
        }

        let mut info = self.extract_user_info(&responses)?;
        info.idp_token = Some(token.to_string());
        Ok(info)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OAuthProviderInfo {
    provider: OAuthProviderName,
    client_id: String,
    code: Option<OAuthProviderAuthorizationCodeInfo>,
    pkce: Option<OAuthProviderAuthorizationCodePkceInfo>,
    device: Option<OAuthProviderDeviceInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OAuthProviderAuthorizationCodeInfo {
    auth_url_endpoint: String,
    redirect_endpoint: String,
    token_endpoint_content_type: String,
    token_endpoint: String,
    remote: OAuthProviderAuthorizationCodeRemoteInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OAuthProviderAuthorizationCodeRemoteInfo {
    client_id: String,
    client_secret: OpenApiSecretString,
    auth_url_endpoint: String,
    token_endpoint_content_type: String,
    token_endpoint: String,
    revocation_endpoint: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OAuthProviderAuthorizationCodePkceInfo {
    client_id: TypedUuid<OAuthClientId>,
    redirect_endpoint: String,
    proxy_port: u16,
    web: OAuthProviderAuthorizationCodeInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OAuthProviderDeviceInfo {
    client_id: TypedUuid<OAuthClientId>,
    remote_client_id: String,
    remote_client_secret: OpenApiSecretString,
    device_code_endpoint: String,
    token_endpoint_content_type: String,
    token_endpoint: String,
    revocation_endpoint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OAuthProviderName {
    #[serde(rename = "github")]
    GitHub,
    Google,
    Zendesk,
}

impl Display for OAuthProviderName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuthProviderName::GitHub => write!(f, "github"),
            OAuthProviderName::Google => write!(f, "google"),
            OAuthProviderName::Zendesk => write!(f, "zendesk"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct OAuthProviderNameParam {
    provider: OAuthProviderName,
}

pub trait CheckOAuthClient {
    fn is_secret_valid<T>(&self, key: &RawKey, verifier: &T) -> bool
    where
        T: Verify;
    fn is_redirect_uri_valid(&self, redirect_uri: &str) -> bool;
}

impl CheckOAuthClient for OAuthClient {
    fn is_secret_valid<T>(&self, key: &RawKey, verifier: &T) -> bool
    where
        T: Verify,
    {
        for secret in &self.secrets {
            match key.verify(verifier, secret.secret_signature.as_bytes()) {
                Ok(_) => return true,
                Err(err) => {
                    tracing::error!(?err, ?secret.id, "Client contains an invalid secret signature");
                }
            }
        }

        false
    }

    fn is_redirect_uri_valid(&self, redirect_uri: &str) -> bool {
        tracing::trace!(?redirect_uri, valid_uris = ?self.redirect_uris, "Checking redirect uri against list of valid uris");
        is_redirect_uri_valid(
            redirect_uri,
            self.redirect_uris.iter().map(|r| r.redirect_uri.as_str()),
        )
    }
}
