// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use http::Method;
use hyper::{
    body::{to_bytes, Bytes},
    client::HttpConnector,
    header::HeaderValue,
    header::AUTHORIZATION,
    Body, Client, Request,
};
use hyper_rustls::HttpsConnector;
use oauth2::{
    basic::BasicClient, url::ParseError, AuthUrl, ClientId, ClientSecret, RedirectUrl,
    RevocationUrl, TokenUrl,
};
use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};
use thiserror::Error;
use tracing::instrument;
use v_model::OAuthClient;

use crate::authn::{key::RawKey, Signer};

use super::{UserInfo, UserInfoError, UserInfoProvider};

pub mod client;
pub mod code;
pub mod device_token;
pub mod github;
pub mod google;

#[derive(Debug, Error)]
pub enum OAuthProviderError {
    #[error("Unable to instantiate invalid provider")]
    FailToCreateInvalidProvider,
}

#[derive(Debug)]
pub enum ClientType {
    Device,
    Web { prefix: String },
}

pub struct OAuthPublicCredentials {
    client_id: String,
}

pub struct OAuthPrivateCredentials {
    client_secret: SecretString,
}

pub trait OAuthProvider: ExtractUserInfo + Debug + Send + Sync {
    fn name(&self) -> OAuthProviderName;
    fn scopes(&self) -> Vec<&str>;
    fn start_request(&self) -> Request<Body>;
    fn client(&self) -> &Client<HttpsConnector<HttpConnector>>;
    fn client_id(&self, client_type: &ClientType) -> &str;
    fn client_secret(&self, client_type: &ClientType) -> Option<&SecretString>;

    // TODO: How can user info be change to something statically checked instead of a runtime check
    fn user_info_endpoints(&self) -> Vec<&str>;
    fn device_code_endpoint(&self) -> &str;
    fn auth_url_endpoint(&self) -> &str;
    fn token_exchange_content_type(&self) -> &str;
    fn token_exchange_endpoint(&self) -> &str;
    fn token_revocation_endpoint(&self) -> Option<&str>;
    fn supports_pkce(&self) -> bool;

    fn provider_info(&self, public_url: &str, client_type: &ClientType) -> OAuthProviderInfo {
        OAuthProviderInfo {
            provider: self.name(),
            client_id: self.client_id(client_type).to_string(),
            auth_url_endpoint: self.auth_url_endpoint().to_string(),
            device_code_endpoint: self.device_code_endpoint().to_string(),
            token_endpoint: format!("{}/login/oauth/{}/device/exchange", public_url, self.name(),),
            scopes: self
                .scopes()
                .into_iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        }
    }

    fn as_client(&self, client_type: &ClientType) -> Result<BasicClient, ParseError> {
        let mut client = BasicClient::new(
            ClientId::new(self.client_id(client_type).to_string()),
            self.client_secret(client_type)
                .map(|s| ClientSecret::new(s.expose_secret().to_string())),
            AuthUrl::new(self.auth_url_endpoint().to_string())?,
            Some(TokenUrl::new(self.token_exchange_endpoint().to_string())?),
        );

        if let Some(revocation_endpoint) = self.token_revocation_endpoint() {
            client =
                client.set_revocation_uri(RevocationUrl::new(revocation_endpoint.to_string())?);
        }

        // If we are asked for a web client we need to attach a redirect uri
        Ok(match client_type {
            ClientType::Web { prefix } => {
                let redirect_url = RedirectUrl::new(format!(
                    "{}/login/oauth/{}/code/callback",
                    prefix,
                    self.name()
                ))?;

                client.set_redirect_uri(redirect_url)
            }
            _ => client,
        })
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
            let mut request = self.start_request();
            *request.method_mut() = Method::GET;
            *request.uri_mut() = endpoint.parse().unwrap();

            let headers = request.headers_mut();
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
            );

            let response = self.client().request(request).await?;

            tracing::trace!(status = ?response.status(), "Received response from OAuth provider");

            let bytes = to_bytes(response.into_body()).await?;
            responses.push(bytes);
        }

        self.extract_user_info(&responses)
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct OAuthProviderInfo {
    provider: OAuthProviderName,
    client_id: String,
    auth_url_endpoint: String,
    device_code_endpoint: String,
    token_endpoint: String,
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Hash, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum OAuthProviderName {
    #[serde(rename = "github")]
    GitHub,
    Google,
}

impl Display for OAuthProviderName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuthProviderName::GitHub => write!(f, "github"),
            OAuthProviderName::Google => write!(f, "google"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct OAuthProviderNameParam {
    provider: OAuthProviderName,
}

pub trait CheckOAuthClient {
    fn is_secret_valid(&self, key: &RawKey, signer: &dyn Signer) -> bool;
    fn is_redirect_uri_valid(&self, redirect_uri: &str) -> bool;
}

impl CheckOAuthClient for OAuthClient {
    fn is_secret_valid(&self, key: &RawKey, signer: &dyn Signer) -> bool {
        for secret in &self.secrets {
            match key.verify(signer, secret.secret_signature.as_bytes()) {
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
        self.redirect_uris
            .iter()
            .any(|r| r.redirect_uri == redirect_uri)
    }
}
