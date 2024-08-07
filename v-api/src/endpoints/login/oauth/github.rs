// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use http::{header::USER_AGENT, HeaderMap, HeaderValue};
use hyper::{body::Bytes, client::HttpConnector, Body, Client, Request};
use hyper_rustls::HttpsConnector;
use secrecy::SecretString;
use serde::Deserialize;
use std::fmt;

use crate::endpoints::login::{ExternalUserId, UserInfo, UserInfoError};

use super::{
    ClientType, ExtractUserInfo, OAuthPrivateCredentials, OAuthProvider, OAuthProviderName,
    OAuthPublicCredentials,
};

pub struct GitHubOAuthProvider {
    // public: GitHubPublicProvider,
    // private: Option<GitHubPrivateProvider>,
    device_public: OAuthPublicCredentials,
    device_private: Option<OAuthPrivateCredentials>,
    web_public: OAuthPublicCredentials,
    web_private: Option<OAuthPrivateCredentials>,
    additional_scopes: Vec<String>,
    default_headers: HeaderMap,
    client: Client<HttpsConnector<HttpConnector>>,
}

impl fmt::Debug for GitHubOAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitHubOAuthProvider").finish()
    }
}

impl GitHubOAuthProvider {
    pub fn new(
        device_client_id: String,
        device_client_secret: SecretString,
        web_client_id: String,
        web_client_secret: SecretString,
        additional_scopes: Option<Vec<String>>,
    ) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("v-api"));

        let client = Client::builder().build(
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .unwrap()
                .https_only()
                .enable_http2()
                .build(),
        );

        Self {
            device_public: OAuthPublicCredentials {
                client_id: device_client_id,
            },
            device_private: Some(OAuthPrivateCredentials {
                client_secret: device_client_secret,
            }),
            web_public: OAuthPublicCredentials {
                client_id: web_client_id,
            },
            web_private: Some(OAuthPrivateCredentials {
                client_secret: web_client_secret,
            }),
            additional_scopes: additional_scopes.unwrap_or_default(),
            default_headers: headers,
            client,
        }
    }

    pub fn with_client(&mut self, client: Client<HttpsConnector<HttpConnector>>) -> &mut Self {
        self.client = client;
        self
    }
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: u32,
    login: String,
}

#[derive(Debug, Deserialize)]
struct GitHubUserEmails {
    email: String,
    verified: bool,
}

impl ExtractUserInfo for GitHubOAuthProvider {
    // There should always be as many entries in the data list as there are endpoints. This should
    // be changed in the future to be a static check
    fn extract_user_info(&self, data: &[Bytes]) -> Result<UserInfo, UserInfoError> {
        tracing::debug!("Extracting user information from GitHub responses");

        let user: GitHubUser = serde_json::from_slice(&data[0])?;

        let remote_emails: Vec<GitHubUserEmails> = serde_json::from_slice(&data[1])?;
        let verified_emails = remote_emails
            .into_iter()
            .filter(|email| email.verified)
            .map(|e| e.email)
            .collect::<Vec<_>>();

        Ok(UserInfo {
            external_id: ExternalUserId::GitHub(user.id.to_string()),
            verified_emails,
            github_username: Some(user.login),
        })
    }
}

impl OAuthProvider for GitHubOAuthProvider {
    fn name(&self) -> OAuthProviderName {
        OAuthProviderName::GitHub
    }

    fn scopes(&self) -> Vec<&str> {
        let mut default = vec!["user:email"];
        default.extend(self.additional_scopes.iter().map(|s| s.as_str()));
        default
    }

    fn start_request(&self) -> Request<Body> {
        let mut request = Request::new(Body::empty());
        *request.headers_mut() = self.default_headers.clone();

        request
    }

    fn client(&self) -> &Client<HttpsConnector<HttpConnector>> {
        &self.client
    }

    fn client_id(&self, client_type: &ClientType) -> &str {
        match client_type {
            ClientType::Device => &self.device_public.client_id,
            ClientType::Web { .. } => &self.web_public.client_id,
        }
    }

    fn client_secret(&self, client_type: &ClientType) -> Option<&SecretString> {
        match client_type {
            ClientType::Device => self
                .device_private
                .as_ref()
                .map(|private| &private.client_secret),
            ClientType::Web { .. } => self
                .web_private
                .as_ref()
                .map(|private| &private.client_secret),
        }
    }

    fn user_info_endpoints(&self) -> Vec<&str> {
        vec![
            "https://api.github.com/user",
            "https://api.github.com/user/emails",
        ]
    }

    fn device_code_endpoint(&self) -> &str {
        "https://github.com/login/device/code"
    }

    fn auth_url_endpoint(&self) -> &str {
        "https://github.com/login/oauth/authorize"
    }

    fn token_exchange_content_type(&self) -> &str {
        "application/x-www-form-urlencoded"
    }

    fn token_exchange_endpoint(&self) -> &str {
        "https://github.com/login/oauth/access_token"
    }

    fn token_revocation_endpoint(&self) -> Option<&str> {
        None
    }

    fn supports_pkce(&self) -> bool {
        true
    }
}
