// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

pub struct GoogleOAuthProvider {
    device_public: OAuthPublicCredentials,
    device_private: Option<OAuthPrivateCredentials>,
    web_public: OAuthPublicCredentials,
    web_private: Option<OAuthPrivateCredentials>,
    additional_scopes: Vec<String>,
    client: Client<HttpsConnector<HttpConnector>>,
}

impl fmt::Debug for GoogleOAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoogleOAuthProvider").finish()
    }
}

impl GoogleOAuthProvider {
    pub fn new(
        device_client_id: String,
        device_client_secret: SecretString,
        web_client_id: String,
        web_client_secret: SecretString,
        additional_scopes: Option<Vec<String>>,
    ) -> Self {
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
            client,
        }
    }

    pub fn with_client(&mut self, client: Client<HttpsConnector<HttpConnector>>) -> &mut Self {
        self.client = client;
        self
    }
}

#[derive(Debug, Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: String,
    email_verified: bool,
}

impl ExtractUserInfo for GoogleOAuthProvider {
    // There should always be as many entries in the data list as there are endpoints. This should
    // be changed in the future to be a static check
    fn extract_user_info(&self, data: &[Bytes]) -> Result<UserInfo, UserInfoError> {
        let remote_info: GoogleUserInfo = serde_json::from_slice(&data[0])?;
        let verified_emails = if remote_info.email_verified {
            vec![remote_info.email]
        } else {
            vec![]
        };

        Ok(UserInfo {
            external_id: ExternalUserId::Google(remote_info.sub),
            verified_emails,
            github_username: None,
        })
    }
}

impl OAuthProvider for GoogleOAuthProvider {
    fn name(&self) -> OAuthProviderName {
        OAuthProviderName::Google
    }

    fn scopes(&self) -> Vec<&str> {
        let mut default = vec!["openid", "email"];
        default.extend(self.additional_scopes.iter().map(|s| s.as_str()));
        default
    }

    fn start_request(&self) -> Request<Body> {
        Request::new(Body::empty())
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
        vec!["https://openidconnect.googleapis.com/v1/userinfo"]
    }

    fn device_code_endpoint(&self) -> &str {
        "https://oauth2.googleapis.com/device/code"
    }

    fn auth_url_endpoint(&self) -> &str {
        "https://accounts.google.com/o/oauth2/v2/auth"
    }

    fn token_exchange_content_type(&self) -> &str {
        "application/x-www-form-urlencoded"
    }

    fn token_exchange_endpoint(&self) -> &str {
        "https://oauth2.googleapis.com/token"
    }

    fn token_revocation_endpoint(&self) -> Option<&str> {
        Some("https://oauth2.googleapis.com/revoke")
    }

    fn supports_pkce(&self) -> bool {
        true
    }
}
