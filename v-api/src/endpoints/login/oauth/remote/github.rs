// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use http::{HeaderMap, HeaderValue, header::USER_AGENT};
use hyper::body::Bytes;
use reqwest::Request;
use serde::Deserialize;
use std::fmt;

use crate::{
    config::ResolvedOAuthConfig,
    endpoints::login::{
        ExternalUserId, UserInfo, UserInfoError,
        oauth::{
            OAuthProviderAuthorizationCodeInfo, OAuthProviderAuthorizationCodePkceInfo,
            OAuthProviderAuthorizationCodeRemoteInfo, OAuthProviderDeviceInfo,
            OAuthProviderDeviceRemoteInfo,
        },
    },
};

use super::super::{ExtractUserInfo, OAuthProvider, OAuthProviderName};

pub struct GitHubOAuthProvider {
    authz_code_flow_info: Option<OAuthProviderAuthorizationCodeInfo>,
    device_code_flow_info: Option<OAuthProviderDeviceInfo>,
    default_headers: HeaderMap,
    default_scopes: Vec<String>,
    client: reqwest::Client,
}

impl fmt::Debug for GitHubOAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitHubOAuthProvider").finish()
    }
}

impl GitHubOAuthProvider {
    pub fn new(
        config: ResolvedOAuthConfig,
        public_url: String,
        additional_scopes: Option<Vec<String>>,
    ) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static("v-api"));

        let mut default_scopes = vec!["user:email".to_string()];
        default_scopes.extend(additional_scopes.unwrap_or_default());

        let authz_code_flow_info = config.web.map(|web| OAuthProviderAuthorizationCodeInfo {
            auth_url_endpoint: format!("{}/login/oauth/github/code/authorize", public_url),
            redirect_endpoint: format!("{}/login/oauth/github/code/callback", public_url),
            token_endpoint_content_type: "application/x-www-form-urlencoded".to_string(),
            token_endpoint: format!("{}/login/oauth/github/code/token", public_url),
            remote: OAuthProviderAuthorizationCodeRemoteInfo {
                client_id: web.remote_client_id,
                client_secret: web.remote_client_secret.into(),
                auth_url_endpoint: "https://github.com/login/oauth/authorize".to_string(),
                token_endpoint_content_type: "application/x-www-form-urlencoded".to_string(),
                token_endpoint: "https://github.com/login/oauth/access_token".to_string(),
                revocation_endpoint: None,
            },
        });
        let device_code_flow_info = config.device.map(|device| OAuthProviderDeviceInfo {
            client_id: device.client_id,
            remote: OAuthProviderDeviceRemoteInfo {
                client_id: device.remote_client_id,
                client_secret: device.remote_client_secret.into(),
                device_code_endpoint: "https://github.com/login/device/code".to_string(),
                token_endpoint: "https://github.com/login/oauth/access_token".to_string(),
                revocation_endpoint: None,
            },
        });

        Self {
            authz_code_flow_info,
            device_code_flow_info,
            default_headers: headers,
            default_scopes,
            client: reqwest::ClientBuilder::new()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("Static client must build"),
        }
    }

    pub fn with_client(&mut self, client: reqwest::Client) -> &mut Self {
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
            display_name: Some(user.login),
            idp_token: None,
        })
    }
}

impl OAuthProvider for GitHubOAuthProvider {
    fn name(&self) -> OAuthProviderName {
        OAuthProviderName::GitHub
    }
    fn initialize_headers(&self, request: &mut Request) {
        *request.headers_mut() = self.default_headers.clone();
    }
    fn client(&self) -> &reqwest::Client {
        &self.client
    }
    fn user_info_endpoints(&self) -> Vec<&str> {
        vec![
            "https://api.github.com/user",
            "https://api.github.com/user/emails",
        ]
    }

    fn expires_in(&self) -> Option<u64> {
        None
    }
    fn default_scopes(&self) -> &[String] {
        &self.default_scopes
    }
    fn supports_pkce(&self) -> bool {
        true
    }

    fn authz_code_flow_info(&self) -> Option<&OAuthProviderAuthorizationCodeInfo> {
        self.authz_code_flow_info.as_ref()
    }
    fn authz_code_pkce_flow_info(&self) -> Option<&OAuthProviderAuthorizationCodePkceInfo> {
        None
    }
    fn device_code_flow_info(&self) -> Option<&OAuthProviderDeviceInfo> {
        self.device_code_flow_info.as_ref()
    }
}
