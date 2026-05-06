// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use hyper::body::Bytes;
use reqwest::Request;
use serde::Deserialize;
use std::fmt;

use crate::{
    config::ResolvedOAuthConfig,
    endpoints::login::{
        ExternalUserId, UserInfo, UserInfoError, oauth::{
            OAuthProviderAuthorizationCodeInfo, OAuthProviderAuthorizationCodePkceInfo, OAuthProviderAuthorizationCodeRemoteInfo, OAuthProviderDeviceInfo
        }
    },
};

use super::super::{ExtractUserInfo, OAuthProvider, OAuthProviderName};

pub struct GoogleOAuthProvider {
    authz_code_flow_info: Option<OAuthProviderAuthorizationCodeInfo>,
    authz_code_pkce_flow_info: Option<OAuthProviderAuthorizationCodePkceInfo>,
    device_code_flow_info: Option<OAuthProviderDeviceInfo>,
    default_scopes: Vec<String>,
    client: reqwest::Client,
}

impl fmt::Debug for GoogleOAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GoogleOAuthProvider").finish()
    }
}

impl GoogleOAuthProvider {
    pub fn new(
        config: ResolvedOAuthConfig,
        public_url: String,
        additional_scopes: Option<Vec<String>>,
    ) -> Self {
        let mut default_scopes = vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ];
        default_scopes.extend(additional_scopes.unwrap_or_default());

        let authz_code_flow_info = config.web.map(|web| OAuthProviderAuthorizationCodeInfo {
            auth_url_endpoint: format!("{}/login/oauth/google/code/authorize", public_url),
            redirect_endpoint: format!("{}/login/oauth/google/code/callback", public_url),
            token_endpoint_content_type: "application/x-www-form-urlencoded".to_string(),
            token_endpoint: format!("{}/login/oauth/google/device/exchange", public_url),
            remote: OAuthProviderAuthorizationCodeRemoteInfo {
                client_id: web.remote_client_id,
                client_secret: web.remote_client_secret.into(),
                auth_url_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
                token_endpoint_content_type: "application/x-www-form-urlencoded".to_string(),
                token_endpoint: "https://oauth2.googleapis.com/token".to_string(),
                revocation_endpoint: Some("https://oauth2.googleapis.com/revoke".to_string()),
            },
        });
        let authz_code_pkce_flow_info =
            config
                .proxy_web
                .and_then(|proxy| authz_code_flow_info.as_ref().map(|web| (web, proxy)))
                .map(|(web, proxy)| OAuthProviderAuthorizationCodePkceInfo {
                    client_id: proxy.client_id,
                    redirect_endpoint: proxy.redirect_uri,
                    proxy_port: proxy.proxy_port,
                    web: web.clone()
                });
        let device_code_flow_info = config.device.map(|device| OAuthProviderDeviceInfo {
            client_id: device.client_id,
            remote_client_id: device.remote_client_id,
            remote_client_secret: device.remote_client_secret.into(),
            device_code_endpoint: "https://oauth2.googleapis.com/device/code".to_string(),
            token_endpoint_content_type: "application/x-www-form-urlencoded".to_string(),
            token_endpoint: "https://oauth2.googleapis.com/token".to_string(),
            revocation_endpoint: Some("https://oauth2.googleapis.com/revoke".to_string()),
        });

        Self {
            authz_code_flow_info,
            authz_code_pkce_flow_info,
            device_code_flow_info,
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
struct GoogleUserInfo {
    sub: String,
    email: String,
    email_verified: bool,
}

#[derive(Debug, Deserialize)]
struct GoogleProfile {
    #[serde(default)]
    names: Vec<GoogleProfileName>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoogleProfileName {
    display_name: String,
    metadata: GoogleProfileNameMeta,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GoogleProfileNameMeta {
    #[serde(default)]
    primary: bool,
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

        let profile_info: GoogleProfile = serde_json::from_slice(&data[1])?;
        let display_name = profile_info
            .names
            .into_iter()
            .filter_map(|name| name.metadata.primary.then_some(name.display_name))
            .nth(0);

        Ok(UserInfo {
            external_id: ExternalUserId::Google(remote_info.sub),
            verified_emails,
            display_name,
            idp_token: None,
        })
    }
}

impl OAuthProvider for GoogleOAuthProvider {
    fn name(&self) -> OAuthProviderName {
        OAuthProviderName::Google
    }
    fn initialize_headers(&self, _request: &mut Request) {}
    fn client(&self) -> &reqwest::Client {
        &self.client
    }
    fn user_info_endpoints(&self) -> Vec<&str> {
        vec![
            "https://openidconnect.googleapis.com/v1/userinfo",
            "https://people.googleapis.com/v1/people/me?personFields=names",
        ]
    }
    fn default_scopes(&self) -> &[String] {
        &self.default_scopes
    }

    fn authz_code_flow_info(&self) -> Option<&OAuthProviderAuthorizationCodeInfo> {
        self.authz_code_flow_info.as_ref()
    }
    fn authz_code_pkce_flow_info(&self) -> Option<&OAuthProviderAuthorizationCodePkceInfo> {
        self.authz_code_pkce_flow_info.as_ref()
    }
    fn device_code_flow_info(&self) -> Option<&OAuthProviderDeviceInfo> {
        self.device_code_flow_info.as_ref()
    }
}
