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
        ExternalUserId, UserInfo, UserInfoError,
        oauth::{
            OAuthProviderAuthorizationCodeInfo, OAuthProviderAuthorizationCodePkceInfo,
            OAuthProviderAuthorizationCodeRemoteInfo, OAuthProviderDeviceInfo,
        },
    },
};

use super::super::{ExtractUserInfo, OAuthProvider, OAuthProviderName};

pub struct ZendeskOAuthProvider {
    authz_code_flow_info: Option<OAuthProviderAuthorizationCodeInfo>,
    authz_code_pkce_flow_info: Option<OAuthProviderAuthorizationCodePkceInfo>,
    user_info_endpoint: String,
    default_scopes: Vec<String>,
    client: reqwest::Client,
}

impl fmt::Debug for ZendeskOAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZendeskOAuthProvider").finish()
    }
}

impl ZendeskOAuthProvider {
    pub fn new(
        config: ResolvedOAuthConfig,
        public_url: String,
        subdomain: String,
        additional_scopes: Option<Vec<String>>,
    ) -> Self {
        let base_url = format!("https://{}.zendesk.com", subdomain);

        let mut default_scopes = vec!["read".to_string(), "write".to_string()];
        default_scopes.extend(additional_scopes.unwrap_or_default());

        let authz_code_flow_info = config.web.map(|web| OAuthProviderAuthorizationCodeInfo {
            auth_url_endpoint: format!("{}/login/oauth/zendesk/code/authorize", public_url),
            redirect_endpoint: format!("{}/login/oauth/zendesk/code/callback", public_url),
            token_endpoint_content_type: "application/x-www-form-urlencoded".to_string(),
            token_endpoint: format!("{}/login/oauth/zendesk/code/token", public_url),
            remote: OAuthProviderAuthorizationCodeRemoteInfo {
                client_id: web.remote_client_id,
                client_secret: web.remote_client_secret.into(),
                auth_url_endpoint: format!("{}/oauth/authorizations/new", base_url),
                token_endpoint_content_type: "application/x-www-form-urlencoded".to_string(),
                token_endpoint: format!("{}/oauth/tokens", base_url),
                revocation_endpoint: None,
            },
        });
        let authz_code_pkce_flow_info =
            authz_code_flow_info
                .as_ref()
                .zip(config.proxy_web)
                .map(|(web, proxy)| OAuthProviderAuthorizationCodePkceInfo {
                    client_id: proxy.client_id,
                    redirect_endpoint: proxy.redirect_uri,
                    proxy_port: proxy.proxy_port,
                    web: web.clone(),
                });

        Self {
            authz_code_flow_info,
            authz_code_pkce_flow_info,
            user_info_endpoint: format!("{}/api/v2/users/me.json", base_url),
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
struct ZendeskUserResponse {
    user: ZendeskUser,
}

#[derive(Debug, Deserialize)]
struct ZendeskUser {
    id: u64,
    name: String,
    email: String,
    verified: bool,
    suspended: bool,
}

impl ExtractUserInfo for ZendeskOAuthProvider {
    fn extract_user_info(&self, data: &[Bytes]) -> Result<UserInfo, UserInfoError> {
        let response: ZendeskUserResponse = serde_json::from_slice(&data[0])?;
        let user = response.user;

        if user.suspended {
            return Err(UserInfoError::Locked);
        }

        let verified_emails = if user.verified {
            vec![user.email]
        } else {
            vec![]
        };

        Ok(UserInfo {
            external_id: ExternalUserId::Zendesk(user.id.to_string()),
            verified_emails,
            display_name: Some(user.name),
            idp_token: None,
        })
    }
}

impl OAuthProvider for ZendeskOAuthProvider {
    fn name(&self) -> OAuthProviderName {
        OAuthProviderName::Zendesk
    }
    fn initialize_headers(&self, _request: &mut Request) {}
    fn client(&self) -> &reqwest::Client {
        &self.client
    }
    fn user_info_endpoints(&self) -> Vec<&str> {
        vec![&self.user_info_endpoint]
    }

    fn expires_in(&self) -> Option<u64> {
        // This is the maximum token duration that Zendesk supports. In the future we should make
        // this configurable
        Some(172800)
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
        self.authz_code_pkce_flow_info.as_ref()
    }
    fn device_code_flow_info(&self) -> Option<&OAuthProviderDeviceInfo> {
        None
    }
}
