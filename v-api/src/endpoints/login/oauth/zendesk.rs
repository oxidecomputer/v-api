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
        oauth::{
            OAuthProviderAuthorizationCodeInfo, OAuthProviderAuthorizationCodePkceInfo,
            OAuthProviderDeviceInfo,
        },
        ExternalUserId, UserInfo, UserInfoError,
    },
};

use super::{ExtractUserInfo, OAuthProvider, OAuthProviderName};

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
        // let base_url = format!("https://{}.zendesk.com", subdomain);

        // Self {
        //     device_public: OAuthPublicCredentials {
        //         client_id: device_client_id,
        //     },
        //     device_private: Some(OAuthPrivateCredentials {
        //         client_secret: device_client_secret,
        //     }),
        //     web_public: OAuthPublicCredentials {
        //         client_id: web_client_id,
        //     },
        //     web_private: Some(OAuthPrivateCredentials {
        //         client_secret: web_client_secret,
        //     }),
        //     web_pkce: web_pkce_client_id.map(|client_id| OAuthPublicCredentials {
        //         client_id,
        //     }),
        //     web_pkce_port: web_pkce_port,
        //     additional_scopes: additional_scopes.unwrap_or_default(),
        //     client: reqwest::ClientBuilder::new()
        //         .redirect(reqwest::redirect::Policy::none())
        //         .build()
        //         .expect("Static client must build"),
        //     user_info_endpoint: format!("{}/api/v2/users/me.json", base_url),
        //     auth_url_endpoint: format!("{}/oauth/authorizations/new", base_url),
        //     token_exchange_endpoint: format!("{}/oauth/tokens", base_url),
        //     token_endpoint: Some(format!(
        //         "{}/login/oauth/zendesk/device/exchange",
        //         public_url
        //     )),
        //     redirect_endpoint: Some(format!("{}/login/oauth/zendesk/code/callback", public_url,)),
        // }

        let base_url = format!("https://{}.zendesk.com", subdomain);

        let mut default_scopes = vec!["users:read".to_string()];
        default_scopes.extend(additional_scopes.unwrap_or_default());

        let authz_code_flow_info = config.web.map(|web| OAuthProviderAuthorizationCodeInfo {
            client_id: web.client_id,
            client_secret: web.client_secret.into(),
            auth_url_endpoint: format!("{}/oauth/authorizations/new", base_url),
            redirect_endpoint: format!("{}/login/oauth/zendesk/code/callback", public_url),
            token_endpoint_content_type: "application/x-www-form-urlencoded".to_string(),
            token_endpoint: format!("{}/oauth/tokens", base_url),
            revocation_endpoint: None,
        });
        let authz_code_pkce_flow_info =
            config
                .proxy_web
                .map(|proxy| OAuthProviderAuthorizationCodePkceInfo {
                    client_id: proxy.client_id,
                    auth_url_endpoint: format!("{}/oauth/authorizations/new", base_url),
                    redirect_endpoint: format!("{}/login/oauth/zendesk/code/callback", public_url),
                    token_endpoint_content_type: "application/x-www-form-urlencoded".to_string(),
                    token_endpoint: format!("{}/oauth/tokens", base_url),
                    proxy_port: proxy.proxy_port,
                    revocation_endpoint: None,
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
        None
    }
}
