// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use hyper::body::Bytes;
use reqwest::Request;
use secrecy::SecretString;
use serde::Deserialize;
use std::fmt;

use crate::endpoints::login::{ExternalUserId, UserInfo, UserInfoError};

use super::{
    ClientType, ExtractUserInfo, OAuthPrivateCredentials, OAuthProvider, OAuthProviderName,
    OAuthPublicCredentials,
};

pub struct ZendeskOAuthProvider {
    device_public: OAuthPublicCredentials,
    device_private: Option<OAuthPrivateCredentials>,
    web_public: OAuthPublicCredentials,
    web_private: Option<OAuthPrivateCredentials>,
    additional_scopes: Vec<String>,
    client: reqwest::Client,
    user_info_endpoint: String,
    auth_url_endpoint: String,
    token_exchange_endpoint: String,
    token_endpoint: Option<String>,
    redirect_endpoint: Option<String>,
    redirect_proxy_endpoint: Option<String>,
}

impl fmt::Debug for ZendeskOAuthProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZendeskOAuthProvider").finish()
    }
}

impl ZendeskOAuthProvider {
    pub fn new(
        public_url: String,
        subdomain: String,
        device_client_id: String,
        device_client_secret: SecretString,
        web_client_id: String,
        web_client_secret: SecretString,
        additional_scopes: Option<Vec<String>>,
        redirect_proxy_port: u16,
    ) -> Self {
        let base_url = format!("https://{}.zendesk.com", subdomain);

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
            client: reqwest::ClientBuilder::new()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("Static client must build"),
            user_info_endpoint: format!("{}/api/v2/users/me.json", base_url),
            auth_url_endpoint: format!("{}/oauth/authorizations/new", base_url),
            token_exchange_endpoint: format!("{}/oauth/tokens", base_url),
            token_endpoint: Some(format!(
                "{}/login/oauth/zendesk/device/exchange",
                public_url
            )),
            redirect_endpoint: Some(format!("{}/login/oauth/zendesk/code/callback", public_url,)),
            redirect_proxy_endpoint: Some(format!(
                "http://localhost:{}/login/oauth/zendesk/code/callback",
                redirect_proxy_port
            )),
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

    fn scopes(&self) -> Vec<&str> {
        let mut default = vec!["users:read"];
        default.extend(self.additional_scopes.iter().map(|s| s.as_str()));
        default
    }

    fn initialize_headers(&self, _request: &mut Request) {}

    fn client(&self) -> &reqwest::Client {
        &self.client
    }

    fn client_id(&self, client_type: &ClientType) -> &str {
        match client_type {
            ClientType::Device => &self.device_public.client_id,
            ClientType::Web => &self.web_public.client_id,
        }
    }

    fn client_secret(&self, client_type: &ClientType) -> Option<&SecretString> {
        match client_type {
            ClientType::Device => self
                .device_private
                .as_ref()
                .map(|private| &private.client_secret),
            ClientType::Web => self
                .web_private
                .as_ref()
                .map(|private| &private.client_secret),
        }
    }

    fn user_info_endpoints(&self) -> Vec<&str> {
        vec![&self.user_info_endpoint]
    }

    fn device_code_endpoint(&self) -> Option<&str> {
        None
    }

    fn auth_url_endpoint(&self) -> &str {
        &self.auth_url_endpoint
    }

    fn token_exchange_content_type(&self) -> &str {
        "application/x-www-form-urlencoded"
    }

    fn token_exchange_endpoint(&self) -> &str {
        &self.token_exchange_endpoint
    }

    fn token_revocation_endpoint(&self) -> Option<&str> {
        None
    }

    fn supports_pkce(&self) -> bool {
        false
    }

    fn token_endpoint(&self) -> Option<&str> {
        self.token_endpoint.as_deref()
    }
    fn redirect_endpoint(&self) -> Option<&str> {
        self.redirect_endpoint.as_deref()
    }
    fn redirect_proxy_endpoint(&self) -> Option<&str> {
        self.redirect_proxy_endpoint.as_deref()
    }
}
