// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use oauth2::PkceCodeVerifier;
use std::{error::Error as StdError, future::Future, pin::Pin};
use uuid::Uuid;

pub mod code;
pub mod device;

use crate::cmd::auth::login::{CliAdapterToken, LoginProvider};

/// Parameters for exchanging an authorization code for an access token.
pub struct AuthorizationCodeExchange {
    pub provider: super::login::LoginProvider,
    pub client_id: Uuid,
    pub redirect_uri: String,
    pub grant_type: String,
    pub code: String,
    pub pkce_verifier: PkceCodeVerifier,
    pub request_idp_token: bool,
}

/// Parameters for initiating a device authorization flow.
pub struct DeviceAuthorizationRequest {
    pub provider: LoginProvider,
    pub client_id: Uuid,
    pub scope: Option<String>,
}

/// Response from initiating a device authorization flow.
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: Option<u64>,
    pub interval: Option<u64>,
}

/// Parameters for exchanging a device code for an access token.
pub struct DeviceTokenExchange {
    pub provider: LoginProvider,
    pub client_id: Uuid,
    pub device_code: String,
    pub grant_type: String,
}

/// Result of a device token exchange poll.
pub enum DeviceAccessTokenResponse<T> {
    /// The user has not yet completed authorization. The client should continue polling.
    Pending,
    /// The user completed authorization and a token was issued.
    Token(T),
}

pub trait CliOAuthAdapter {
    type ShortToken: CliAdapterToken + Send + 'static;
    type LongToken: CliAdapterToken + Send + 'static;
    type Error: StdError + Send + Sync + 'static;

    #[allow(clippy::type_complexity)]
    fn provider(
        &self,
        provider: super::login::LoginProvider,
    ) -> Pin<Box<dyn Future<Output = Result<impl CliOAuthProviderInfo, Self::Error>> + Send>>;
    #[allow(clippy::type_complexity)]
    fn exchange_authorization_code(
        &self,
        exchange: AuthorizationCodeExchange,
    ) -> Pin<Box<dyn Future<Output = Result<Self::ShortToken, Self::Error>> + Send>>;
    #[allow(clippy::type_complexity)]
    fn initiate_device_authorization(
        &self,
        request: DeviceAuthorizationRequest,
    ) -> Pin<Box<dyn Future<Output = Result<DeviceAuthorizationResponse, Self::Error>> + Send>>;
    #[allow(clippy::type_complexity)]
    fn exchange_device_token(
        &self,
        exchange: DeviceTokenExchange,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<DeviceAccessTokenResponse<Self::ShortToken>, Self::Error>>
                + Send,
        >,
    >;
    #[allow(clippy::type_complexity)]
    fn get_long_lived_token(
        &self,
        access_token: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Self::LongToken, Self::Error>> + Send>>;
}

pub trait CliOAuthProviderInfo {
    fn provider(&self) -> LoginProvider;
    fn client_id(&self) -> Uuid;
    fn supports_device_flow(&self) -> bool;
    fn public_pkce_port(&self) -> Option<u16>;
    fn supports_pkce_only(&self) -> bool;
    fn auth_url_endpoint(&self) -> Option<&str>;
    fn token_endpoint(&self) -> &str;
    fn redirect_endpoint(&self) -> Option<&str>;
    fn scopes(&self) -> &[String];
}
