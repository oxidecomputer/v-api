// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use oauth2::PkceCodeVerifier;
use std::{error::Error as StdError, future::Future, pin::Pin};
use uuid::Uuid;

pub mod code;
pub mod device;

use crate::cmd::auth::login::CliAdapterToken;

pub trait CliOAuthAdapter {
    type ShortToken: CliAdapterToken + Send + 'static;
    type LongToken: CliAdapterToken + Send + 'static;
    type Error: StdError + Send + Sync + 'static;

    fn provider(
        &self,
        provider: super::login::LoginProvider,
    ) -> Pin<Box<dyn Future<Output = Result<impl CliOAuthProviderInfo, Self::Error>> + Send>>;
    fn exchange_authorization_code(
        &self,
        provider: super::login::LoginProvider,
        client_id: Uuid,
        redirect_uri: String,
        grant_type: String,
        code: String,
        pkce_verifier: PkceCodeVerifier,
        request_idp_token: bool,
    ) -> Pin<Box<dyn Future<Output = Result<Self::ShortToken, Self::Error>> + Send>>;
    fn get_long_lived_token(
        &self,
        access_token: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Self::LongToken, Self::Error>> + Send>>;
}

pub trait CliOAuthProviderInfo {
    fn client_id(&self) -> Uuid;
    fn remote_client_id(&self) -> &str;
    fn public_pkce_port(&self) -> Option<u16>;
    fn supports_pkce_only(&self) -> bool;
    fn device_code_endpoint(&self) -> Option<&str>;
    fn auth_url_endpoint(&self) -> Option<&str>;
    fn token_endpoint(&self) -> &str;
    fn redirect_endpoint(&self) -> Option<&str>;
    fn scopes(&self) -> &[String];
}
