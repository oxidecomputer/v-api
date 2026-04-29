// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use oauth2::TokenResponse;
use std::{error::Error as StdError, future::Future, io::Write, pin::Pin};

use crate::{CliContext, cmd::{auth::oauth::{self, CliOAuthProviderInfo}, config::CliConfig}};

// Authenticates and generates an access token for interacting with the api
#[derive(Parser, Debug, Clone)]
#[clap(name = "login")]
pub struct Login {
    #[command(subcommand)]
    method: LoginMethod,
    #[arg(short = 'm', default_value = "id")]
    mode: AuthenticationMode,
}

impl Login {
    pub async fn run<T, C, P>(&self, ctx: &mut T) -> Result<()>
    where
        T: CliContext<C, P>,
    {
        let access_token = self.method.run(ctx, &self.mode).await?;

        ctx.config_mut().set_token(access_token);
        ctx.config_mut().save()?;

        Ok(())
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum LoginMethod {
    #[command(name = "oauth")]
    /// Login via OAuth
    OAuth {
        #[command(subcommand)]
        provider: LoginProvider,
    },
    /// Login via Magic Link
    #[command(name = "mlink")]
    MagicLink {
        /// Email recipient to login via
        email: String,
        /// Optional access scopes to apply to this session
        scope: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum LoginProvider {
    #[command(name = "google")]
    /// Login via Google
    Google,
}

#[derive(ValueEnum, Debug, Clone, PartialEq)]
pub enum AuthenticationMode {
    /// Retrieve and store an identity token. Identity mode is the default and should be used to
    /// when you do not require extended (multi-day) access
    #[value(name = "id")]
    Identity,
    /// Retrieve and store an api token. Token mode should be used when you want to authenticate
    /// a machine for continued access. This requires the permission to create api tokens
    #[value(name = "token")]
    Token,
}

impl LoginMethod {
    pub async fn run<T, C, P>(&self, ctx: &T, mode: &AuthenticationMode) -> Result<String>
    where
        T: CliContext<C, P>,
    {
        match self {
            Self::OAuth { provider } => {
                self.run_oauth_provider(provider, mode, ctx.oauth_adapter())
                    .await
            }
            Self::MagicLink { email, scope } => {
                self.run_magic_link(email, scope.as_deref(), ctx.mlink_adapter())
                    .await
            }
        }
    }

    async fn run_oauth_provider<T>(
        &self,
        provider: &LoginProvider,
        mode: &AuthenticationMode,
        adapter: T
    ) -> Result<String> where T: CliOAuthAdapter {
        let provider = adapter.provider(provider).await?;
        let oauth_client = oauth::DeviceOAuth::new(provider)?;
        let details = oauth_client.get_device_authorization().await?;

        println!(
            "To complete login visit: {} and enter {}",
            details.verification_uri().as_str(),
            details.user_code().secret()
        );

        let token_response = oauth_client.login(&details).await;

        let identity_token = match token_response {
            Ok(token) => Ok(token.access_token().to_owned()),
            Err(err) => Err(anyhow::anyhow!("Authentication failed: {}", err)),
        }?;

        if mode == &AuthenticationMode::Token {
            let token = adapter.get_long_lived_token(identity_token.secret()).await?;
            Ok(token.access_token().to_string())
        } else {
            Ok(identity_token.secret().to_string())
        }
    }

    async fn run_magic_link<T>(
        &self,
        email: &str,
        scope: Option<&str>,
        adapter: T,
    ) -> Result<String>
    where
        T: CliMagicLinkAdapter,
    {
        let attempt = adapter.create_attempt(email, scope).await?;

        let mut auth_secret = String::new();
        print!("Enter the login token sent to the recipient: ");
        std::io::stdout().flush()?;
        std::io::stdin().read_line(&mut auth_secret)?;

        let token = adapter.exchange(attempt, email, &auth_secret).await?;

        Ok(token.access_token().to_string())
    }
}

pub trait CliOAuthAdapter {
    type Token: CliAdapterToken;
    type Error: StdError + Send + Sync + 'static;

    fn provider(&self, provider: &LoginProvider) -> Pin<Box<dyn Future<Output = Result<impl CliOAuthProviderInfo, Self::Error>> + Send>>;
    fn get_long_lived_token(&self, access_token: &str) -> Pin<Box<dyn Future<Output = Result<Self::Token, Self::Error>> + Send>>;
}

pub trait CliMagicLinkAdapter {
    type Attempt;
    type Token: CliAdapterToken;
    type Error: StdError + Send + Sync + 'static;

    fn create_attempt(&self, email: &str, scope: Option<&str>) -> Pin<Box<dyn Future<Output = Result<Self::Attempt, Self::Error>> + Send>>;
    fn exchange(&self, attempt: Self::Attempt, email: &str, token: &str) -> Pin<Box<dyn Future<Output = Result<Self::Token, Self::Error>> + Send>>;
}

pub trait CliAdapterToken {
    fn access_token(&self) -> &str;
}
