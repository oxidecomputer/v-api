// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use oauth2::TokenResponse;
use std::{error::Error as StdError, fmt::Debug, future::Future, io::Write, pin::Pin, sync::Arc};

use crate::{
    cmd::{
        auth::oauth::{self, CliOAuthAdapter, CliOAuthProviderInfo},
        config::CliConfig,
    },
    CliContext,
};

pub trait CliAdapterToken {
    fn access_token(&self) -> &str;
}

pub trait CliConsumerLoginProvider: Into<LoginProvider> + Subcommand + Debug + Clone {}
impl<T> CliConsumerLoginProvider for T where T: Into<LoginProvider> + Subcommand + Debug + Clone {}

// Authenticates and generates an access token for interacting with the api
#[derive(Parser, Debug, Clone)]
#[clap(name = "login")]
pub struct Login<P>
where
    P: CliConsumerLoginProvider,
{
    #[command(subcommand)]
    method: LoginMethod<P>,
    #[arg(short = 'm', default_value = "id")]
    mode: AuthenticationMode,
}

impl<P> Login<P>
where
    P: CliConsumerLoginProvider,
{
    pub async fn run<T, C, R>(&self, ctx: &mut T) -> Result<()>
    where
        T: CliContext<C, R>,
        <T as CliContext<C, R>>::Error: StdError + Send + Sync + 'static,
    {
        let access_token = self.method.run(ctx, &self.mode).await?;

        ctx.config_mut().set_token(access_token);
        ctx.config_mut().save()?;

        Ok(())
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum LoginMethod<P>
where
    P: Subcommand + Debug + Clone,
{
    #[command(name = "oauth")]
    /// Login via OAuth
    OAuth {
        #[command(subcommand)]
        provider: P,
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

pub enum LoginProvider {
    Google,
    GitHub,
    Zendesk,
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
    /// Retrieve and store a remote token. Remote mode should be used when you want to authenticate
    /// and retrieve a token for use against the underlying authentication provider
    #[value(name = "remote")]
    Remote,
}

impl<P> LoginMethod<P>
where
    P: CliConsumerLoginProvider,
{
    pub async fn run<T, C, R>(&self, ctx: &T, mode: &AuthenticationMode) -> Result<String>
    where
        T: CliContext<C, R>,
        <T as CliContext<C, R>>::Error: StdError + Send + Sync + 'static,
    {
        match self {
            Self::OAuth { provider } => {
                let adapter = ctx.oauth_adapter();
                let provider = provider.clone().into();
                let provider = adapter.provider(&provider).await?;

                // We now need to inspect the provider to determine the correct flow to use. If
                // possible we use a limited input device flow, but not all providers support it.
                // To handle those cases we need to use a proxy path that emulates an authorization
                // code flow.
                if provider.device_code_endpoint().is_some() {
                    self.run_oauth_device_provider(provider, mode, ctx.oauth_adapter())
                        .await
                } else if provider.code_redirect_proxy_endpoint().is_some() {
                    self.run_oauth_code_provider(provider, mode, ctx.oauth_adapter())
                        .await
                } else {
                    anyhow::bail!("OAuth provider does not support any CLI authentication methods")
                }
            }
            Self::MagicLink { email, scope } => {
                self.run_magic_link(email, scope.as_deref(), ctx.mlink_adapter())
                    .await
            }
        }
    }

    async fn run_oauth_device_provider<T, V>(
        &self,
        provider: V,
        mode: &AuthenticationMode,
        adapter: T,
    ) -> Result<String>
    where
        T: CliOAuthAdapter,
        V: CliOAuthProviderInfo,
    {
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
            let token = adapter
                .get_long_lived_token(identity_token.secret())
                .await?;
            Ok(token.access_token().to_string())
        } else {
            Ok(identity_token.secret().to_string())
        }
    }

    async fn run_oauth_code_provider<T, V>(
        &self,
        provider: V,
        mode: &AuthenticationMode,
        adapter: T,
    ) -> Result<String>
    where
        T: CliOAuthAdapter + Send + Sync + 'static,
        V: CliOAuthProviderInfo,
    {
        let oauth_client = oauth::CodeOAuth::new(provider)?;
        let adapter = Arc::new(adapter);

        let identity_token = oauth_client.login(Arc::clone(&adapter)).await?;

        if mode == &AuthenticationMode::Token {
            let token = adapter.get_long_lived_token(&identity_token).await?;
            Ok(token.access_token().to_string())
        } else {
            Ok(identity_token)
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

pub trait CliMagicLinkAdapter {
    type Attempt;
    type Token: CliAdapterToken;
    type Error: StdError + Send + Sync + 'static;

    fn create_attempt(
        &self,
        email: &str,
        scope: Option<&str>,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Attempt, Self::Error>> + Send>>;
    fn exchange(
        &self,
        attempt: Self::Attempt,
        email: &str,
        token: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Token, Self::Error>> + Send>>;
}
