// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};

use std::{error::Error as StdError, fmt::Debug, future::Future, io::Write, pin::Pin, sync::Arc};

use crate::{
    VCliConfig, VCliContext,
    cmd::auth::oauth::{self, CliOAuthAdapter, CliOAuthProviderInfo},
};

pub trait CliAdapterToken {
    fn access_token(&self) -> &str;
    fn idp_token(&self) -> Option<&str>;
}

pub trait CliConsumerLoginProvider: Into<LoginProvider> + Subcommand + Debug + Clone {}
impl<T> CliConsumerLoginProvider for T where T: Into<LoginProvider> + Subcommand + Debug + Clone {}

// Authenticates and generates an access token for interacting with the api
#[derive(Parser, Debug, Clone)]
#[clap(name = "login")]
pub struct Login<SupportedProviders>
where
    SupportedProviders: CliConsumerLoginProvider,
{
    #[command(subcommand)]
    method: LoginMethod<SupportedProviders>,
    #[arg(short = 'm', default_value = "id")]
    mode: AuthenticationMode,
}

impl<P> Login<P>
where
    P: CliConsumerLoginProvider,
{
    pub async fn run<T, C, R>(&self, ctx: &mut T) -> Result<()>
    where
        T: VCliContext<C, R>,
        <T as VCliContext<C, R>>::Error: StdError + Send + Sync + 'static,
    {
        let (access_token, idp_token) = self.method.run(ctx, self.mode).await?;

        ctx.config_mut().set_token(access_token);
        ctx.config_mut().save()?;

        // If we are acquiring an IdP token, present it to the user.
        if let Some(idp_token) = idp_token {
            println!(
                "\nYou can now additionally authenticate against the requested remote service API \
                with the following token."
            );
            println!("IdP token: {}", idp_token);
            println!();
            println!(
                "Please note that this should be kept secure as calls made with this token are \
                made on behalf of your user acount"
            );
        }

        Ok(())
    }
}

#[derive(Subcommand, Debug, Clone)]
pub enum LoginMethod<SupportedProviders>
where
    SupportedProviders: Subcommand + Debug + Clone,
{
    #[command(name = "oauth")]
    /// Login via OAuth
    OAuth {
        #[command(subcommand)]
        provider: SupportedProviders,
        /// Additionally retrieve a the underlying IdP token. This token is not stored. An IdP token
        /// should be used when you need to authenticate to the underlying system frontend by the API
        #[arg(long, default_value = "false")]
        request_idp_token: bool,
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

#[derive(Copy, Clone)]
pub enum LoginProvider {
    Google,
    GitHub,
    Zendesk,
}

#[derive(Copy, ValueEnum, Debug, Clone, PartialEq)]
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

impl<SupportedProviders> LoginMethod<SupportedProviders>
where
    SupportedProviders: CliConsumerLoginProvider,
{
    pub async fn run<T, C, R>(
        &self,
        ctx: &T,
        mode: AuthenticationMode,
    ) -> Result<(String, Option<String>)>
    where
        T: VCliContext<C, R>,
        <T as VCliContext<C, R>>::Error: StdError + Send + Sync + 'static,
    {
        match self {
            Self::OAuth {
                provider,
                request_idp_token,
            } => {
                let adapter = ctx.oauth_adapter();
                let provider = provider.clone().into();
                let provider = adapter.provider(provider).await?;

                // We now need to inspect the provider to determine the correct flow to use. If
                // possible we use a limited input device flow, but not all providers support it.
                // To handle those cases we need to use a proxy path that emulates an authorization
                // code flow.
                if provider.device_authorization_endpoint().is_some() {
                    if *request_idp_token {
                        anyhow::bail!(
                            "Remote token access is not supported via device authentication flow"
                        );
                    }
                    Ok((
                        self.run_oauth_device_provider(provider, mode, ctx.oauth_adapter())
                            .await?,
                        None,
                    ))
                } else if provider.supports_pkce_only() {
                    self.run_oauth_code_provider(
                        provider,
                        mode,
                        *request_idp_token,
                        ctx.oauth_adapter(),
                    )
                    .await
                } else {
                    anyhow::bail!("OAuth provider does not support any CLI authentication methods")
                }
            }
            Self::MagicLink { email, scope } => Ok((
                self.run_magic_link(email, scope.as_deref(), ctx.mlink_adapter())
                    .await?,
                None,
            )),
        }
    }

    async fn run_oauth_device_provider<T, V>(
        &self,
        provider: V,
        mode: AuthenticationMode,
        adapter: T,
    ) -> Result<String>
    where
        T: CliOAuthAdapter,
        V: CliOAuthProviderInfo,
    {
        let token = oauth::device::login(&provider).await?;

        match mode {
            AuthenticationMode::Identity => Ok(token.access_token.clone()),
            AuthenticationMode::Token => {
                let token = adapter
                    .get_long_lived_token(&token.access_token)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;
                Ok(token.access_token().to_string())
            }
        }
    }

    async fn run_oauth_code_provider<T, V>(
        &self,
        provider: T,
        mode: AuthenticationMode,
        request_idp_token: bool,
        adapter: V,
    ) -> Result<(String, Option<String>)>
    where
        T: CliOAuthProviderInfo,
        V: CliOAuthAdapter + Send + Sync + 'static,
    {
        let oauth_client = oauth::code::CodeOAuth::new(provider)?;
        let adapter = Arc::new(adapter);

        let identity_token = oauth_client
            .login(Arc::clone(&adapter), request_idp_token)
            .await?;

        let access_token = match mode {
            AuthenticationMode::Identity => identity_token.access_token().to_string(),
            AuthenticationMode::Token => {
                let token = adapter
                    .get_long_lived_token(identity_token.access_token())
                    .await?;
                token.access_token().to_string()
            }
        };

        let idp_token = if request_idp_token {
            identity_token.idp_token().map(|s| s.to_string())
        } else {
            None
        };

        Ok((access_token, idp_token))
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

    #[allow(clippy::type_complexity)]
    fn create_attempt(
        &self,
        email: &str,
        scope: Option<&str>,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Attempt, Self::Error>> + Send>>;
    #[allow(clippy::type_complexity)]
    fn exchange(
        &self,
        attempt: Self::Attempt,
        email: &str,
        token: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Self::Token, Self::Error>> + Send>>;
}
