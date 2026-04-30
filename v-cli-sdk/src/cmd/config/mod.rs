// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{CliContext, FormatStyle};

pub trait CliConfig {
    fn host(&self) -> Option<&str>;
    fn set_host(&mut self, host: String);
    fn token(&self) -> Option<&str>;
    fn set_token(&mut self, token: String);
    fn default_format(&self) -> Option<&FormatStyle>;
    fn set_default_format(&mut self, format: FormatStyle);
    fn mlink_redirect(&self) -> Option<&str>;
    fn set_mlink_redirect(&mut self, redirect: String);
    fn mlink_secret(&self) -> Option<&str>;
    fn set_mlink_secret(&mut self, secret: String);
    fn save(&self) -> Result<(), std::io::Error>;
}

#[derive(Debug, Parser)]
#[clap(name = "config")]
pub struct ConfigCmd {
    #[clap(subcommand)]
    setting: SettingCmd,
}

#[derive(Debug, Subcommand)]
pub enum SettingCmd {
    /// Gets a setting
    #[clap(subcommand, name = "get")]
    Get(GetCmd),
    /// Sets a setting
    #[clap(subcommand, name = "set")]
    Set(SetCmd),
}

#[derive(Debug, Subcommand)]
pub enum GetCmd {
    /// Get the default formatter to use when printing results
    #[clap(name = "format")]
    Format,
    /// Get the configured API host in use
    #[clap(name = "host")]
    Host,
    /// Get the configured access token
    #[clap(name = "token")]
    Token,
    /// Get the configured magic redirect uri
    #[clap(name = "mlink-redirect")]
    MagicLinkRedirectUri,
    /// Get the configured magic link secret
    #[clap(name = "mlink-secret")]
    MagicLinkSecret,
}

#[derive(Debug, Subcommand)]
pub enum SetCmd {
    /// Set the default formatter to use when printing results
    #[clap(name = "format")]
    Format { format: FormatStyle },
    /// Set the configured API host to use
    #[clap(name = "host")]
    Host { host: String },
    /// Set the configured magic redirect uri
    #[clap(name = "mlink-redirect")]
    MagicLinkRedirectUri { redirect: String },
    /// Set the configured magic link secret
    #[clap(name = "mlink-secret")]
    MagicLinkSecret { secret: String },
}

impl ConfigCmd {
    pub async fn run<T, C, P>(&self, ctx: &mut T) -> Result<()>
    where
        T: CliContext<C, P>,
    {
        match &self.setting {
            SettingCmd::Get(get) => get.run(ctx.config()).await?,
            SettingCmd::Set(set) => set.run(ctx.config_mut()).await?,
        }

        Ok(())
    }
}

impl GetCmd {
    pub async fn run<T>(&self, config: &T) -> Result<()>
    where
        T: CliConfig,
    {
        match &self {
            GetCmd::Format => {
                println!(
                    "{}",
                    config
                        .default_format()
                        .copied()
                        .unwrap_or(FormatStyle::Json)
                );
            }
            GetCmd::Host => {
                println!("{}", config.host().unwrap_or("None"));
            }
            GetCmd::Token => {
                println!("{}", config.token().unwrap_or("None"));
            }
            GetCmd::MagicLinkRedirectUri => {
                println!("{}", config.mlink_redirect().unwrap_or("None"));
            }
            GetCmd::MagicLinkSecret => {
                println!("{}", config.mlink_secret().unwrap_or("None"));
            }
        }

        Ok(())
    }
}

impl SetCmd {
    pub async fn run<T>(&self, config: &mut T) -> Result<()>
    where
        T: CliConfig,
    {
        match &self {
            SetCmd::Format { format } => {
                config.set_default_format(*format);
                config.save()?;
            }
            SetCmd::Host { host } => {
                config.set_host(host.to_string());
                config.save()?;
            }
            SetCmd::MagicLinkRedirectUri { redirect } => {
                config.set_mlink_redirect(redirect.to_string());
                config.save()?;
            }
            SetCmd::MagicLinkSecret { secret } => {
                config.set_mlink_secret(secret.to_string());
                config.save()?;
            }
        }

        Ok(())
    }
}
