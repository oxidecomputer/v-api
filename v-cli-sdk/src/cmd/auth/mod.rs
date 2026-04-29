// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::error::Error as StdError;

use crate::{cmd::auth::login::CliConsumerLoginProvider, CliContext};

pub mod login;
pub mod oauth;
pub mod proxy;

// Authenticate against the Meetings API
#[derive(Parser, Debug)]
#[clap(name = "auth")]
pub struct Auth<P>
where
    P: CliConsumerLoginProvider,
{
    #[command(subcommand)]
    auth: AuthCommands<P>,
}

#[derive(Subcommand, Debug, Clone)]
enum AuthCommands<P>
where
    P: CliConsumerLoginProvider,
{
    /// Login via an authentication provider
    Login(login::Login<P>),
}

impl<P> Auth<P>
where
    P: CliConsumerLoginProvider,
{
    pub async fn run<T, C>(&self, ctx: &mut T) -> Result<()>
    where
        T: CliContext<C, P>,
        <T as CliContext<C, P>>::Error: StdError + Send + Sync + 'static,
    {
        match &self.auth {
            AuthCommands::Login(login) => login.run(ctx).await,
        }
    }
}
