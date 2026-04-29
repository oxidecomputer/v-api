// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::CliContext;

// mod link;
pub mod login;
pub mod oauth;

// Authenticate against the Meetings API
#[derive(Parser, Debug)]
#[clap(name = "auth")]
pub struct Auth {
    #[command(subcommand)]
    auth: AuthCommands,
}

#[derive(Subcommand, Debug, Clone)]
enum AuthCommands {
    /// Login via an authentication provider
    Login(login::Login),
}

impl Auth {
    pub async fn run<T, C, P>(&self, ctx: &mut T) -> Result<()> where T: CliContext<C, P> {
        match &self.auth {
            AuthCommands::Login(login) => login.run(ctx).await,
        }
    }
}
