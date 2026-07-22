// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Interactive saga browser command.
//!
//! Like the auth commands, the concrete saga types come from the consumer of
//! the CLI. Consumers implement the [`adapter`] traits on their own generated
//! types (which share the shape of the server's `SagaView`, `SagaDetailView`,
//! and `EnrichedSagaEventView`) and expose an adapter from their context via
//! [`VCliContext::saga_adapter`](crate::VCliContext::saga_adapter).

use anyhow::Result;
use clap::Parser;

use crate::VCliContext;

pub mod adapter;
pub mod app;
pub mod dag;

pub use adapter::{
    BoxFuture, CliSagaAdapter, CliSagaDetail, CliSagaEvent, CliSagaSummary, SagaPage,
};
pub use dag::{DagNode, NodeKind, unpack_dag};

/// Browse sagas in an interactive terminal UI.
///
/// Lists sagas with pagination and lets you drill into a selected saga to see
/// its DAG nodes alongside the events recorded for each node.
#[derive(Parser, Debug)]
#[clap(name = "saga")]
pub struct Saga {
    /// Open directly to the detail view for this saga id.
    saga: Option<String>,

    /// Number of sagas to fetch per page.
    #[arg(long, default_value_t = 20)]
    page_size: u32,
}

impl Saga {
    /// Launch the interactive saga browser, sourcing the adapter from the
    /// context. This mirrors how the `auth` and `config` commands are run.
    pub async fn run<T, C, P>(&self, ctx: &T) -> Result<()>
    where
        T: VCliContext<C, P>,
    {
        app::run(ctx.saga_adapter(), self.page_size, self.saga.clone()).await
    }
}
