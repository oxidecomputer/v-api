// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Glue traits that the consumer of the CLI implements on their own concrete
//! types so that the saga browser can render them.
//!
//! The v-api server exposes sagas through the `SagaView`, `SagaDetailView`, and
//! `EnrichedSagaEventView` types. Consumers of this SDK generate their own
//! copies of these types (for example via `progenitor`), but the shapes are
//! identical. Rather than depend on any single concrete representation, the
//! saga browser is written against the accessor traits defined here, mirroring
//! the adapter pattern already used by the auth commands.

use std::{error::Error as StdError, future::Future, pin::Pin};

/// A boxed, `Send` future, matching the style used by the auth adapters.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A single page of saga summaries returned by [`CliSagaAdapter::list_sagas`].
///
/// This mirrors Dropshot's `ResultsPage`: `items` holds the sagas for the
/// current page and `next_page` holds the opaque continuation token to request
/// the following page (or `None` when the end has been reached).
pub struct SagaPage<S> {
    /// The sagas contained in this page.
    pub items: Vec<S>,
    /// The continuation token for the next page, if any.
    pub next_page: Option<String>,
}

/// Summary view of a saga, mirroring the server `SagaView`.
pub trait CliSagaSummary {
    /// Unique identifier of the saga, rendered as a string.
    fn id(&self) -> String;
    /// Human-readable name of the saga type.
    fn name(&self) -> String;
    /// Current cached state of the saga (e.g. `running`, `done`).
    fn state(&self) -> String;
    /// When the saga was created, rendered for display.
    fn created_at(&self) -> String;
    /// When the saga was last updated, rendered for display.
    fn updated_at(&self) -> String;
}

/// A single saga event, mirroring the server `EnrichedSagaEventView`.
pub trait CliSagaEvent {
    /// Auto-generated event identifier.
    fn id(&self) -> i64;
    /// Index of the DAG node this event belongs to. This matches the node
    /// index produced when unpacking the saga DAG.
    fn node_id(&self) -> i64;
    /// The name of the node from the DAG, when available.
    fn node_name(&self) -> Option<String>;
    /// The type of event (e.g. `started`, `succeeded`, `failed`).
    fn event_type(&self) -> String;
    /// The full event payload.
    fn event_data(&self) -> &serde_json::Value;
    /// When the event was recorded, rendered for display.
    fn created_at(&self) -> String;
}

/// A detailed view of a saga including its events, mirroring the server
/// `SagaDetailView`.
pub trait CliSagaDetail {
    /// The concrete event type carried by this detail view.
    type Event: CliSagaEvent;

    /// Unique identifier of the saga, rendered as a string.
    fn id(&self) -> String;
    /// Human-readable name of the saga type.
    fn name(&self) -> String;
    /// Current cached state of the saga.
    fn state(&self) -> String;
    /// When the saga was created, rendered for display.
    fn created_at(&self) -> String;
    /// When the saga was last updated, rendered for display.
    fn updated_at(&self) -> String;
    /// The saga DAG, serialized as JSON in the shape produced by steno's
    /// `SagaDag`. The browser unpacks this to derive the ordered, indented list
    /// of nodes shown in the detail view.
    fn dag(&self) -> serde_json::Value;
    /// All recorded events for this saga.
    fn events(&self) -> &[Self::Event];
}

/// The adapter a consumer implements to let the saga browser fetch data from
/// their API. Implementations typically wrap a generated API client together
/// with an access token.
pub trait CliSagaAdapter {
    /// Concrete summary type returned when listing sagas.
    type Summary: CliSagaSummary + Send;
    /// Concrete detail type returned when viewing a single saga.
    type Detail: CliSagaDetail + Send;
    /// Error type surfaced by the underlying client.
    type Error: StdError + Send + Sync + 'static;

    /// Fetch a page of sagas.
    ///
    /// `page_token` is `None` for the first page, or the [`SagaPage::next_page`]
    /// token returned by a previous call. `limit` is the desired page size.
    fn list_sagas(
        &self,
        page_token: Option<String>,
        limit: u32,
    ) -> BoxFuture<'_, Result<SagaPage<Self::Summary>, Self::Error>>;

    /// Fetch the details (including events) for a single saga by id.
    fn get_saga(&self, id: String) -> BoxFuture<'_, Result<Self::Detail, Self::Error>>;
}

#[cfg(test)]
mod tests {
    //! Compile-level check that the adapter traits can be implemented on
    //! consumer-owned types using the intended boxed-future style.

    use super::*;

    struct Summary;
    impl CliSagaSummary for Summary {
        fn id(&self) -> String {
            "id".into()
        }
        fn name(&self) -> String {
            "name".into()
        }
        fn state(&self) -> String {
            "running".into()
        }
        fn created_at(&self) -> String {
            String::new()
        }
        fn updated_at(&self) -> String {
            String::new()
        }
    }

    struct Event {
        data: serde_json::Value,
    }
    impl CliSagaEvent for Event {
        fn id(&self) -> i64 {
            1
        }
        fn node_id(&self) -> i64 {
            0
        }
        fn node_name(&self) -> Option<String> {
            None
        }
        fn event_type(&self) -> String {
            "started".into()
        }
        fn event_data(&self) -> &serde_json::Value {
            &self.data
        }
        fn created_at(&self) -> String {
            String::new()
        }
    }

    struct Detail {
        events: Vec<Event>,
    }
    impl CliSagaDetail for Detail {
        type Event = Event;
        fn id(&self) -> String {
            "id".into()
        }
        fn name(&self) -> String {
            "name".into()
        }
        fn state(&self) -> String {
            "done".into()
        }
        fn created_at(&self) -> String {
            String::new()
        }
        fn updated_at(&self) -> String {
            String::new()
        }
        fn dag(&self) -> serde_json::Value {
            serde_json::json!({})
        }
        fn events(&self) -> &[Event] {
            &self.events
        }
    }

    struct Adapter;
    impl CliSagaAdapter for Adapter {
        type Summary = Summary;
        type Detail = Detail;
        type Error = std::io::Error;

        fn list_sagas(
            &self,
            _page_token: Option<String>,
            _limit: u32,
        ) -> BoxFuture<'_, Result<SagaPage<Self::Summary>, Self::Error>> {
            Box::pin(async {
                Ok(SagaPage {
                    items: vec![Summary],
                    next_page: None,
                })
            })
        }

        fn get_saga(&self, _id: String) -> BoxFuture<'_, Result<Self::Detail, Self::Error>> {
            Box::pin(async { Ok(Detail { events: Vec::new() }) })
        }
    }

    #[tokio::test]
    async fn adapter_is_implementable() {
        let adapter = Adapter;
        let page = adapter.list_sagas(None, 10).await.unwrap();
        assert_eq!(page.items.len(), 1);
        let detail = adapter.get_saga("id".to_string()).await.unwrap();
        assert!(detail.events().is_empty());
    }
}
