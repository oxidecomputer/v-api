// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{DateTime, Utc};
use dropshot::{HttpError, HttpResponseOk, Path, RequestContext};
use newtype_uuid::{GenericUuid, TypedUuid};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use steno::{SagaCachedState, SagaDag};
use v_model::{
    permissions::PermissionStorage,
    saga::{
        jsonschema::SagaDagWrapper,
        storage::SagaFilter,
        view::{SagaExecNodeId, SagaId, SagaView},
    },
};

use crate::{permissions::VAppPermission, ApiContext};

/// An enriched view of a saga event that includes the node name from the dag
#[derive(Debug, Serialize, JsonSchema)]
pub struct EnrichedSagaEventView {
    /// Auto-generated event ID
    pub id: i64,
    /// The saga this event belongs to
    pub saga_id: TypedUuid<SagaId>,
    /// The node index within the saga DAG
    pub node_id: i64,
    /// The name of the node from the DAG (if available)
    pub node_name: Option<String>,
    /// Type of event
    pub event_type: String,
    /// Full event data
    pub event_data: serde_json::Value,
    /// When the event was recorded
    pub created_at: DateTime<Utc>,
}

/// A detailed view of a saga including its events
#[derive(Debug, Serialize, JsonSchema)]
pub struct SagaDetailView {
    /// Unique identifier for this saga
    pub id: TypedUuid<SagaId>,
    /// Human-readable name of the saga type
    pub name: String,
    /// Current cached state of the saga
    pub state: SagaCachedState,
    /// A structure representing the DAG of the saga
    pub dag: SagaDagWrapper,
    /// ID of the node currently processing this saga
    pub current_node_id: Option<TypedUuid<SagaExecNodeId>>,
    /// When the current node claimed this saga
    pub node_claimed_at: Option<DateTime<Utc>>,
    /// When the saga was created
    pub created_at: DateTime<Utc>,
    /// When the saga was last updated
    pub updated_at: DateTime<Utc>,
    /// Events for this saga in reverse chronological order
    pub events: Vec<EnrichedSagaEventView>,
}

/// Extracts node name from the dag given a node index
fn get_node_name_from_dag(dag: &SagaDag, node_id: i64) -> Option<String> {
    // The node_id corresponds to the node index in the graph.
    // Use get_nodes() to iterate through all named nodes and find the one
    // with the matching index. Note that get_nodes() only returns named nodes
    // (Action, Constant, SubsagaEnd), not Start, End, or SubsagaStart nodes.
    dag.get_nodes()
        .find(|entry| entry.index().index() == node_id as usize)
        .map(|entry| entry.name().as_ref().to_string())
}

pub async fn list_sagas_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
) -> Result<HttpResponseOk<Vec<SagaView>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let caller = rqctx.v_ctx().get_caller(&rqctx).await?;
    let sagas = rqctx
        .v_ctx()
        .saga
        .list_sagas(&caller, SagaFilter::default())
        .await
        .map_err(|err| {
            tracing::error!(?err, "Failed to list sagas");
            HttpError::for_internal_error("Failed to list sagas".to_string())
        })?;

    Ok(HttpResponseOk(sagas))
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SagaPath {
    /// UUID of a saga
    saga: TypedUuid<SagaId>,
}

pub async fn view_saga_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<SagaPath>,
) -> Result<HttpResponseOk<SagaDetailView>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let ctx = rqctx.v_ctx();
    let caller = ctx.get_caller(&rqctx).await?;
    let saga_id = path.into_inner().saga;

    // Get the saga
    let saga = ctx.saga.get_saga(&caller, saga_id).await?;

    // Get the events for this saga
    let events = ctx
        .saga
        .list_event_models(&caller, saga_id)
        .await
        .map_err(|err| {
            tracing::error!(?err, "Failed to list saga events");
            HttpError::for_internal_error("Failed to list saga events".to_string())
        })?;

    // Enrich events with node names from the dag
    let enriched_events: Vec<EnrichedSagaEventView> = events
        .into_iter()
        .map(|event| {
            let node_name = get_node_name_from_dag(&saga.dag, event.node_id);
            EnrichedSagaEventView {
                id: event.id,
                saga_id: TypedUuid::from_untyped_uuid(event.saga_id),
                node_id: event.node_id,
                node_name,
                event_type: event.event_type,
                event_data: event.event_data,
                created_at: event.created_at,
            }
        })
        .collect();

    let detail_view = SagaDetailView {
        id: saga.id,
        name: saga.name,
        state: saga.state,
        dag: saga.dag,
        current_node_id: saga.current_node_id,
        node_claimed_at: saga.node_claimed_at,
        created_at: saga.created_at,
        updated_at: saga.updated_at,
        events: enriched_events,
    };

    Ok(HttpResponseOk(detail_view))
}
