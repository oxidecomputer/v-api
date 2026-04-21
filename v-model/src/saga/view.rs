// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{DateTime, Utc};
use newtype_uuid::{GenericUuid, TypedUuid, TypedUuidKind, TypedUuidTag};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use steno::SagaCachedState;

use crate::saga::{
    db::{ModelSagaCachedState, SagaEventModel, SagaModel},
    jsonschema::SagaDagWrapper,
};

#[derive(JsonSchema)]
pub enum SagaId {}
impl TypedUuidKind for SagaId {
    fn tag() -> TypedUuidTag {
        const TAG: TypedUuidTag = TypedUuidTag::new("saga");
        TAG
    }
}

#[derive(JsonSchema)]
pub enum SagaEventId {}
impl TypedUuidKind for SagaEventId {
    fn tag() -> TypedUuidTag {
        const TAG: TypedUuidTag = TypedUuidTag::new("saga-event");
        TAG
    }
}

#[derive(JsonSchema)]
pub enum SagaExecNodeId {}
impl TypedUuidKind for SagaExecNodeId {
    fn tag() -> TypedUuidTag {
        const TAG: TypedUuidTag = TypedUuidTag::new("saga-exec-node");
        TAG
    }
}

/// View of a saga for external consumption.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SagaView {
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
}

impl From<ModelSagaCachedState> for SagaCachedState {
    fn from(model: ModelSagaCachedState) -> Self {
        match model {
            ModelSagaCachedState::Done => Self::Done,
            ModelSagaCachedState::Running => Self::Running,
            ModelSagaCachedState::Unwinding => Self::Unwinding,
        }
    }
}

impl From<SagaCachedState> for ModelSagaCachedState {
    fn from(model: SagaCachedState) -> Self {
        match model {
            SagaCachedState::Done => Self::Done,
            SagaCachedState::Running => Self::Running,
            SagaCachedState::Unwinding => Self::Unwinding,
        }
    }
}

impl From<SagaModel> for SagaView {
    fn from(model: SagaModel) -> Self {
        Self {
            id: TypedUuid::from_untyped_uuid(model.saga_id),
            name: model.name,
            dag: SagaDagWrapper(
                serde_json::from_value(model.dag).expect("Failed to deserialize stored DAG"),
            ),
            state: model.state.into(),
            current_node_id: model.current_node_id.map(TypedUuid::from_untyped_uuid),
            node_claimed_at: model.node_claimed_at,
            created_at: model.created_at,
            updated_at: model.updated_at,
        }
    }
}

/// View of a saga event for external consumption.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SagaEventView {
    /// Auto-generated event ID
    pub id: i64,
    /// The saga this event belongs to
    pub saga_id: TypedUuid<SagaId>,
    /// The node within the saga DAG
    pub node_id: i64,
    /// Type of event
    pub event_type: String,
    /// Full event data
    pub event_data: serde_json::Value,
    /// When the event was recorded
    pub created_at: DateTime<Utc>,
}

impl From<SagaEventModel> for SagaEventView {
    fn from(model: SagaEventModel) -> Self {
        Self {
            id: model.id,
            saga_id: TypedUuid::from_untyped_uuid(model.saga_id),
            node_id: model.node_id,
            event_type: model.event_type,
            event_data: model.event_data,
            created_at: model.created_at,
        }
    }
}
