use async_trait::async_trait;
#[cfg(feature = "mock")]
use mockall::automock;
use newtype_uuid::TypedUuid;

use crate::{saga::{db::{ModelSagaCachedState, NewSagaEventModel, NewSagaModel, SagaEventModel, SagaModel}, view::{SagaExecNodeId, SagaId}}, storage::{StoreError, ListPagination}};

/// Filter for querying sagas.
#[derive(Debug, Default)]
pub struct SagaFilter {
    /// Filter by saga ID
    pub saga_id: Option<Vec<TypedUuid<SagaId>>>,
    /// Filter by saga name (type)
    pub name: Option<Vec<String>>,
    /// Filter by cached state
    pub state: Option<Vec<ModelSagaCachedState>>,
    /// Filter by current node ID
    pub current_node_id: Option<Vec<String>>,
    /// Filter for unclaimed sagas (current_node_id IS NULL)
    pub unclaimed: Option<bool>,
}

impl SagaFilter {
    pub fn saga_id(mut self, saga_id: Option<Vec<TypedUuid<SagaId>>>) -> Self {
        self.saga_id = saga_id;
        self
    }

    pub fn name(mut self, name: Option<Vec<String>>) -> Self {
        self.name = name;
        self
    }

    pub fn state(mut self, state: Option<Vec<ModelSagaCachedState>>) -> Self {
        self.state = state;
        self
    }

    pub fn current_node_id(mut self, current_node_id: Option<Vec<String>>) -> Self {
        self.current_node_id = current_node_id;
        self
    }

    pub fn unclaimed(mut self, unclaimed: Option<bool>) -> Self {
        self.unclaimed = unclaimed;
        self
    }
}

/// Storage trait for saga records.
#[cfg_attr(feature = "mock", automock)]
#[async_trait]
pub trait SagaStore {
    /// Get a saga by ID.
    async fn get(&self, saga_id: TypedUuid<SagaId>) -> Result<Option<SagaModel>, StoreError>;

    /// List sagas matching the given filters.
    async fn list(
        &self,
        filters: Vec<SagaFilter>,
        pagination: &ListPagination,
    ) -> Result<Vec<SagaModel>, StoreError>;

    /// Create a new saga record.
    async fn create(&self, new_saga: NewSagaModel) -> Result<SagaModel, StoreError>;

    /// Update a saga's state and node claim.
    async fn update_state(
        &self,
        saga_id: TypedUuid<SagaId>,
        state: ModelSagaCachedState,
    ) -> Result<Option<SagaModel>, StoreError>;

    /// Attempt to claim a saga for processing by a node.
    /// Returns the updated saga if the claim succeeded, None if already claimed by another node.
    async fn try_claim(
        &self,
        saga_id: TypedUuid<SagaId>,
        node_id: TypedUuid<SagaExecNodeId>,
    ) -> Result<Option<SagaModel>, StoreError>;

    /// Release a node's claim on a saga.
    async fn release_claim(
        &self,
        saga_id: TypedUuid<SagaId>,
        node_id: TypedUuid<SagaExecNodeId>,
    ) -> Result<Option<SagaModel>, StoreError>;

    /// Delete a saga and all its events.
    async fn delete(&self, saga_id: TypedUuid<SagaId>) -> Result<Option<SagaModel>, StoreError>;
}

/// Filter for querying saga events.
#[derive(Debug, Default)]
pub struct SagaEventFilter {
    /// Filter by saga ID
    pub saga_id: Option<Vec<TypedUuid<SagaId>>>,
    /// Filter by event type
    pub event_type: Option<Vec<String>>,
}

impl SagaEventFilter {
    pub fn saga_id(mut self, saga_id: Option<Vec<TypedUuid<SagaId>>>) -> Self {
        self.saga_id = saga_id;
        self
    }

    pub fn event_type(mut self, event_type: Option<Vec<String>>) -> Self {
        self.event_type = event_type;
        self
    }
}

/// Storage trait for saga event records.
#[cfg_attr(feature = "mock", automock)]
#[async_trait]
pub trait SagaEventStore {
    /// List events for a saga in order.
    async fn list(
        &self,
        filters: Vec<SagaEventFilter>,
        pagination: &ListPagination,
    ) -> Result<Vec<SagaEventModel>, StoreError>;

    /// Record a new event for a saga.
    async fn create(&self, new_event: NewSagaEventModel) -> Result<SagaEventModel, StoreError>;

    /// Delete all events for a saga (used when deleting the saga).
    async fn delete_for_saga(&self, saga_id: TypedUuid<SagaId>) -> Result<u64, StoreError>;
}
