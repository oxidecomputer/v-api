// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use newtype_uuid::{GenericUuid, TypedUuid};
use slog::{Discard, Logger, o};
use std::{fmt::Debug, future::Future, pin::Pin, sync::Arc};
use steno::{
    ActionRegistry, SagaCachedState, SagaCreateParams, SagaDag, SagaId as StenoId, SagaNodeEvent,
    SagaResult, SagaType, SecClient, SecStore,
};
use thiserror::Error;
use uuid::Uuid;
use v_model::{
    permissions::Caller,
    saga::{
        db::{NewSagaEventModel, NewSagaModel, SagaEventModel},
        storage::{SagaEventFilter, SagaEventStore, SagaFilter, SagaStore},
        view::{SagaExecNodeId, SagaId, SagaView},
    },
    storage::ListPagination,
};

use crate::{
    ApiContext, VApiStorage,
    permissions::{VAppPermission, VPermission},
    response::{
        OptionalResource, ResourceError, ResourceErrorInner, ResourceResult, resource_restricted,
    },
};

pub type CreateSagaFuture = Pin<
    Box<
        dyn Future<
                Output = Result<
                    (StenoId, Pin<Box<dyn Future<Output = SagaResult> + Send>>),
                    SagaCtxError,
                >,
            > + Send,
    >,
>;

/// Errors that can occur in the saga store.
#[derive(Debug, Error)]
pub enum SagaCtxError {
    #[error("Sec must be configured before sagas can be created")]
    SecNotConfigured,
    #[error("Failed to create saga")]
    Creation(anyhow::Error),
    #[error("Failed to start saga")]
    Start(anyhow::Error),
    #[error("Storage error")]
    Storage(#[from] v_model::storage::StoreError),
    #[error("Serialization error")]
    Serialization(String),
    #[error("Deserialization error")]
    Deserialization(String),
    #[error("Saga not found: {0}")]
    NotFound(TypedUuid<SagaId>),
}

#[derive(Clone)]
pub struct SagaContext<T> {
    node_id: TypedUuid<SagaExecNodeId>,
    sec: Arc<SecClient>,
    storage: Arc<dyn VApiStorage<T>>,
}

impl<T> SagaContext<T>
where
    T: VAppPermission,
{
    pub fn new(
        node_id: TypedUuid<SagaExecNodeId>,
        storage: Arc<dyn VApiStorage<T>>,
        logger: Option<Logger>,
    ) -> Self {
        let adapter = SecStoreAdapter {
            node_id,
            storage: storage.clone(),
        };

        let logger = logger.unwrap_or_else(|| Logger::root(Discard, o!()));

        Self {
            node_id,
            sec: Arc::new(steno::sec(logger, Arc::new(adapter))),
            storage,
        }
    }

    /// Get the node ID for this adapter.
    pub fn node_id(&self) -> TypedUuid<SagaExecNodeId> {
        self.node_id
    }

    pub fn sec(&self) -> Arc<SecClient> {
        self.sec.clone()
    }

    /// Get a saga by ID.
    pub async fn get_saga(
        &self,
        caller: &Caller<T>,
        saga_id: TypedUuid<SagaId>,
    ) -> ResourceResult<SagaView, SagaCtxError> {
        if caller.can(&VPermission::GetSagasAll.into()) {
            let model = SagaStore::get(&*self.storage, saga_id).await.optional()?;
            Ok(model.into())
        } else {
            resource_restricted()
        }
    }

    /// List all sagas matching the given filter.
    pub async fn list_sagas(
        &self,
        caller: &Caller<T>,
        filter: SagaFilter,
    ) -> ResourceResult<Vec<SagaView>, SagaCtxError> {
        if caller.can(&VPermission::GetSagasAll.into()) {
            let models =
                SagaStore::list(&*self.storage, vec![filter], &ListPagination::unlimited())
                    .await
                    .map_err(ResourceError::InternalError)
                    .inner_err_into()?;
            Ok(models.into_iter().map(SagaView::from).collect())
        } else {
            resource_restricted()
        }
    }

    pub async fn start_saga(
        &self,
        caller: &Caller<T>,
        saga: StenoId,
    ) -> ResourceResult<StenoId, SagaCtxError> {
        if caller.can(&VPermission::ManageSagasAll.into()) {
            self.sec
                .saga_start(saga)
                .await
                .map_err(SagaCtxError::Start)
                .map_err(ResourceError::InternalError)?;
            tracing::info!(saga = ?saga, "Started saga");

            Ok(saga)
        } else {
            resource_restricted()
        }
    }

    /// Create a new saga
    pub fn create_saga<S, R>(
        &self,
        caller: &Caller<T>,
        dag: Arc<SagaDag>,
        context: Arc<S>,
        registry: Arc<ActionRegistry<R>>,
    ) -> ResourceResult<CreateSagaFuture, SagaCtxError>
    where
        S: ApiContext,
        R: SagaType<ExecContextType = S>,
    {
        if caller.can(&VPermission::ManageSagasAll.into()) {
            let sec = self.sec.clone();
            Ok(Box::pin(async move {
                let saga_id = StenoId(Uuid::new_v4());

                // This returns a future that can be used to await the completion of the saga. We safely
                // drop it here as the executor handles continual execution for the saga.
                let handle = sec
                    .saga_create(saga_id, context, dag, registry)
                    .await
                    .map_err(|err| {
                        tracing::error!(error = %err, "Failed to create saga");
                        SagaCtxError::Creation(err)
                    })?;

                tracing::info!(saga = ?saga_id, "Created saga");

                Ok((saga_id, handle))
            }))
        } else {
            resource_restricted()
        }
    }

    /// Attempt to claim a saga for processing by this node. This does not distinguish between
    /// a saga that is already claimed by another node and a saga that does not exist.
    pub async fn try_claim_saga(
        &self,
        caller: &Caller<T>,
        saga_id: TypedUuid<SagaId>,
    ) -> ResourceResult<Option<SagaView>, SagaCtxError> {
        if caller.can(&VPermission::ManageSagasAll.into()) {
            let model = SagaStore::try_claim(&*self.storage, saga_id, self.node_id)
                .await
                .map_err(ResourceError::InternalError)
                .inner_err_into()?;
            Ok(model.map(SagaView::from))
        } else {
            resource_restricted()
        }
    }

    /// Release this node's claim on a saga.
    pub async fn release_saga(
        &self,
        caller: &Caller<T>,
        saga_id: TypedUuid<SagaId>,
    ) -> ResourceResult<Option<SagaView>, SagaCtxError> {
        if caller.can(&VPermission::ManageSagasAll.into()) {
            let model = SagaStore::release_claim(&*self.storage, saga_id, self.node_id)
                .await
                .map_err(ResourceError::InternalError)
                .inner_err_into()?;
            Ok(model.map(SagaView::from))
        } else {
            resource_restricted()
        }
    }

    /// Delete a completed saga and its events.
    pub async fn delete_saga(
        &self,
        caller: &Caller<T>,
        saga_id: TypedUuid<SagaId>,
    ) -> ResourceResult<Option<SagaView>, SagaCtxError> {
        if caller.can(&VPermission::ManageSagasAll.into()) {
            let model = SagaStore::delete(&*self.storage, saga_id)
                .await
                .map_err(ResourceError::InternalError)
                .inner_err_into()?;
            Ok(model.map(SagaView::from))
        } else {
            resource_restricted()
        }
    }

    /// List all events for a saga as deserialized SagaNodeEvent
    pub async fn list_events(
        &self,
        caller: &Caller<T>,
        saga_id: TypedUuid<SagaId>,
    ) -> ResourceResult<Vec<SagaNodeEvent>, SagaCtxError> {
        if caller.can(&VPermission::GetSagasAll.into()) {
            let models = self.list_event_models(caller, saga_id).await?;

            Ok(models
                .into_iter()
                .map(|m| {
                    serde_json::from_value(m.event_data)
                        .map_err(|e| SagaCtxError::Deserialization(e.to_string()))
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(ResourceError::InternalError)?)
        } else {
            resource_restricted()
        }
    }

    /// List all events for a saga as raw SagaEventModel (for API responses)
    pub async fn list_event_models(
        &self,
        caller: &Caller<T>,
        saga_id: TypedUuid<SagaId>,
    ) -> ResourceResult<Vec<SagaEventModel>, SagaCtxError> {
        if caller.can(&VPermission::GetSagasAll.into()) {
            let models = SagaEventStore::list(
                &*self.storage,
                vec![SagaEventFilter::default().saga_id(Some(vec![saga_id]))],
                &ListPagination::unlimited(),
            )
            .await
            .map_err(ResourceError::InternalError)
            .inner_err_into()?;

            Ok(models)
        } else {
            resource_restricted()
        }
    }
}

struct SecStoreAdapter<T> {
    node_id: TypedUuid<SagaExecNodeId>,
    storage: Arc<dyn VApiStorage<T>>,
}
impl<T> std::fmt::Debug for SecStoreAdapter<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SagaContext")
            .field("node_id", &self.node_id)
            .finish()
    }
}

#[async_trait]
impl<T> SecStore for SecStoreAdapter<T> {
    async fn saga_create(&self, create_params: SagaCreateParams) -> Result<(), anyhow::Error> {
        let saga_id: TypedUuid<SagaId> = TypedUuid::from_untyped_uuid(create_params.id.0);
        let new_saga = NewSagaModel {
            saga_id: create_params.id.0,
            name: create_params.name.to_string(),
            dag: create_params.dag,
            state: create_params.state.into(),
            current_node_id: Some(self.node_id.into_untyped_uuid()),
            node_claimed_at: None,
        };

        SagaStore::create(&*self.storage, new_saga)
            .await
            .map_err(|err| {
                tracing::error!(
                    saga_id = %saga_id,
                    error = %err,
                    "Failed to create saga"
                );
                SagaCtxError::Storage(err)
            })?;

        tracing::debug!(
            saga_id = %saga_id,
            node_id = %self.node_id,
            "Created saga with node claim"
        );

        Ok(())
    }

    async fn record_event(&self, event: SagaNodeEvent) {
        let saga_id = event.saga_id;

        let event_data = match serde_json::to_value(&event) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(
                    saga_id = %saga_id,
                    error = %e,
                    "Failed to serialize saga event"
                );
                return;
            }
        };

        // Extract node_id from the serialized event data since SagaNodeId's inner field is private
        let node_id = event_data
            .get("node_id")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        let new_event = NewSagaEventModel {
            saga_id: saga_id.0,
            node_id,
            event_type: format!("{:?}", event.event_type),
            event_data,
        };

        if let Err(e) = SagaEventStore::create(&*self.storage, new_event).await {
            tracing::error!(
                saga_id = %saga_id,
                error = %e,
                "Failed to record saga event"
            );
        }
    }

    async fn saga_update(&self, id: steno::SagaId, update: SagaCachedState) {
        let saga_id: TypedUuid<SagaId> = TypedUuid::from_untyped_uuid(id.0);
        if let Err(err) = SagaStore::update_state(&*self.storage, saga_id, update.into()).await {
            tracing::error!(
                saga_id = %saga_id,
                error = %err,
                "Failed to update saga state"
            );
        }
    }
}
