// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_bb8_diesel::AsyncRunQueryDsl;
use async_trait::async_trait;
use chrono::Utc;
use diesel::{
    delete, insert_into, query_dsl::QueryDsl, update, BoolExpressionMethods, ExpressionMethods,
    NullableExpressionMethods, OptionalExtension,
};
use newtype_uuid::{GenericUuid, TypedUuid};

use crate::{
    saga::{
        db::{ModelSagaCachedState, NewSagaEventModel, NewSagaModel, SagaEventModel, SagaModel},
        storage::{SagaEventFilter, SagaEventStore, SagaFilter, SagaStore},
        view::{SagaExecNodeId, SagaId},
    },
    schema::{saga_events, sagas},
    storage::{postgres::PostgresStore, ListPagination, StoreError},
};

#[async_trait]
impl SagaStore for PostgresStore {
    async fn get(&self, saga_id: TypedUuid<SagaId>) -> Result<Option<SagaModel>, StoreError> {
        let result = sagas::dsl::sagas
            .filter(sagas::saga_id.eq(saga_id.into_untyped_uuid()))
            .get_result_async::<SagaModel>(&*self.pool.get().await?)
            .await
            .optional()?;

        Ok(result)
    }

    async fn list(
        &self,
        filters: Vec<SagaFilter>,
        pagination: &ListPagination,
    ) -> Result<Vec<SagaModel>, StoreError> {
        let mut query = sagas::dsl::sagas.into_boxed();

        // Each SagaFilter in the Vec represents an OR group.
        // Within a single SagaFilter, all set fields are AND'd together.
        // Multiple SagaFilters are OR'd together.
        if !filters.is_empty() {
            // Build a combined OR expression from all filters
            let mut or_expression: Option<
                Box<
                    dyn diesel::expression::BoxableExpression<
                        sagas::table,
                        diesel::pg::Pg,
                        SqlType = diesel::sql_types::Bool,
                    >,
                >,
            > = None;

            for filter in filters {
                // Start with TRUE and AND each condition
                let mut and_expression: Box<
                    dyn diesel::expression::BoxableExpression<
                        sagas::table,
                        diesel::pg::Pg,
                        SqlType = diesel::sql_types::Bool,
                    >,
                > = Box::new(diesel::dsl::sql::<diesel::sql_types::Bool>("TRUE"));

                if let Some(saga_ids) = filter.saga_id {
                    and_expression = Box::new(and_expression.and(
                        sagas::saga_id
                            .eq_any(saga_ids.into_iter().map(|id| id.into_untyped_uuid())),
                    ));
                }

                if let Some(names) = filter.name {
                    and_expression = Box::new(and_expression.and(sagas::name.eq_any(names)));
                }

                if let Some(states) = filter.state {
                    and_expression =
                        Box::new(and_expression.and(sagas::state.eq_any(states)));
                }

                if let Some(node_ids) = filter.current_node_id {
                    let uuids: Vec<uuid::Uuid> = node_ids
                        .into_iter()
                        .filter_map(|id| uuid::Uuid::parse_str(&id).ok())
                        .collect();
                    and_expression = Box::new(
                        and_expression.and(
                            sagas::current_node_id
                                .assume_not_null()
                                .eq_any(uuids),
                        ),
                    );
                }

                if let Some(true) = filter.unclaimed {
                    and_expression =
                        Box::new(and_expression.and(sagas::current_node_id.is_null()));
                }

                or_expression = Some(match or_expression {
                    None => and_expression,
                    Some(prev) => Box::new(prev.or(and_expression)),
                });
            }

            if let Some(expr) = or_expression {
                query = query.filter(expr);
            }
        }

        let results = query
            .offset(pagination.offset)
            .limit(pagination.limit)
            .order(sagas::created_at.asc())
            .get_results_async::<SagaModel>(&*self.pool.get().await?)
            .await?;

        Ok(results)
    }

    async fn create(&self, new_saga: NewSagaModel) -> Result<SagaModel, StoreError> {
        let saga = insert_into(sagas::dsl::sagas)
            .values((
                sagas::saga_id.eq(new_saga.saga_id),
                sagas::name.eq(new_saga.name),
                sagas::dag.eq(new_saga.dag),
                sagas::state.eq(new_saga.state),
                sagas::current_node_id.eq(new_saga.current_node_id),
                sagas::node_claimed_at.eq(new_saga.node_claimed_at),
            ))
            .get_result_async::<SagaModel>(&*self.pool.get().await?)
            .await?;

        Ok(saga)
    }

    async fn update_state(
        &self,
        saga_id: TypedUuid<SagaId>,
        state: ModelSagaCachedState,
    ) -> Result<Option<SagaModel>, StoreError> {
        let new_state: ModelSagaCachedState = state;
        let result = update(sagas::dsl::sagas)
            .filter(sagas::saga_id.eq(saga_id.into_untyped_uuid()))
            .set((
                sagas::state.eq(new_state),
                sagas::updated_at.eq(Utc::now()),
            ))
            .get_result_async::<SagaModel>(&*self.pool.get().await?)
            .await
            .optional()?;

        Ok(result)
    }

    async fn try_claim(
        &self,
        saga_id: TypedUuid<SagaId>,
        node_id: TypedUuid<SagaExecNodeId>,
    ) -> Result<Option<SagaModel>, StoreError> {
        let result = update(sagas::dsl::sagas)
            .filter(sagas::saga_id.eq(saga_id.into_untyped_uuid()))
            .filter(sagas::current_node_id.is_null())
            .set((
                sagas::current_node_id.eq(Some(node_id.into_untyped_uuid())),
                sagas::node_claimed_at.eq(Some(Utc::now())),
                sagas::updated_at.eq(Utc::now()),
            ))
            .get_result_async::<SagaModel>(&*self.pool.get().await?)
            .await
            .optional()?;

        Ok(result)
    }

    async fn release_claim(
        &self,
        saga_id: TypedUuid<SagaId>,
        node_id: TypedUuid<SagaExecNodeId>,
    ) -> Result<Option<SagaModel>, StoreError> {
        let node_uuid = node_id.into_untyped_uuid();
        let result = update(sagas::dsl::sagas)
            .filter(sagas::saga_id.eq(saga_id.into_untyped_uuid()))
            .filter(
                sagas::current_node_id.eq(Some(node_uuid)),
            )
            .set((
                sagas::current_node_id.eq(None::<uuid::Uuid>),
                sagas::node_claimed_at.eq(None::<chrono::DateTime<Utc>>),
                sagas::updated_at.eq(Utc::now()),
            ))
            .get_result_async::<SagaModel>(&*self.pool.get().await?)
            .await
            .optional()?;

        Ok(result)
    }

    async fn delete(&self, saga_id: TypedUuid<SagaId>) -> Result<Option<SagaModel>, StoreError> {
        let uuid = saga_id.into_untyped_uuid();

        // Delete associated events first
        delete(saga_events::dsl::saga_events)
            .filter(saga_events::saga_id.eq(uuid))
            .execute_async(&*self.pool.get().await?)
            .await?;

        // Delete the saga itself
        let result = delete(sagas::dsl::sagas)
            .filter(sagas::saga_id.eq(uuid))
            .get_result_async::<SagaModel>(&*self.pool.get().await?)
            .await
            .optional()?;

        Ok(result)
    }
}

#[async_trait]
impl SagaEventStore for PostgresStore {
    async fn list(
        &self,
        filters: Vec<SagaEventFilter>,
        pagination: &ListPagination,
    ) -> Result<Vec<SagaEventModel>, StoreError> {
        let mut query = saga_events::dsl::saga_events.into_boxed();

        if !filters.is_empty() {
            let mut or_expression: Option<
                Box<
                    dyn diesel::expression::BoxableExpression<
                        saga_events::table,
                        diesel::pg::Pg,
                        SqlType = diesel::sql_types::Bool,
                    >,
                >,
            > = None;

            for filter in filters {
                let mut and_expression: Box<
                    dyn diesel::expression::BoxableExpression<
                        saga_events::table,
                        diesel::pg::Pg,
                        SqlType = diesel::sql_types::Bool,
                    >,
                > = Box::new(diesel::dsl::sql::<diesel::sql_types::Bool>("TRUE"));

                if let Some(saga_ids) = filter.saga_id {
                    and_expression = Box::new(and_expression.and(
                        saga_events::saga_id
                            .eq_any(saga_ids.into_iter().map(|id| id.into_untyped_uuid())),
                    ));
                }

                if let Some(event_types) = filter.event_type {
                    and_expression = Box::new(
                        and_expression.and(saga_events::event_type.eq_any(event_types)),
                    );
                }

                or_expression = Some(match or_expression {
                    None => and_expression,
                    Some(prev) => Box::new(prev.or(and_expression)),
                });
            }

            if let Some(expr) = or_expression {
                query = query.filter(expr);
            }
        }

        let results = query
            .offset(pagination.offset)
            .limit(pagination.limit)
            .order(saga_events::id.asc())
            .get_results_async::<SagaEventModel>(&*self.pool.get().await?)
            .await?;

        Ok(results)
    }

    async fn create(&self, new_event: NewSagaEventModel) -> Result<SagaEventModel, StoreError> {
        let event = insert_into(saga_events::dsl::saga_events)
            .values((
                saga_events::saga_id.eq(new_event.saga_id),
                saga_events::node_id.eq(new_event.node_id),
                saga_events::event_type.eq(new_event.event_type),
                saga_events::event_data.eq(new_event.event_data),
            ))
            .get_result_async::<SagaEventModel>(&*self.pool.get().await?)
            .await?;

        Ok(event)
    }

    async fn delete_for_saga(&self, saga_id: TypedUuid<SagaId>) -> Result<u64, StoreError> {
        let count = delete(saga_events::dsl::saga_events)
            .filter(saga_events::saga_id.eq(saga_id.into_untyped_uuid()))
            .execute_async(&*self.pool.get().await?)
            .await?;

        Ok(count as u64)
    }
}