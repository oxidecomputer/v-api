// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use newtype_uuid::TypedUuid;
use serde_json::Value;
use std::{collections::BTreeSet, sync::Arc};
use v_model::{
    AccessGroupId, Mapper, MapperId, NewMapper, NewMapperEvent, Permissions, UserId,
    permissions::Caller,
    storage::{ListPagination, MapperEventStore, MapperFilter, MapperStore, StoreError},
};

use crate::{
    VApiStorage,
    endpoints::login::UserInfo,
    mapper::MappingEngine,
    permissions::{VAppPermission, VPermission},
    response::{OptionalResource, ResourceResult, resource_restricted},
};

pub struct MappingContext<T> {
    engine: Option<Arc<dyn MappingEngine<T>>>,
    storage: Arc<dyn VApiStorage<T>>,
    ephemeral_mappers: Vec<Mapper>,
}

impl<T> MappingContext<T>
where
    T: VAppPermission,
{
    pub fn new(storage: Arc<dyn VApiStorage<T>>) -> Self {
        Self {
            engine: None,
            storage,
            ephemeral_mappers: Vec::new(),
        }
    }

    pub fn set_storage(&mut self, storage: Arc<dyn VApiStorage<T>>) {
        self.storage = storage;
    }

    pub fn set_engine(
        &mut self,
        engine: Option<Arc<dyn MappingEngine<T>>>,
    ) -> Option<Arc<dyn MappingEngine<T>>> {
        let previous = self.engine.take();
        self.engine = engine;
        previous
    }

    pub fn set_ephemeral_mappers(&mut self, mappers: Vec<Mapper>) {
        self.ephemeral_mappers = mappers;
    }

    pub fn is_ephemeral(&self, id: &TypedUuid<MapperId>) -> bool {
        self.ephemeral_mappers.iter().any(|m| &m.id == id)
    }

    pub fn validate(&self, value: &Value) -> bool {
        match &self.engine {
            Some(engine) => engine.validate_mapping_data(value),
            None => false,
        }
    }

    pub async fn get_mappers(
        &self,
        caller: &Caller<T>,
        included_depleted: bool,
    ) -> ResourceResult<Vec<Mapper>, StoreError> {
        if caller.can(&VPermission::GetMappersAll.into()) {
            let mut mappers = MapperStore::list(
                &*self.storage,
                MapperFilter::default().depleted(included_depleted),
                &ListPagination::unlimited(),
            )
            .await?;
            mappers.extend(self.ephemeral_mappers.iter().cloned());

            Ok(mappers)
        } else {
            resource_restricted()
        }
    }

    pub async fn add_mapper(
        &self,
        caller: &Caller<T>,
        new_mapper: &NewMapper,
    ) -> ResourceResult<Mapper, StoreError> {
        if caller.can(&VPermission::CreateMapper.into()) {
            Ok(MapperStore::upsert(&*self.storage, new_mapper).await?)
        } else {
            resource_restricted()
        }
    }

    pub async fn remove_mapper(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<MapperId>,
    ) -> ResourceResult<Mapper, StoreError> {
        if caller.can(&VPermission::ManageMapper(*id).into()) {
            MapperStore::delete(&*self.storage, id).await.optional()
        } else {
            resource_restricted()
        }
    }

    pub async fn get_mapped_fields(
        &self,
        caller: &Caller<T>,
        info: &UserInfo,
        user_id: TypedUuid<UserId>,
    ) -> ResourceResult<(Permissions<T>, BTreeSet<TypedUuid<AccessGroupId>>), StoreError> {
        let mut mapped_permissions = Permissions::new();
        let mut mapped_groups = BTreeSet::new();

        // We only need to run mapping logic if there is mapping engine available to transform
        // mappers into mappings
        if let Some(engine) = &self.engine {
            // We optimistically load mappers here. We do not want to take a lock on the mappers and
            // instead handle mappers that become depleted before we can evaluate them at evaluation
            // time.
            for mapper in self.get_mappers(caller, false).await? {
                let is_ephemeral = self.is_ephemeral(&mapper.id);
                tracing::trace!(?mapper.name, is_ephemeral, "Attempt to run mapper");

                // Try to transform this mapper into a mapping
                let mapping = engine.create_mapping(mapper.clone());

                let (mut permissions, mut groups) = match mapping {
                    Ok(mapping) => {
                        tracing::trace!(?mapper.name, "Applying mapping");
                        (
                            mapping.permissions_for(info).await?,
                            mapping.groups_for(info).await?,
                        )
                    }
                    Err(err) => {
                        // Errors here can be expected. They are reported, but not acted upon
                        tracing::info!(?err, "No mapping was found for mapper");
                        (Permissions::new(), BTreeSet::default())
                    }
                };

                let apply = if !permissions.is_empty() || !groups.is_empty() {
                    if is_ephemeral {
                        // Ephemeral mappers always apply - no activation gating
                        true
                    } else if mapper.max_activations.is_some() {
                        // Dynamic mappers with activation limits need to consume an activation
                        match self.consume_mapping_activation(&mapper).await {
                            Ok(_) => true,
                            Err(err) => {
                                // TODO: Inspect the error. We expect to see a conflict error, and
                                // should is expected to be seen. Other errors are problematic.
                                tracing::info!(
                                    ?err,
                                    "Login may have attempted to use depleted mapper."
                                );
                                false
                            }
                        }
                    } else {
                        // Dynamic mappers without activation limits always apply
                        true
                    }
                } else {
                    false
                };

                if apply {
                    // Record the mapper event for audit purposes
                    if let Err(err) = self
                        .record_mapper_event(&mapper, user_id, is_ephemeral)
                        .await
                    {
                        tracing::warn!(
                            ?err,
                            mapper_name = ?mapper.name,
                            "Failed to record mapper event"
                        );
                    }

                    mapped_permissions.append(&mut permissions);
                    mapped_groups.append(&mut groups);
                }
            }
        };

        Ok((mapped_permissions, mapped_groups))
    }

    // TODO: Create a permission for this that only the registration user has
    async fn consume_mapping_activation(&self, mapper: &Mapper) -> Result<(), StoreError> {
        // Activations are only incremented if the rule actually has a max activation value
        let activations = mapper
            .max_activations
            .map(|_| mapper.activations.unwrap_or(0) + 1);

        let mut update: NewMapper = mapper.clone().into();
        update.activations = activations;

        MapperStore::upsert(&*self.storage, &update)
            .await
            .map(|_| ())
    }

    async fn record_mapper_event(
        &self,
        mapper: &Mapper,
        user_id: TypedUuid<UserId>,
        ephemeral: bool,
    ) -> Result<(), StoreError> {
        let event = NewMapperEvent {
            id: TypedUuid::new_v4(),
            mapper_id: mapper.id,
            mapper_name: mapper.name.clone(),
            user_id,
            rule: mapper.rule.clone(),
            ephemeral,
        };

        MapperEventStore::record(&*self.storage, &event)
            .await
            .map(|_| ())
    }
}
