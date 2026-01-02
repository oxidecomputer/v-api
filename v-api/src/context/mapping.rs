// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use newtype_uuid::TypedUuid;
use serde_json::Value;
use std::{collections::BTreeSet, sync::Arc};
use v_model::{
    permissions::Caller,
    storage::{ListPagination, MapperFilter, MapperStore, StoreError},
    AccessGroupId, Mapper, MapperId, NewMapper, Permissions,
};

use crate::{
    endpoints::login::UserInfo,
    mapper::MappingEngine,
    permissions::{VAppPermission, VPermission},
    response::{resource_restricted, OptionalResource, ResourceResult},
    VApiStorage,
};

pub struct MappingContext<T> {
    engine: Option<Arc<dyn MappingEngine<T>>>,
    storage: Arc<dyn VApiStorage<T>>,
}

impl<T> MappingContext<T>
where
    T: VAppPermission,
{
    pub fn new(storage: Arc<dyn VApiStorage<T>>) -> Self {
        Self {
            engine: None,
            storage,
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
            Ok(MapperStore::list(
                &*self.storage,
                MapperFilter::default().depleted(included_depleted),
                &ListPagination::unlimited(),
            )
            .await?)
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
        if caller.any(
            &mut [
                VPermission::ManageMapper(*id).into(),
                VPermission::ManageMappersAll.into(),
            ]
            .iter(),
        ) {
            MapperStore::delete(&*self.storage, id).await.optional()
        } else {
            resource_restricted()
        }
    }

    pub async fn get_mapped_fields(
        &self,
        caller: &Caller<T>,
        info: &UserInfo,
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
                tracing::trace!(?mapper.name, "Attempt to run mapper");

                // Try to transform this mapper into a mapping
                // let mappings = self.mapping_fns.iter().filter_map(|mapping_fn| mapping_fn(mapper.clone()).ok()).nth(0);
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
                        tracing::info!(?err, "Not mapping was found for mapper");
                        (Permissions::new(), BTreeSet::default())
                    }
                };

                // If a rule is set to apply a permission or group to a user, then the rule needs to be
                // checked for usage. If it does not have an activation limit then nothing is needed.
                // If it does have a limit then we need to attempt to consume an activation. If the
                // consumption works then we add the permissions. If they fail then we do not, but we
                // do not fail the entire mapping process
                let apply = if !permissions.is_empty() || !groups.is_empty() {
                    if mapper.max_activations.is_some() {
                        match self.consume_mapping_activation(&mapper).await {
                            Ok(_) => true,
                            Err(err) => {
                                // TODO: Inspect the error. We expect to see a conflict error, and
                                // should is expected to be seen. Other errors are problematic.
                                tracing::warn!(?err, "Login may have attempted to use depleted mapper. This may be ok if it is an isolated occurrence, but should occur repeatedly.");
                                false
                            }
                        }
                    } else {
                        true
                    }
                } else {
                    false
                };

                if apply {
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
}
