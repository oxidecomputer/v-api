// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use newtype_uuid::TypedUuid;
use serde_json::Value;
use std::{collections::BTreeSet, sync::Arc};
use v_model::{
    AccessGroup, AccessGroupId, Mapper, MapperEvent, MapperId, MapperSource, NewMapper,
    NewMapperEvent, UserId,
    permissions::Caller,
    storage::{ListPagination, MapperEventStore, MapperFilter, MapperStore, StoreError},
};

use crate::{
    VApiStorage,
    endpoints::login::UserInfo,
    mapper::{MappingEngine, MappingRulesData, resolve_mapped_groups},
    permissions::{VAppPermission, VPermission},
    response::{OptionalResource, ResourceError, ResourceResult, resource_restricted},
};

#[derive(Debug, thiserror::Error)]
pub enum AddMapperError {
    #[error("Mapper rule is invalid")]
    InvalidRule,
    #[error(transparent)]
    Resource(#[from] ResourceError<StoreError>),
}

pub struct MappingContext<T> {
    engine: Option<Arc<dyn MappingEngine>>,
    storage: Arc<dyn VApiStorage<T>>,
    preset_mappers: Vec<Mapper>,
}

impl<T> MappingContext<T>
where
    T: VAppPermission,
{
    pub fn new(storage: Arc<dyn VApiStorage<T>>) -> Self {
        Self {
            engine: None,
            storage,
            preset_mappers: Vec::new(),
        }
    }

    pub fn set_storage(&mut self, storage: Arc<dyn VApiStorage<T>>) {
        self.storage = storage;
    }

    pub fn set_engine(
        &mut self,
        engine: Option<Arc<dyn MappingEngine>>,
    ) -> Option<Arc<dyn MappingEngine>> {
        let previous = self.engine.take();
        self.engine = engine;
        previous
    }

    pub fn set_preset_mappers(&mut self, mappers: Vec<Mapper>) {
        self.preset_mappers = mappers;
    }

    pub fn is_preset(&self, id: &TypedUuid<MapperId>) -> bool {
        self.preset_mappers.iter().any(|m| &m.id == id)
    }

    pub fn validate(&self, value: &Value) -> bool {
        match &self.engine {
            Some(engine) => {
                tracing::trace!(?value, "Validating mapping rule");
                engine.validate_mapping_data(value) && self.is_current_mapper_version(value)
            }
            None => {
                tracing::warn!("No mapping rule is installed to validate rules");
                false
            }
        }
    }

    fn is_current_mapper_version(&self, value: &Value) -> bool {
        serde_json::from_value::<MappingRulesData>(value.clone()).is_ok()
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
            mappers.extend(self.preset_mappers.iter().cloned());

            Ok(mappers)
        } else {
            resource_restricted()
        }
    }

    /// Stores a new mapper.
    pub async fn add_mapper(
        &self,
        caller: &Caller<T>,
        visible_groups: &[AccessGroup<T>],
        new_mapper: &NewMapper,
    ) -> Result<Mapper, AddMapperError> {
        if !caller.can(&VPermission::CreateMapper.into()) {
            Err(ResourceError::Restricted.into())
        } else if !self.validate(&new_mapper.rule) {
            Err(AddMapperError::InvalidRule)
        } else if !self.can_grant_mapping(caller, visible_groups, &new_mapper.rule) {
            Err(ResourceError::Restricted.into())
        } else {
            let mapper = MapperStore::upsert(&*self.storage, new_mapper)
                .await
                .map_err(ResourceError::from)?;
            Ok(mapper)
        }
    }

    // TODO: Really don't like that we are passing in the visible_groups here. Needs some more
    // thought before figuring out how this is changed.

    /// Returns true if the caller could grant everything the rule grants.
    fn can_grant_mapping(
        &self,
        caller: &Caller<T>,
        visible_groups: &[AccessGroup<T>],
        rule: &Value,
    ) -> bool {
        match self
            .engine
            .as_ref()
            .map(|engine| engine.create_mapping(rule))
        {
            Some(Ok(mapping)) => {
                let grants = mapping.grants();
                let named = grants
                    .groups
                    .iter()
                    .map(|name| visible_groups.iter().find(|group| &group.name == name))
                    .collect::<Option<Vec<_>>>();

                match named {
                    Some(named) => named.iter().all(|group| {
                        caller.can(&VPermission::ManageGroupMembership(group.id).into())
                            && caller.can_grant_all(&group.permissions)
                    }),
                    None => {
                        tracing::warn!(
                            groups = ?grants.groups,
                            "Mapping rule names a group that does not exist or is not visible"
                        );
                        false
                    }
                }
            }
            Some(Err(err)) => {
                tracing::warn!(
                    ?err,
                    "Failed to build a mapping rule to check what it grants"
                );
                false
            }
            None => {
                tracing::warn!("No mapping engine is installed to determine what a rule grants");
                false
            }
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

    /// The permissions and groups that every matching mapper hands to the user.
    pub async fn get_mapped_fields(
        &self,
        caller: &Caller<T>,
        visible_groups: &[AccessGroup<T>],
        info: &UserInfo,
        user_id: TypedUuid<UserId>,
    ) -> ResourceResult<BTreeSet<TypedUuid<AccessGroupId>>, StoreError> {
        let mut mapped_groups = BTreeSet::new();

        // We only need to run mapping logic if there is mapping engine available to transform
        // mappers into mappings
        if let Some(engine) = &self.engine {
            // We optimistically load mappers here. We do not want to take a lock on the mappers and
            // instead handle mappers that become depleted before we can evaluate them at evaluation
            // time.
            for mapper in self.get_mappers(caller, false).await? {
                let is_preset = mapper.source == MapperSource::Preset;
                tracing::trace!(?mapper.name, is_preset, "Attempt to run mapper");

                // Try to transform this mapper into a mapping
                let mapping = engine.create_mapping(&mapper.rule);

                let mut groups = match mapping {
                    Ok(mapping) => {
                        if mapping.matches(info).await {
                            tracing::trace!(?mapper.name, "Applying mapping");
                            let grants = mapping.grants();
                            resolve_mapped_groups(&grants.groups, visible_groups)
                        } else {
                            BTreeSet::default()
                        }
                    }
                    Err(err) => {
                        // Errors here can be expected. They are reported, but not acted upon
                        tracing::info!(?err, "No mapping was found for mapper");
                        BTreeSet::default()
                    }
                };

                let apply = if !groups.is_empty() {
                    if is_preset {
                        // Preset mappers always apply - no activation gating
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
                    // Record the mapper event for audit purposes.
                    // TODO: This should hook into an audit log feature
                    if let Err(err) = self.record_mapper_event(&mapper, user_id).await {
                        tracing::warn!(
                            ?err,
                            mapper_name = ?mapper.name,
                            "Failed to record mapper event"
                        );
                    }

                    mapped_groups.append(&mut groups);
                }
            }
        };

        Ok(mapped_groups)
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
    ) -> Result<MapperEvent, StoreError> {
        let event = NewMapperEvent {
            id: TypedUuid::new_v4(),
            mapper_id: mapper.id,
            mapper_name: mapper.name.clone(),
            user_id,
            rule: mapper.rule.clone(),
            source: mapper.source,
        };

        MapperEventStore::record(&*self.storage, &event).await
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use newtype_uuid::TypedUuid;
    use serde_json::json;
    use std::{collections::BTreeSet, sync::Arc};
    use v_model::{
        AccessGroup, AccessGroupSource, Mapper, MapperEvent, MapperSource, NewMapper,
        permissions::{Caller, Permissions},
        storage::{MockMapperEventStore, MockMapperStore},
    };

    use super::{AddMapperError, MappingContext};
    use crate::{
        context::test_mocks::MockStorage,
        endpoints::login::{ExternalUserId, UserInfo},
        mapper::DefaultMappingEngine,
        permissions::VPermission,
        response::ResourceError,
    };

    fn group(name: &str) -> AccessGroup<VPermission> {
        AccessGroup {
            id: TypedUuid::new_v4(),
            name: name.to_string(),
            permissions: vec![VPermission::CreateGroup].into(),
            source: AccessGroupSource::Dynamic,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
            generation: 0,
        }
    }

    /// A mapping context using the default engine, whose store accepts new mappers
    fn mapping_context() -> MappingContext<VPermission> {
        let mut mapper_store = MockMapperStore::new();
        mapper_store.expect_upsert().returning(|mapper| {
            Ok(Mapper {
                id: mapper.id,
                name: mapper.name.clone(),
                rule: mapper.rule.clone(),
                activations: mapper.activations,
                max_activations: mapper.max_activations,
                source: MapperSource::Dynamic,
                depleted_at: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                deleted_at: None,
            })
        });

        let mut storage = MockStorage::new();
        storage.mapper_store = Some(Arc::new(mapper_store));

        let mut mapping = MappingContext::new(Arc::new(storage));
        mapping.set_engine(Some(Arc::new(DefaultMappingEngine)));
        mapping
    }

    fn mapper(groups: Vec<&str>) -> NewMapper {
        NewMapper {
            id: TypedUuid::new_v4(),
            name: "rule".to_string(),
            rule: json!({ "rule": "default", "groups": groups }),
            activations: None,
            max_activations: None,
        }
    }

    fn caller_with(permissions: Vec<VPermission>) -> Caller<VPermission> {
        Caller::from(Permissions::<VPermission>::from(permissions))
    }

    /// Mapping a user into a group is the same as adding them to it, so the creator needs the
    /// group's membership permission and must be able to grant the group's permissions
    #[tokio::test]
    async fn creating_a_mapper_requires_adding_to_its_groups() {
        let engineering = group("engineering");
        let visible = vec![engineering.clone()];
        let mapping = mapping_context();
        let rule = mapper(vec!["engineering"]);

        let no_membership = caller_with(vec![VPermission::CreateMapper, VPermission::CreateGroup]);
        let refused = mapping.add_mapper(&no_membership, &visible, &rule).await;
        assert!(matches!(
            refused,
            Err(AddMapperError::Resource(ResourceError::Restricted))
        ));

        let cannot_grant_group = caller_with(vec![
            VPermission::CreateMapper,
            VPermission::ManageGroupMembership(engineering.id),
        ]);
        let refused = mapping
            .add_mapper(&cannot_grant_group, &visible, &rule)
            .await;
        assert!(matches!(
            refused,
            Err(AddMapperError::Resource(ResourceError::Restricted))
        ));

        let can_add = caller_with(vec![
            VPermission::CreateMapper,
            VPermission::ManageGroupMembership(engineering.id),
            VPermission::CreateGroup,
        ]);
        assert!(mapping.add_mapper(&can_add, &visible, &rule).await.is_ok());
    }

    /// Every group a rule names must be one the caller can see. A name that resolves to nothing
    /// could later resolve to a group someone else creates, and a group the caller can not see
    /// is not theirs to hand out, so both are refused.
    #[tokio::test]
    async fn creating_a_mapper_refuses_groups_the_caller_can_not_see() {
        let mapping = mapping_context();
        let visible = vec![group("engineering")];
        let rule = mapper(vec!["engineering", "not-visible"]);

        let caller = caller_with(vec![
            VPermission::CreateMapper,
            VPermission::ManageGroupMembershipsAll,
            VPermission::CreateGroup,
        ]);
        let refused = mapping.add_mapper(&caller, &visible, &rule).await;
        assert!(matches!(
            refused,
            Err(AddMapperError::Resource(ResourceError::Restricted))
        ));
    }

    fn preset_mapper(name: &str, rule: serde_json::Value) -> Mapper {
        Mapper {
            id: TypedUuid::new_v4(),
            name: name.to_string(),
            rule,
            activations: None,
            max_activations: None,
            source: MapperSource::Preset,
            depleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        }
    }

    /// A login applies exactly the groups of each rule it matches, resolved against the groups
    /// the caller can see. A rule that does not match contributes nothing.
    #[tokio::test]
    async fn logins_apply_exactly_the_grants_of_matching_rules() {
        let engineering = group("engineering");
        let admins = group("admins");
        let visible = vec![engineering.clone(), admins];

        let mut mapper_store = MockMapperStore::new();
        mapper_store.expect_list().returning(|_, _| Ok(vec![]));
        let mut event_store = MockMapperEventStore::new();
        event_store.expect_record().returning(|event| {
            Ok(MapperEvent {
                id: event.id,
                mapper_id: event.mapper_id,
                mapper_name: event.mapper_name.clone(),
                user_id: event.user_id,
                rule: event.rule.clone(),
                source: event.source,
                created_at: Utc::now(),
            })
        });

        let mut storage = MockStorage::new();
        storage.mapper_store = Some(Arc::new(mapper_store));
        storage.mapper_event_store = Some(Arc::new(event_store));

        let mut mapping = MappingContext::new(Arc::new(storage));
        mapping.set_engine(Some(Arc::new(DefaultMappingEngine)));
        mapping.set_preset_mappers(vec![
            preset_mapper(
                "matching",
                json!({ "rule": "default", "groups": ["engineering"] }),
            ),
            preset_mapper(
                "not-matching",
                json!({
                    "rule": "email_address",
                    "email": "someone-else@example.com",
                    "groups": ["admins"],
                }),
            ),
        ]);

        let registration = caller_with(vec![VPermission::GetMappersAll]);
        let user = UserInfo {
            external_id: ExternalUserId::MagicLink("user@example.com".to_string()),
            verified_emails: vec!["user@example.com".to_string()],
            display_name: None,
            idp_token: None,
        };

        let groups = mapping
            .get_mapped_fields(&registration, &visible, &user, TypedUuid::new_v4())
            .await
            .unwrap();

        assert_eq!(BTreeSet::from([engineering.id]), groups);
    }

    /// New mappers must use the current shape, even when the caller could grant everything the
    /// original shape asks for. The caller is shown to be allowed to create the same rule in the
    /// current shape, so the refusals can only come from the shape of the rule.
    #[tokio::test]
    async fn creating_a_mapper_refuses_the_original_shape() {
        let engineering = group("engineering");
        let visible = vec![engineering.clone()];
        let mapping = mapping_context();
        let caller = caller_with(vec![
            VPermission::CreateMapper,
            VPermission::ManageGroupMembershipsAll,
            VPermission::CreateGroup,
        ]);

        let current = NewMapper {
            rule: json!({ "rule": "default", "groups": ["engineering"] }),
            ..mapper(vec![])
        };
        assert!(
            mapping
                .add_mapper(&caller, &visible, &current)
                .await
                .is_ok(),
            "the caller must be able to create the rule in the current shape"
        );

        for rule in [
            json!({
                "rule": "default",
                "permissions": serde_json::to_value(Permissions::<VPermission>::from(vec![VPermission::CreateGroup])).unwrap(),
                "groups": ["engineering"],
            }),
            json!({ "rule": "default" }),
        ] {
            let new_mapper = NewMapper {
                rule: rule.clone(),
                ..mapper(vec![])
            };
            let refused = mapping.add_mapper(&caller, &visible, &new_mapper).await;
            assert!(
                matches!(refused, Err(AddMapperError::InvalidRule)),
                "{rule}"
            );
        }
    }
}
