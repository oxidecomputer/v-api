// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use newtype_uuid::TypedUuid;
use std::sync::Arc;
use v_model::{
    AccessGroup, AccessGroupId, NewAccessGroup,
    permissions::{Caller, PermissionStorage, Permissions},
    storage::{AccessGroupFilter, AccessGroupStore, ListPagination, StoreError},
};

use crate::{
    VApiStorage,
    permissions::{VAppPermission, VPermission},
    response::{OptionalResource, ResourceResult, resource_conflict, resource_restricted},
};

/// A change to a stored group. Each kind of change carries what is needed to check the caller's
/// authority to make it.
enum GroupChange<'a, T> {
    AddPermission(T),
    RemovePermission(&'a T),
}

#[derive(Clone)]
pub struct GroupContext<T> {
    storage: Arc<dyn VApiStorage<T>>,
    preset_groups: Arc<Vec<AccessGroup<T>>>,
}

impl<T> GroupContext<T>
where
    T: VAppPermission,
{
    pub fn new(storage: Arc<dyn VApiStorage<T>>) -> Self {
        Self {
            storage,
            preset_groups: Arc::new(Vec::new()),
        }
    }

    pub fn set_storage(&mut self, storage: Arc<dyn VApiStorage<T>>) {
        self.storage = storage;
    }

    pub fn set_preset_groups(&mut self, groups: Vec<AccessGroup<T>>) {
        self.preset_groups = Arc::new(groups);
    }

    pub fn preset_groups(&self) -> &[AccessGroup<T>] {
        &self.preset_groups
    }

    pub fn is_preset(&self, id: &TypedUuid<AccessGroupId>) -> bool {
        self.preset_groups.iter().any(|group| &group.id == id)
    }

    fn preset_matches_filter(group: &AccessGroup<T>, filter: &AccessGroupFilter) -> bool {
        filter
            .id
            .as_ref()
            .map(|ids| ids.contains(&group.id))
            .unwrap_or(true)
            && filter
                .name
                .as_ref()
                .map(|names| names.contains(&group.name))
                .unwrap_or(true)
    }

    pub async fn get_group(
        &self,
        caller: &Caller<T>,
        group_id: &TypedUuid<AccessGroupId>,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        if caller.can(&VPermission::GetGroup(*group_id).into()) {
            if let Some(group) = self
                .preset_groups
                .iter()
                .find(|group| &group.id == group_id)
            {
                return Ok(group.clone());
            }

            AccessGroupStore::get(&*self.storage, group_id, false)
                .await
                .optional()
        } else {
            resource_restricted()
        }
    }

    pub async fn list_groups(
        &self,
        caller: &Caller<T>,
        filter: AccessGroupFilter,
    ) -> ResourceResult<Vec<AccessGroup<T>>, StoreError> {
        let presets = self
            .preset_groups
            .iter()
            .filter(|group| Self::preset_matches_filter(group, &filter))
            .cloned()
            .collect::<Vec<_>>();

        let mut groups =
            AccessGroupStore::list(&*self.storage, filter, &ListPagination::unlimited()).await?;
        groups.extend(presets);
        groups.retain(|group| caller.can(&VPermission::GetGroup(group.id).into()));

        Ok(groups)
    }

    pub async fn create_group(
        &self,
        caller: &Caller<T>,
        group: NewAccessGroup<T>,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        if self.is_preset(&group.id)
            || self
                .preset_groups
                .iter()
                .any(|preset| preset.name == group.name)
        {
            return resource_conflict();
        }

        if caller.can(&VPermission::CreateGroup.into()) && caller.can_grant_all(&group.permissions)
        {
            Ok(AccessGroupStore::upsert(&*self.storage, &group).await?)
        } else {
            resource_restricted()
        }
    }

    /// Adds a permission to a group.
    pub async fn add_permission_to_group(
        &self,
        caller: &Caller<T>,
        group_id: &TypedUuid<AccessGroupId>,
        permission: T,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        self.modify_group(caller, group_id, GroupChange::AddPermission(permission))
            .await
    }

    /// Removes a permission from a group.
    pub async fn remove_permission_from_group(
        &self,
        caller: &Caller<T>,
        group_id: &TypedUuid<AccessGroupId>,
        permission: &T,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        self.modify_group(caller, group_id, GroupChange::RemovePermission(permission))
            .await
    }

    /// Applies a change to a stored group.
    async fn modify_group(
        &self,
        caller: &Caller<T>,
        group_id: &TypedUuid<AccessGroupId>,
        change: GroupChange<'_, T>,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        if self.is_preset(group_id) {
            resource_conflict()
        } else if Self::can_make_change(caller, group_id, &change) {
            let current = self.get_group(caller, group_id).await?;

            let mut update = NewAccessGroup {
                id: current.id,
                name: current.name,
                permissions: current.permissions.expand_values(),
            };
            Self::apply_change(&mut update, change);
            update.permissions = <T as PermissionStorage>::contract(&update.permissions);

            match AccessGroupStore::update(&*self.storage, &update, current.generation).await? {
                Some(updated) => Ok(updated),
                None => {
                    tracing::info!(
                        ?group_id,
                        generation = current.generation,
                        "Group was written by someone else since it was read"
                    );
                    resource_conflict()
                }
            }
        } else {
            resource_restricted()
        }
    }

    /// Returns true if the caller has the authority to make the change to the group
    fn can_make_change(
        caller: &Caller<T>,
        group_id: &TypedUuid<AccessGroupId>,
        change: &GroupChange<T>,
    ) -> bool {
        let permission = match change {
            GroupChange::AddPermission(permission) => permission,
            GroupChange::RemovePermission(permission) => *permission,
        };

        caller.can(&VPermission::ManageGroup(*group_id).into()) && caller.can_grant(permission)
    }

    fn apply_change(update: &mut NewAccessGroup<T>, change: GroupChange<T>) {
        match change {
            GroupChange::AddPermission(permission) => {
                for value in Permissions::from_iter([permission])
                    .expand_values()
                    .into_iter()
                {
                    update.permissions.insert(value);
                }
            }
            GroupChange::RemovePermission(permission) => {
                update.permissions = update.permissions.without(permission);
            }
        }
    }

    pub async fn delete_group(
        &self,
        caller: &Caller<T>,
        group_id: &TypedUuid<AccessGroupId>,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        if self.is_preset(group_id) {
            return resource_conflict();
        }

        if caller.can(&VPermission::ManageGroup(*group_id).into()) {
            AccessGroupStore::delete(&*self.storage, group_id)
                .await
                .optional()
        } else {
            resource_restricted()
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use newtype_uuid::{GenericUuid, TypedUuid};
    use std::{
        collections::BTreeSet,
        sync::{Arc, Mutex},
    };
    use uuid::Uuid;
    use v_model::{
        AccessGroup, AccessGroupSource, NewAccessGroup,
        permissions::{Caller, Permissions, Principal},
        storage::{AccessGroupFilter, MockAccessGroupStore},
    };

    use crate::{
        context::test_mocks::MockStorage, permissions::VPermission, response::ResourceError,
    };

    use super::GroupContext;

    fn preset_group(name: &str) -> AccessGroup<VPermission> {
        AccessGroup {
            id: TypedUuid::from_untyped_uuid(Uuid::new_v5(&Uuid::NAMESPACE_URL, name.as_bytes())),
            name: name.to_string(),
            permissions: vec![VPermission::CreateGroup].into(),
            source: AccessGroupSource::Preset,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
            generation: 0,
        }
    }

    fn dynamic_group(name: &str) -> AccessGroup<VPermission> {
        AccessGroup {
            id: TypedUuid::new_v4(),
            name: name.to_string(),
            permissions: Permissions::new(),
            source: AccessGroupSource::Dynamic,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
            generation: 0,
        }
    }

    /// A context whose backing store holds the supplied groups, and that has been configured
    /// with a single preset group named "admins".
    fn ctx_with_preset(stored: Vec<AccessGroup<VPermission>>) -> GroupContext<VPermission> {
        let mut group_store = MockAccessGroupStore::new();
        group_store
            .expect_list()
            .returning(move |_, _| Ok(stored.clone()));

        let mut storage = MockStorage::new();
        storage.access_group_store = Some(Arc::new(group_store));

        let mut ctx = GroupContext::new(Arc::new(storage));
        ctx.set_preset_groups(vec![preset_group("admins")]);
        ctx
    }

    fn admin_caller() -> Caller<VPermission> {
        Caller {
            principal: Principal::User(TypedUuid::new_v4()),
            permissions: vec![
                VPermission::GetGroupsAll,
                VPermission::CreateGroup,
                VPermission::ManageGroupsAll,
            ]
            .into(),
            extensions: Default::default(),
        }
    }

    #[tokio::test]
    async fn lists_preset_groups_alongside_stored_groups() {
        let ctx = ctx_with_preset(vec![dynamic_group("customers")]);
        let groups = ctx
            .list_groups(&admin_caller(), AccessGroupFilter::default())
            .await
            .unwrap();

        let names = groups
            .iter()
            .map(|group| group.name.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(names, BTreeSet::from(["customers", "admins"]));
    }

    /// Callers use id filtered lists to resolve the groups a user has been mapped into. A
    /// preset group that does not match the filter must not be returned, otherwise every
    /// preset group would be granted to every user.
    #[tokio::test]
    async fn filters_preset_groups_by_id() {
        let ctx = ctx_with_preset(vec![]);
        let groups = ctx
            .list_groups(
                &admin_caller(),
                AccessGroupFilter {
                    id: Some(vec![TypedUuid::new_v4()]),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert!(
            groups.is_empty(),
            "Preset group was returned for a filter that does not include it: {:?}",
            groups.iter().map(|group| &group.name).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn returns_preset_group_by_id() {
        let ctx = ctx_with_preset(vec![]);
        let group = ctx
            .get_group(&admin_caller(), &preset_group("admins").id)
            .await
            .unwrap();

        assert_eq!(group.name, "admins");
        assert_eq!(group.source, AccessGroupSource::Preset);
    }

    #[tokio::test]
    async fn preset_groups_can_not_be_updated_or_deleted() {
        let ctx = ctx_with_preset(vec![]);
        let preset = preset_group("admins");

        let add = ctx
            .add_permission_to_group(&admin_caller(), &preset.id, VPermission::CreateGroup)
            .await;
        assert!(matches!(add, Err(ResourceError::Conflict)));

        let remove = ctx
            .remove_permission_from_group(&admin_caller(), &preset.id, &VPermission::CreateGroup)
            .await;
        assert!(matches!(remove, Err(ResourceError::Conflict)));

        let delete = ctx.delete_group(&admin_caller(), &preset.id).await;
        assert!(matches!(delete, Err(ResourceError::Conflict)));
    }

    /// Mappers resolve group names, so a dynamic group must not be able to shadow the name
    /// of a preset group.
    #[tokio::test]
    async fn dynamic_group_can_not_reuse_preset_name() {
        let ctx = ctx_with_preset(vec![]);
        let create = ctx
            .create_group(
                &admin_caller(),
                NewAccessGroup {
                    id: TypedUuid::new_v4(),
                    name: "admins".to_string(),
                    permissions: Permissions::new(),
                },
            )
            .await;

        assert!(matches!(create, Err(ResourceError::Conflict)));
    }

    /// The permissions written by each successful group change
    type GroupWrites = Arc<Mutex<Vec<Permissions<VPermission>>>>;

    /// A context holding one stored group with the supplied permissions. Every write succeeds
    /// and the written permissions are recorded.
    fn ctx_with_group(
        permissions: Permissions<VPermission>,
    ) -> (
        GroupContext<VPermission>,
        AccessGroup<VPermission>,
        GroupWrites,
    ) {
        let group = AccessGroup {
            permissions,
            ..dynamic_group("engineering")
        };
        let writes: GroupWrites = Arc::new(Mutex::new(vec![]));

        let mut group_store = MockAccessGroupStore::new();
        let stored = group.clone();
        group_store
            .expect_get()
            .returning(move |_, _| Ok(Some(stored.clone())));
        let recorder = writes.clone();
        let template = group.clone();
        group_store.expect_update().returning(move |update, _| {
            recorder.lock().unwrap().push(update.permissions.clone());
            Ok(Some(AccessGroup {
                name: update.name.clone(),
                permissions: update.permissions.clone(),
                ..template.clone()
            }))
        });

        let mut storage = MockStorage::new();
        storage.access_group_store = Some(Arc::new(group_store));

        (GroupContext::new(Arc::new(storage)), group, writes)
    }

    fn caller_with(permissions: Vec<VPermission>) -> Caller<VPermission> {
        Caller {
            principal: Principal::User(TypedUuid::new_v4()),
            permissions: permissions.into(),
            extensions: Default::default(),
        }
    }

    /// Every member receives a group's permissions, so adding one requires managing the group
    /// and being able to grant the permission
    #[tokio::test]
    async fn adding_a_group_permission_requires_grant() {
        let (ctx, group, writes) = ctx_with_group(Permissions::new());

        let cannot_grant = caller_with(vec![VPermission::ManageGroup(group.id)]);
        let refused = ctx
            .add_permission_to_group(&cannot_grant, &group.id, VPermission::CreateMapper)
            .await;
        assert!(matches!(refused, Err(ResourceError::Restricted)));
        assert!(writes.lock().unwrap().is_empty());

        let can_grant = caller_with(vec![
            VPermission::GetGroup(group.id),
            VPermission::ManageGroup(group.id),
            VPermission::CreateMapper,
        ]);
        let updated = ctx
            .add_permission_to_group(&can_grant, &group.id, VPermission::CreateMapper)
            .await
            .unwrap();
        assert!(updated.permissions.can(&VPermission::CreateMapper));
    }

    /// Removing a group permission requires being able to grant it, so the group's members never
    /// lose permissions outside of the caller's authority
    #[tokio::test]
    async fn removing_a_group_permission_requires_grant() {
        let (ctx, group, writes) =
            ctx_with_group(vec![VPermission::CreateMapper, VPermission::CreateGroup].into());

        let cannot_grant = caller_with(vec![VPermission::ManageGroup(group.id)]);
        let refused = ctx
            .remove_permission_from_group(&cannot_grant, &group.id, &VPermission::CreateMapper)
            .await;
        assert!(matches!(refused, Err(ResourceError::Restricted)));
        assert!(writes.lock().unwrap().is_empty());

        let can_grant = caller_with(vec![
            VPermission::GetGroup(group.id),
            VPermission::ManageGroup(group.id),
            VPermission::CreateMapper,
        ]);
        let updated = ctx
            .remove_permission_from_group(&can_grant, &group.id, &VPermission::CreateMapper)
            .await
            .unwrap();
        assert!(!updated.permissions.can(&VPermission::CreateMapper));
        assert!(updated.permissions.can(&VPermission::CreateGroup));
    }

    /// A write against a generation that has moved on is refused as a conflict after a single
    /// attempt, and is never retried
    #[tokio::test]
    async fn a_stale_group_write_is_a_conflict() {
        let group = dynamic_group("engineering");
        let stored = group.clone();

        let mut group_store = MockAccessGroupStore::new();
        group_store
            .expect_get()
            .times(1)
            .returning(move |_, _| Ok(Some(stored.clone())));
        group_store
            .expect_update()
            .times(1)
            .returning(|_, _| Ok(None));

        let mut storage = MockStorage::new();
        storage.access_group_store = Some(Arc::new(group_store));
        let ctx = GroupContext::new(Arc::new(storage));

        let manager = caller_with(vec![
            VPermission::GetGroup(group.id),
            VPermission::ManageGroup(group.id),
            VPermission::CreateMapper,
        ]);
        let conflict = ctx
            .add_permission_to_group(&manager, &group.id, VPermission::CreateMapper)
            .await;
        assert!(matches!(conflict, Err(ResourceError::Conflict)));
    }
}
