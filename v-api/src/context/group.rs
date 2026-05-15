// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use newtype_uuid::TypedUuid;
use std::sync::Arc;
use v_model::{
    AccessGroup, AccessGroupId, NewAccessGroup,
    permissions::Caller,
    storage::{AccessGroupFilter, AccessGroupStore, ListPagination, StoreError},
};

use crate::{
    VApiStorage,
    permissions::{VAppPermission, VPermission},
    response::{OptionalResource, ResourceResult, resource_restricted},
};

#[derive(Clone)]
pub struct GroupContext<T> {
    storage: Arc<dyn VApiStorage<T>>,
}

impl<T> GroupContext<T>
where
    T: VAppPermission,
{
    pub fn new(storage: Arc<dyn VApiStorage<T>>) -> Self {
        Self { storage }
    }

    pub fn set_storage(&mut self, storage: Arc<dyn VApiStorage<T>>) {
        self.storage = storage;
    }

    pub async fn get_group(
        &self,
        caller: &Caller<T>,
        group_id: &TypedUuid<AccessGroupId>,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        if caller.can(&VPermission::GetGroup(*group_id).into()) {
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
        let mut groups =
            AccessGroupStore::list(&*self.storage, filter, &ListPagination::unlimited()).await?;
        groups.retain(|group| caller.can(&VPermission::GetGroup(group.id).into()));

        Ok(groups)
    }

    pub async fn create_group(
        &self,
        caller: &Caller<T>,
        group: NewAccessGroup<T>,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        if caller.can(&VPermission::CreateGroup.into()) && caller.can_grant_all(&group.permissions)
        {
            Ok(AccessGroupStore::upsert(&*self.storage, &group).await?)
        } else {
            resource_restricted()
        }
    }

    pub async fn update_group(
        &self,
        caller: &Caller<T>,
        group: NewAccessGroup<T>,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        if caller.can(&VPermission::ManageGroup(group.id).into())
            && caller.can_grant_all(&group.permissions)
        {
            Ok(AccessGroupStore::upsert(&*self.storage, &group).await?)
        } else {
            resource_restricted()
        }
    }

    pub async fn delete_group(
        &self,
        caller: &Caller<T>,
        group_id: &TypedUuid<AccessGroupId>,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        if caller.can(&VPermission::ManageGroup(*group_id).into()) {
            AccessGroupStore::delete(&*self.storage, group_id)
                .await
                .optional()
        } else {
            resource_restricted()
        }
    }
}
