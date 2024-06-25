use newtype_uuid::TypedUuid;
use std::sync::Arc;
use v_model::{
    permissions::Caller,
    storage::{AccessGroupFilter, AccessGroupStore, ListPagination, StoreError},
    AccessGroup, AccessGroupId, NewAccessGroup,
};

use crate::{
    permissions::{VAppPermission, VPermission},
    response::{resource_restricted, ResourceResult, ToResourceResult, ToResourceResultOpt},
    VApiStorage,
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

    pub async fn get_groups(
        &self,
        caller: &Caller<T>,
    ) -> ResourceResult<Vec<AccessGroup<T>>, StoreError> {
        let mut groups = AccessGroupStore::list(
            &*self.storage,
            AccessGroupFilter::default(),
            &ListPagination::unlimited(),
        )
        .await
        .to_resource_result()?;
        groups.retain(|group| {
            caller.any(&[
                &VPermission::GetGroupsAll.into(),
                &VPermission::GetGroup(group.id).into(),
            ])
        });

        Ok(groups)
    }

    pub async fn create_group(
        &self,
        caller: &Caller<T>,
        group: NewAccessGroup<T>,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        if caller.can(&VPermission::CreateGroup.into()) {
            AccessGroupStore::upsert(&*self.storage, &group)
                .await
                .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn update_group(
        &self,
        caller: &Caller<T>,
        group: NewAccessGroup<T>,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        if caller.any(&[
            &VPermission::ManageGroup(group.id).into(),
            &VPermission::ManageGroupsAll.into(),
        ]) {
            AccessGroupStore::upsert(&*self.storage, &group)
                .await
                .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn delete_group(
        &self,
        caller: &Caller<T>,
        group_id: &TypedUuid<AccessGroupId>,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        if caller.any(&[
            &VPermission::ManageGroup(*group_id).into(),
            &VPermission::ManageGroupsAll.into(),
        ]) {
            AccessGroupStore::delete(&*self.storage, group_id)
                .await
                .opt_to_resource_result()
        } else {
            resource_restricted()
        }
    }
}
