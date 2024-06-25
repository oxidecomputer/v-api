// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use v_model::{
    permissions::{Caller, Permissions},
    storage::StoreError,
    AccessGroupId,
};

use crate::{
    context::group::GroupContext, endpoints::login::UserInfo, permissions::VAppPermission,
    util::response::ResourceResult,
};

use super::MapperRule;

pub struct DefaultMapper<T> {
    caller: Caller<T>,
    group: GroupContext<T>,
    data: DefaultMapperData<T>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DefaultMapperData<T> {
    permissions: Option<Permissions<T>>,
    #[serde(default)]
    groups: Vec<String>,
}

impl<T> DefaultMapper<T> {
    pub fn new(caller: Caller<T>, group: GroupContext<T>, data: DefaultMapperData<T>) -> Self {
        Self {
            caller,
            group,
            data,
        }
    }
}

#[async_trait]
impl<T> MapperRule<T> for DefaultMapper<T>
where
    T: VAppPermission,
{
    async fn permissions_for(&self, _user: &UserInfo) -> Result<Permissions<T>, StoreError> {
        Ok(self.data.permissions.clone().unwrap_or_default())
    }

    async fn groups_for(
        &self,
        _user: &UserInfo,
    ) -> ResourceResult<BTreeSet<TypedUuid<AccessGroupId>>, StoreError> {
        let groups = self
            .group
            .get_groups(&self.caller)
            .await?
            .into_iter()
            .filter_map(|group| {
                if self.data.groups.contains(&group.name) {
                    Some(group.id)
                } else {
                    None
                }
            })
            .collect();

        Ok(groups)
    }
}
