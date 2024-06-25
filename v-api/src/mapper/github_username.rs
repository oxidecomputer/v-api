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

pub struct GitHubUsernameMapper<T> {
    caller: Caller<T>,
    group: GroupContext<T>,
    data: GitHubUsernameMapperData<T>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GitHubUsernameMapperData<T> {
    github_username: String,
    permissions: Option<Permissions<T>>,
    #[serde(default)]
    groups: Vec<String>,
}

impl<T> GitHubUsernameMapper<T> {
    pub fn new(
        caller: Caller<T>,
        group: GroupContext<T>,
        data: GitHubUsernameMapperData<T>,
    ) -> Self {
        Self {
            caller,
            group,
            data,
        }
    }
}

#[async_trait]
impl<T> MapperRule<T> for GitHubUsernameMapper<T>
where
    T: VAppPermission,
{
    async fn permissions_for(&self, user: &UserInfo) -> Result<Permissions<T>, StoreError> {
        if user
            .github_username
            .as_ref()
            .map(|u| u == &self.data.github_username)
            .unwrap_or(false)
        {
            Ok(self.data.permissions.clone().unwrap_or_default())
        } else {
            Ok(Permissions::new())
        }
    }

    async fn groups_for(
        &self,
        user: &UserInfo,
    ) -> ResourceResult<BTreeSet<TypedUuid<AccessGroupId>>, StoreError> {
        if user
            .github_username
            .as_ref()
            .map(|u| u == &self.data.github_username)
            .unwrap_or(false)
        {
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
        } else {
            Ok(BTreeSet::new())
        }
    }
}
