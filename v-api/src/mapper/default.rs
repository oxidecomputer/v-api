// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use v_model::{
    permissions::Permissions,
    storage::StoreError,
    AccessGroupId,
};

use crate::{
    context::VContext,
    endpoints::login::UserInfo,
    permissions::VAppPermission,
    util::response::ResourceResult,
};

use super::MapperRule;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DefaultMapper<T> {
    permissions: Option<Permissions<T>>,
    #[serde(default)]
    groups: Vec<String>,
}

#[async_trait]
impl<T> MapperRule<T> for DefaultMapper<T>
where
    T: VAppPermission,
{
    async fn permissions_for(
        &self,
        _ctx: &VContext<T>,
        _user: &UserInfo,
    ) -> Result<Permissions<T>, StoreError> {
        Ok(self.permissions.clone().unwrap_or_default())
    }

    async fn groups_for(
        &self,
        ctx: &VContext<T>,
        _user: &UserInfo,
    ) -> ResourceResult<BTreeSet<TypedUuid<AccessGroupId>>, StoreError> {
        let groups = ctx
            .get_groups(&ctx.builtin_registration_user())
            .await?
            .into_iter()
            .filter_map(|group| {
                if self.groups.contains(&group.name) {
                    Some(group.id)
                } else {
                    None
                }
            })
            .collect();
        Ok(groups)
    }
}
