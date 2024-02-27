// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeSet;

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use v_api_permissions::{Permission, Permissions};
use v_model::storage::StoreError;

use crate::{
    context::VContext,
    endpoints::login::UserInfo,
    permissions::{AsScope, PermissionStorage, VPermission},
    util::response::ResourceResult,
};

use super::MapperRule;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct EmailDomainMapper<T> {
    domain: String,
    permissions: Option<Permissions<T>>,
    #[serde(default)]
    groups: Vec<String>,
}

#[async_trait]
impl<T> MapperRule<T> for EmailDomainMapper<T>
where
    T: Permission + From<VPermission> + AsScope,
    Permissions<T>: PermissionStorage,
{
    async fn permissions_for(
        &self,
        _ctx: &VContext<T>,
        _user: &UserInfo,
    ) -> Result<Permissions<T>, StoreError> {
        Ok(Permissions::new())
    }

    async fn groups_for(
        &self,
        ctx: &VContext<T>,
        user: &UserInfo,
    ) -> ResourceResult<BTreeSet<Uuid>, StoreError> {
        let has_email_in_domain = user
            .verified_emails
            .iter()
            .fold(false, |found, email| found || email.ends_with(&self.domain));

        if has_email_in_domain {
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
        } else {
            Ok(BTreeSet::new())
        }
    }
}
