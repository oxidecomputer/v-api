// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::instrument;
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

pub struct EmailDomainMapper<T> {
    caller: Caller<T>,
    group: GroupContext<T>,
    data: EmailDomainMapperData<T>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct EmailDomainMapperData<T> {
    domain: String,
    permissions: Option<Permissions<T>>,
    #[serde(default)]
    groups: Vec<String>,
}

impl<T> EmailDomainMapper<T> {
    pub fn new(caller: Caller<T>, group: GroupContext<T>, data: EmailDomainMapperData<T>) -> Self {
        Self {
            caller,
            group,
            data,
        }
    }
}

#[async_trait]
impl<T> MapperRule<T> for EmailDomainMapper<T>
where
    T: VAppPermission,
{
    #[instrument(skip(self, _user), field(data = ?self.data))]
    async fn permissions_for(&self, _user: &UserInfo) -> Result<Permissions<T>, StoreError> {
        Ok(Permissions::new())
    }

    #[instrument(skip(self, user), field(data = ?self.data))]
    async fn groups_for(
        &self,
        user: &UserInfo,
    ) -> ResourceResult<BTreeSet<TypedUuid<AccessGroupId>>, StoreError> {
        tracing::trace!("Running email domain mapper");
        let has_email_in_domain = user.verified_emails.iter().fold(false, |found, email| {
            found || email.ends_with(&self.data.domain)
        });

        if has_email_in_domain {
            let groups = self
                .group
                .get_groups(&self.caller)
                .await?
                .into_iter()
                .filter_map(|group| {
                    tracing::trace!(?group, "Processing group for email domain mapper");
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
