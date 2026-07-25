// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tracing::instrument;
use v_model::{
    AccessGroupId,
    permissions::{Caller, Permissions},
    storage::{AccessGroupFilter, StoreError},
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
        let has_email_in_domain = user.verified_emails.iter().any(|email| {
            let mut parts = email.split('@');
            parts
                .nth(1)
                .map(|domain| domain == self.data.domain)
                .unwrap_or(false)
        });

        if has_email_in_domain {
            let known_groups = self
                .group
                .list_groups(&self.caller, AccessGroupFilter::default())
                .await?;

            Ok(super::resolve_mapped_groups(
                &self.data.groups,
                &known_groups,
            ))
        } else {
            Ok(BTreeSet::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use chrono::Utc;
    use newtype_uuid::TypedUuid;
    use std::collections::HashMap;
    use v_model::{
        AccessGroup,
        permissions::{Caller, Permissions},
        storage::MockAccessGroupStore,
    };

    use crate::{
        context::{group::GroupContext, test_mocks::MockStorage},
        endpoints::login::{ExternalUserId, UserInfo},
        mapper::MapperRule,
        permissions::VPermission,
    };

    use super::{EmailDomainMapper, EmailDomainMapperData};

    /// Build a `GroupContext` whose backing store returns a single group with
    /// the provided name/id, mimicking a deployment that has an "employees"
    /// group reserved for members of a configured email domain.
    fn group_context_with_group(
        group_id: TypedUuid<v_model::AccessGroupId>,
        group_name: &str,
    ) -> GroupContext<VPermission> {
        let group = AccessGroup {
            id: group_id,
            name: group_name.to_string(),
            permissions: Permissions::<VPermission>::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };

        let mut group_store = MockAccessGroupStore::new();
        group_store
            .expect_list()
            .returning(move |_, _| Ok(vec![group.clone()]));

        let mut storage = MockStorage::new();
        storage.access_group_store = Some(Arc::new(group_store));

        GroupContext::new(Arc::new(storage))
    }

    /// Mirror the builtin registration caller, which the mapping engine uses
    /// when running mappers during `register_api_user`. It holds broad group
    /// permissions, so every matched group is unconditionally granted.
    fn registration_caller() -> Caller<VPermission> {
        Caller {
            id: "00000000-0000-4000-8000-000000000001".parse().unwrap(),
            permissions: vec![
                VPermission::GetGroupsAll,
                VPermission::ManageGroupMembershipsAll,
            ]
            .into(),
            extensions: HashMap::default(),
        }
    }

    fn user_with_email(email: &str) -> UserInfo {
        UserInfo {
            external_id: ExternalUserId::MagicLink(email.to_string()),
            verified_emails: vec![email.to_string()],
            display_name: None,
            idp_token: None,
        }
    }

    /// Sanity check: a genuine member of the configured domain is mapped into
    /// the reserved group. This is the intended behavior.
    #[tokio::test]
    async fn maps_legitimate_domain_member_into_group() {
        let group_id = TypedUuid::new_v4();
        let mapper = EmailDomainMapper::new(
            registration_caller(),
            group_context_with_group(group_id, "employees"),
            EmailDomainMapperData::<VPermission> {
                domain: "example.com".to_string(),
                permissions: None,
                groups: vec!["employees".to_string()],
            },
        );

        let groups = mapper
            .groups_for(&user_with_email("alice@example.com"))
            .await
            .unwrap();

        assert_eq!(groups, BTreeSet::from([group_id]));
    }

    /// Exploit: an attacker who owns a lookalike domain whose name merely
    /// *ends with* the configured domain (`evilexample.com` vs `example.com`)
    /// is granted the reserved group. The `ends_with` check on
    /// `email.ends_with(&self.data.domain)` has no `@`/`.` boundary, so
    /// `a@evilexample.com`.ends_with(`example.com`) is true.
    #[tokio::test]
    async fn lookalike_domain_must_not_be_granted_reserved_group() {
        let group_id = TypedUuid::new_v4();
        let mapper = EmailDomainMapper::new(
            registration_caller(),
            group_context_with_group(group_id, "employees"),
            EmailDomainMapperData::<VPermission> {
                domain: "example.com".to_string(),
                permissions: None,
                groups: vec!["employees".to_string()],
            },
        );

        // Attacker-controlled address at a domain the attacker registered.
        let attacker = user_with_email("a@evilexample.com");
        let groups = mapper.groups_for(&attacker).await.unwrap();

        assert!(
            groups.is_empty(),
            "authorization bypass: an attacker owning the lookalike domain \
             'evilexample.com' was granted the reserved groups {:?} intended \
             only for 'example.com' members",
            groups,
        );
    }

    /// A related boundary case: a bare-suffix match without any `@` separator
    /// (`notexample.com`) must also be rejected.
    #[tokio::test]
    async fn suffix_only_domain_must_not_be_granted_reserved_group() {
        let group_id = TypedUuid::new_v4();
        let mapper = EmailDomainMapper::new(
            registration_caller(),
            group_context_with_group(group_id, "employees"),
            EmailDomainMapperData::<VPermission> {
                domain: "example.com".to_string(),
                permissions: None,
                groups: vec!["employees".to_string()],
            },
        );

        let attacker = user_with_email("user@notexample.com");
        let groups = mapper.groups_for(&attacker).await.unwrap();

        assert!(
            groups.is_empty(),
            "authorization bypass: 'notexample.com' was treated as a member of \
             'example.com' and granted {:?}",
            groups,
        );
    }
}
