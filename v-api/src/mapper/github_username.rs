// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use v_model::{
    AccessGroupId,
    permissions::{Caller, Permissions},
    storage::{AccessGroupFilter, StoreError},
};

use crate::{
    context::group::GroupContext,
    endpoints::login::{ExternalUserId, UserInfo},
    permissions::VAppPermission,
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
        if matches!(user.external_id, ExternalUserId::GitHub(_)) {
            if user
                .display_name
                .as_ref()
                .map(|u| u == &self.data.github_username)
                .unwrap_or(false)
            {
                Ok(self.data.permissions.clone().unwrap_or_default())
            } else {
                Ok(Permissions::new())
            }
        } else {
            Ok(Permissions::new())
        }
    }

    async fn groups_for(
        &self,
        user: &UserInfo,
    ) -> ResourceResult<BTreeSet<TypedUuid<AccessGroupId>>, StoreError> {
        if matches!(user.external_id, ExternalUserId::GitHub(_)) {
            if user
                .display_name
                .as_ref()
                .map(|u| u == &self.data.github_username)
                .unwrap_or(false)
            {
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
        } else {
            Ok(BTreeSet::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, collections::HashMap, sync::Arc};

    use chrono::Utc;
    use newtype_uuid::TypedUuid;
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

    use super::{GitHubUsernameMapper, GitHubUsernameMapperData};

    /// Build a `GroupContext` whose backing store returns a single group with
    /// the provided name/id, mimicking a deployment that has a "contributors"
    /// group reserved for a trusted GitHub contributor.
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
    /// when running mappers during `register_api_user`. It can grant anything,
    /// so every matched group is unconditionally granted.
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

    /// A mapper configured to trust the GitHub username "trusted-dev", granting
    /// the `GetMappersAll` permission and membership in the "contributors"
    /// group.
    fn trusted_dev_mapper(
        group_id: TypedUuid<v_model::AccessGroupId>,
    ) -> GitHubUsernameMapper<VPermission> {
        GitHubUsernameMapper::new(
            registration_caller(),
            group_context_with_group(group_id, "contributors"),
            GitHubUsernameMapperData::<VPermission> {
                github_username: "trusted-dev".to_string(),
                permissions: Some(vec![VPermission::GetMappersAll].into()),
                groups: vec!["contributors".to_string()],
            },
        )
    }

    /// Sanity check: a genuine GitHub login whose login/display name is
    /// "trusted-dev" receives the mapped permissions and groups. This is the
    /// intended behavior.
    #[tokio::test]
    async fn maps_genuine_github_user() {
        let group_id = TypedUuid::new_v4();
        let mapper = trusted_dev_mapper(group_id);

        let github_user = UserInfo {
            external_id: ExternalUserId::GitHub("trusted-dev".to_string()),
            verified_emails: vec!["trusted-dev@example.com".to_string()],
            display_name: Some("trusted-dev".to_string()),
            idp_token: None,
        };

        assert_eq!(
            mapper.permissions_for(&github_user).await.unwrap(),
            Permissions::<VPermission>::from(vec![VPermission::GetMappersAll]),
        );
        assert_eq!(
            mapper.groups_for(&github_user).await.unwrap(),
            BTreeSet::from([group_id]),
        );
    }

    /// Exploit: an attacker with a free Google account sets the account's
    /// freely-editable profile display name to "trusted-dev" and logs in via
    /// the Google OAuth flow. Because the mapper only compares
    /// `user.display_name` and never checks that `user.external_id` is the
    /// GitHub variant, the attacker impersonates the trusted GitHub
    /// contributor and is granted their permissions and groups.
    #[tokio::test]
    async fn google_login_must_not_impersonate_github_user() {
        let group_id = TypedUuid::new_v4();
        let mapper = trusted_dev_mapper(group_id);

        // Attacker's throwaway Google account with a spoofed display name.
        let attacker = UserInfo {
            external_id: ExternalUserId::Google("attacker-google-id".to_string()),
            verified_emails: vec!["attacker@gmail.com".to_string()],
            display_name: Some("trusted-dev".to_string()),
            idp_token: None,
        };

        let permissions = mapper.permissions_for(&attacker).await.unwrap();
        assert!(
            permissions.is_empty(),
            "authorization bypass: a Google login with a spoofed display name \
             'trusted-dev' was granted the GitHub-mapped permissions {:?}",
            permissions,
        );

        let groups = mapper.groups_for(&attacker).await.unwrap();
        assert!(
            groups.is_empty(),
            "authorization bypass: a Google login with a spoofed display name \
             'trusted-dev' was granted the GitHub-mapped groups {:?}",
            groups,
        );
    }

    /// The same bypass applies to Zendesk, whose `user.name` is self-editable.
    #[tokio::test]
    async fn zendesk_login_must_not_impersonate_github_user() {
        let group_id = TypedUuid::new_v4();
        let mapper = trusted_dev_mapper(group_id);

        let attacker = UserInfo {
            external_id: ExternalUserId::Zendesk("attacker-zendesk-id".to_string()),
            verified_emails: vec!["attacker@zendesk.example".to_string()],
            display_name: Some("trusted-dev".to_string()),
            idp_token: None,
        };

        let permissions = mapper.permissions_for(&attacker).await.unwrap();
        assert!(
            permissions.is_empty(),
            "authorization bypass: a Zendesk login with a spoofed display name \
             'trusted-dev' was granted the GitHub-mapped permissions {:?}",
            permissions,
        );

        let groups = mapper.groups_for(&attacker).await.unwrap();
        assert!(
            groups.is_empty(),
            "authorization bypass: a Zendesk login with a spoofed display name \
             'trusted-dev' was granted the GitHub-mapped groups {:?}",
            groups,
        );
    }
}
