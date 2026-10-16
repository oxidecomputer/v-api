// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Reports this service's access control inventory to Vanta.
//!
//! [`sync`] reads users, groups, and API keys out of the context and pushes them through
//! [`VantaClient`]. It is a plain async function rather than a scheduled task: how often to
//! report, and how to avoid two instances reporting at once, are decisions for the service. Note
//! that Vanta keeps a single active token per integration, so two concurrent syncs sharing
//! credentials will revoke each other's tokens.
//!
//! ```ignore
//! // `config.vanta` is a VantaConfig, deserialized with the rest of the service config
//! let client = VantaClient::new(&config.vanta, config_dir)?;
//!
//! let summary = v_api::vanta::sync(ctx.v_ctx(), &client).await?;
//! tracing::info!(?summary, "Access inventory reported");
//! ```

use std::collections::BTreeMap;

use chrono::Utc;
use newtype_uuid::{GenericUuid, TypedUuid};
use thiserror::Error;
use tracing::instrument;
use uuid::Uuid;
use v_api_vanta::{
    ApiKeyProperties, CustomResource, GroupProperties, UserAccount, VantaClient, VantaError,
    api_key_resource, group_resource, user_account,
};
use v_model::{
    AccessGroupId,
    permissions::Caller,
    storage::{AccessGroupFilter, ApiUserFilter, ListPagination, StoreError},
};

use crate::{
    VContext,
    permissions::{VAppPermission, VPermission},
    response::ResourceError,
};

#[derive(Debug, Error)]
pub enum VantaSyncError {
    #[error("Failed to read the access inventory")]
    Inventory(#[from] ResourceError<StoreError>),
    #[error(transparent)]
    Vanta(#[from] VantaError),
}

/// Everything a sync would report.
///
/// Separated from the push so that what gets reported can be inspected, and tested, without
/// talking to Vanta.
#[derive(Debug)]
pub struct VantaInventory {
    pub user_accounts: Vec<UserAccount>,
    pub groups: Vec<CustomResource<GroupProperties>>,
    pub api_keys: Vec<CustomResource<ApiKeyProperties>>,
}

/// What a completed sync reported
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VantaSyncSummary {
    pub user_accounts: usize,
    pub groups: usize,
    pub api_keys: usize,
}

/// The caller the sync reads as.
///
/// Read only across every user, group, and key, since the point is to report the whole
/// inventory. The nil id marks it as the service itself rather than any real user; it only ever
/// appears in the trace of a sync.
fn sync_caller<T>() -> Caller<T>
where
    T: VAppPermission,
{
    Caller {
        id: TypedUuid::from_untyped_uuid(Uuid::nil()),
        permissions: vec![
            VPermission::GetApiUsersAll,
            VPermission::GetGroupsAll,
            VPermission::GetApiKeysAll,
        ]
        .into(),
        extensions: Default::default(),
    }
}

/// Read the inventory that `client` is configured to report.
///
/// Groups and API keys are custom resources that have to be created in the Vanta dashboard
/// first, so they are only read when the client has an id to send them to.
#[instrument(skip(ctx, client))]
pub async fn collect<T>(
    ctx: &VContext<T>,
    client: &VantaClient,
) -> Result<VantaInventory, VantaSyncError>
where
    T: VAppPermission,
{
    let caller = sync_caller();

    // Deleted users are included on purpose. Omitting a user from a full state sync tells Vanta
    // the account never existed, which throws away the evidence that access was removed, so they
    // are reported as deactivated instead.
    let users = ctx
        .user
        .list_api_user(
            &caller,
            ApiUserFilter {
                deleted: true,
                ..Default::default()
            },
            &ListPagination::unlimited(),
        )
        .await?;

    let user_accounts = users
        .iter()
        .map(|info| user_account(info, ctx.public_url()))
        .collect::<Vec<_>>();

    let groups = match client.group_resource_id() {
        Some(_) => {
            let groups = ctx
                .group
                .list_groups(
                    &caller,
                    AccessGroupFilter {
                        deleted: true,
                        ..Default::default()
                    },
                )
                .await?;

            // Membership is reported for live users only. A deactivated account still shows up as
            // a user account, but counting it as a current member of a group would overstate who
            // holds the group's access today.
            let mut members: BTreeMap<TypedUuid<AccessGroupId>, Vec<String>> = BTreeMap::new();
            for info in users.iter().filter(|info| info.user.deleted_at.is_none()) {
                for group in &info.user.groups {
                    members
                        .entry(*group)
                        .or_default()
                        .push(info.user.id.to_string());
                }
            }

            groups
                .iter()
                .map(|group| group_resource(group, members.remove(&group.id).unwrap_or_default()))
                .collect()
        }
        None => Vec::new(),
    };

    let api_keys = match client.api_key_resource_id() {
        Some(_) => {
            let now = Utc::now();
            let mut api_keys = Vec::new();

            // Keys are listed per user, which is the only way the context exposes them. Keys
            // belonging to a deleted user are still read: a live key on a deprovisioned account is
            // exactly what a reviewer needs to see.
            for info in &users {
                let keys = ctx
                    .user
                    .get_api_user_tokens(&caller, &info.user.id, &ListPagination::unlimited())
                    .await?;

                api_keys.extend(
                    keys.iter()
                        .map(|key| api_key_resource(key, info.contact_email(), now)),
                );
            }

            api_keys
        }
        None => Vec::new(),
    };

    Ok(VantaInventory {
        user_accounts,
        groups,
        api_keys,
    })
}

/// Read the inventory and push it to Vanta.
///
/// Each resource type is a separate full state request, so a failure part way through leaves the
/// earlier ones applied. The next sync corrects it, since every sync sends everything.
#[instrument(skip(ctx, client), err(Debug))]
pub async fn sync<T>(
    ctx: &VContext<T>,
    client: &VantaClient,
) -> Result<VantaSyncSummary, VantaSyncError>
where
    T: VAppPermission,
{
    let inventory = collect(ctx, client).await?;
    let summary = VantaSyncSummary {
        user_accounts: inventory.user_accounts.len(),
        groups: inventory.groups.len(),
        api_keys: inventory.api_keys.len(),
    };

    client.sync_user_accounts(inventory.user_accounts).await?;

    if let Some(resource_id) = client.group_resource_id() {
        client
            .sync_custom_resources(resource_id, inventory.groups)
            .await?;
    }

    if let Some(resource_id) = client.api_key_resource_id() {
        client
            .sync_custom_resources(resource_id, inventory.api_keys)
            .await?;
    }

    tracing::info!(
        user_accounts = summary.user_accounts,
        groups = summary.groups,
        api_keys = summary.api_keys,
        "Reported the access inventory to Vanta"
    );

    Ok(summary)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use chrono::{TimeDelta, Utc};
    use newtype_uuid::TypedUuid;
    use v_api_vanta::{AccountStatus, VantaClient, VantaConfig};
    use v_model::{
        AccessGroup, AccessGroupSource, ApiKey, ApiUser, ApiUserInfo,
        permissions::Permissions,
        storage::{MockAccessGroupStore, MockApiKeyStore, MockApiUserStore},
    };

    use crate::{
        VContext,
        context::test_mocks::{MockStorage, mock_context},
        permissions::VPermission,
        vanta::collect,
    };

    fn user(
        deleted: bool,
        groups: BTreeSet<TypedUuid<v_model::AccessGroupId>>,
    ) -> ApiUser<VPermission> {
        let now = Utc::now();
        ApiUser {
            id: TypedUuid::new_v4(),
            permissions: Permissions::new(),
            groups,
            created_at: now,
            updated_at: now,
            deleted_at: deleted.then_some(now),
        }
    }

    fn config(custom_resources: bool) -> VantaConfig {
        VantaConfig {
            client_id: "client-id".to_string(),
            client_secret: "client-secret".to_string().into(),
            base_url: "http://vanta.invalid".to_string(),
            user_account_resource_id: "user-account-resource".to_string(),
            group_resource_id: custom_resources.then(|| "group-resource".to_string()),
            api_key_resource_id: custom_resources.then(|| "api-key-resource".to_string()),
        }
    }

    /// A context holding one live user in `group`, one deleted user, one key for the live user,
    /// and the group itself
    async fn ctx_with_inventory(
        live: ApiUser<VPermission>,
        deleted: ApiUser<VPermission>,
        group: AccessGroup<VPermission>,
        keys: Vec<ApiKey<VPermission>>,
    ) -> VContext<VPermission> {
        let users = vec![
            ApiUserInfo {
                user: live,
                email: None,
                providers: vec![],
            },
            ApiUserInfo {
                user: deleted,
                email: None,
                providers: vec![],
            },
        ];

        let mut user_store = MockApiUserStore::new();
        user_store
            .expect_list()
            .returning(move |_, _| Ok(users.clone()));

        let mut group_store = MockAccessGroupStore::new();
        group_store
            .expect_list()
            .returning(move |_, _| Ok(vec![group.clone()]));

        let mut key_store = MockApiKeyStore::new();
        key_store.expect_list().returning(move |filter, _| {
            let owner = filter.api_user_id.and_then(|ids| ids.first().copied());
            Ok(keys
                .iter()
                .filter(|key| Some(key.user_id) == owner)
                .cloned()
                .collect())
        });

        let mut storage = MockStorage::new();
        storage.api_user_store = Some(Arc::new(user_store));
        storage.access_group_store = Some(Arc::new(group_store));
        storage.api_user_token_store = Some(Arc::new(key_store));

        mock_context(Arc::new(storage)).await
    }

    fn group(id: TypedUuid<v_model::AccessGroupId>) -> AccessGroup<VPermission> {
        let now = Utc::now();
        AccessGroup {
            id,
            name: "engineering".to_string(),
            permissions: Permissions::new(),
            source: AccessGroupSource::Dynamic,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    fn api_key(user_id: TypedUuid<v_model::UserId>) -> ApiKey<VPermission> {
        let now = Utc::now();
        ApiKey {
            id: TypedUuid::new_v4(),
            user_id,
            key_signature: "signature".to_string(),
            permission_boundary: None,
            expires_at: now + TimeDelta::days(30),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    /// A deprovisioned user is still reported, as deactivated. Dropping it from a full state sync
    /// would tell Vanta the account never existed.
    #[tokio::test]
    async fn deleted_users_are_reported_as_deactivated() {
        let group_id = TypedUuid::new_v4();
        let live = user(false, BTreeSet::from([group_id]));
        let deleted = user(true, BTreeSet::from([group_id]));
        let (live_id, deleted_id) = (live.id, deleted.id);

        let ctx = ctx_with_inventory(live, deleted, group(group_id), vec![]).await;
        let client = VantaClient::new(&config(true), None).expect("client");

        let inventory = collect(&ctx, &client).await.expect("collect");

        assert_eq!(2, inventory.user_accounts.len());
        let statuses = inventory
            .user_accounts
            .iter()
            .map(|account| (account.unique_id.as_str(), account.status))
            .collect::<Vec<_>>();
        assert!(statuses.contains(&(live_id.to_string().as_str(), AccountStatus::Active)));
        assert!(statuses.contains(&(deleted_id.to_string().as_str(), AccountStatus::Deactivated)));
    }

    /// Group membership describes who holds the group's access now, so a deactivated account is
    /// not counted even though it still carries the group
    #[tokio::test]
    async fn group_membership_covers_live_users_only() {
        let group_id = TypedUuid::new_v4();
        let live = user(false, BTreeSet::from([group_id]));
        let deleted = user(true, BTreeSet::from([group_id]));
        let live_id = live.id;

        let ctx = ctx_with_inventory(live, deleted, group(group_id), vec![]).await;
        let client = VantaClient::new(&config(true), None).expect("client");

        let inventory = collect(&ctx, &client).await.expect("collect");

        assert_eq!(1, inventory.groups.len());
        let properties = &inventory.groups[0].custom_properties;
        assert_eq!(1, properties.member_count);
        assert_eq!(vec![live_id.to_string()], properties.member_unique_ids);
    }

    #[tokio::test]
    async fn api_keys_are_reported_against_their_owner() {
        let group_id = TypedUuid::new_v4();
        let live = user(false, BTreeSet::new());
        let live_id = live.id;
        let key = api_key(live_id);
        let key_id = key.id;

        let ctx = ctx_with_inventory(
            live,
            user(true, BTreeSet::new()),
            group(group_id),
            vec![key],
        )
        .await;
        let client = VantaClient::new(&config(true), None).expect("client");

        let inventory = collect(&ctx, &client).await.expect("collect");

        assert_eq!(1, inventory.api_keys.len());
        assert_eq!(key_id.to_string(), inventory.api_keys[0].unique_id);
        assert_eq!(
            live_id.to_string(),
            inventory.api_keys[0].custom_properties.user_unique_id
        );
    }

    /// Custom resources have to exist in the Vanta dashboard before they can be pushed to, so a
    /// service that has not created them is not queried for them either
    #[tokio::test]
    async fn unconfigured_custom_resources_are_not_read() {
        let group_id = TypedUuid::new_v4();

        let users = vec![ApiUserInfo {
            user: user(false, BTreeSet::from([group_id])),
            email: None,
            providers: vec![],
        }];

        let mut user_store = MockApiUserStore::new();
        user_store
            .expect_list()
            .returning(move |_, _| Ok(users.clone()));

        let mut group_store = MockAccessGroupStore::new();
        group_store.expect_list().never();

        let mut key_store = MockApiKeyStore::new();
        key_store.expect_list().never();

        let mut storage = MockStorage::new();
        storage.api_user_store = Some(Arc::new(user_store));
        storage.access_group_store = Some(Arc::new(group_store));
        storage.api_user_token_store = Some(Arc::new(key_store));

        let ctx = mock_context(Arc::new(storage)).await;
        let client = VantaClient::new(&config(false), None).expect("client");

        let inventory = collect(&ctx, &client).await.expect("collect");

        assert_eq!(1, inventory.user_accounts.len());
        assert!(inventory.groups.is_empty());
        assert!(inventory.api_keys.is_empty());
    }
}
