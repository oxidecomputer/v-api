// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use newtype_uuid::TypedUuid;
use partial_struct::partial;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;
use v_model::permissions::{Permission, Permissions};
use v_model::{AccessGroupId, ApiKeyId, MapperId, OAuthClientId, UserId};

pub trait VAppPermission: Permission + From<VPermission> + AsScope {}
impl<T> VAppPermission for T where T: Permission + From<VPermission> + AsScope {}

pub trait VAppPermissionResponse: Permission {}
impl<T> VAppPermissionResponse for T where T: Permission {}

// TODO: Split permissions into expanded and contracted permission sets. Contracted permissions
// are stored in the database as such

#[derive(Debug, Error)]
pub enum ApiPermissionError {
    #[error("Scope is invalid: {0}")]
    InvalidScope(String),
}

#[partial(VPermissionResponse, attributes(#[serde(tag = "kind", content = "value")]))]
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, PartialOrd, Ord,
)]
pub enum VPermission {
    // User information permissions
    CreateApiUser,
    GetApiUser(TypedUuid<UserId>),
    GetApiUsers(BTreeSet<TypedUuid<UserId>>),
    // #[v_api(alias = GetApiUser)]
    GetApiUserSelf,
    // #[v_api(alias = GetApiUser)]
    GetApiUsersAssigned,
    GetApiUsersAll,
    ManageApiUser(TypedUuid<UserId>),
    ManageApiUsers(BTreeSet<TypedUuid<UserId>>),
    ManageApiUsersAssigned,
    ManageApiUsersAll,

    // User api key permissions
    CreateApiKey(TypedUuid<UserId>),
    CreateApiKeySelf,
    CreateApiKeyAssigned,
    CreateApiKeyAll,
    GetApiKey(TypedUuid<ApiKeyId>),
    GetApiKeys(BTreeSet<TypedUuid<ApiKeyId>>),
    GetApiKeyAssigned,
    GetApiKeysAll,
    ManageApiKey(TypedUuid<ApiKeyId>),
    ManageApiKeys(BTreeSet<TypedUuid<ApiKeyId>>),
    ManageApiKeysAssigned,
    ManageApiKeysAll,

    // User provider permissions
    CreateUserApiProviderLinkToken,

    // Group permissions,
    CreateGroup,
    GetGroupsJoined,
    GetGroupsAll,
    ManageGroup(TypedUuid<AccessGroupId>),
    ManageGroups(BTreeSet<TypedUuid<AccessGroupId>>),
    ManageGroupsAssigned,
    ManageGroupsAll,

    // Group Membership Permissions
    ManageGroupMembership(TypedUuid<AccessGroupId>),
    ManageGroupMemberships(BTreeSet<TypedUuid<AccessGroupId>>),
    ManageGroupMembershipsAssigned,
    ManageGroupMembershipsAll,

    // Mapper permissions
    CreateMapper,
    GetMappersAll,
    ManageMapper(TypedUuid<MapperId>),
    ManageMappers(BTreeSet<TypedUuid<MapperId>>),
    ManageMappersAssigned,
    ManageMappersAll,

    // OAuth client manage permissions
    CreateOAuthClient,
    GetOAuthClient(TypedUuid<OAuthClientId>),
    GetOAuthClients(BTreeSet<TypedUuid<OAuthClientId>>),
    GetOAuthClientsAssigned,
    GetOAuthClientsAll,
    ManageOAuthClient(TypedUuid<OAuthClientId>),
    ManageOAuthClients(BTreeSet<TypedUuid<OAuthClientId>>),
    ManageOAuthClientsAssigned,
    ManageOAuthClientsAll,

    // Internal permissions
    CreateAccessToken,

    // Removed
    #[serde(other)]
    Removed,
}

pub trait AsScope: Sized {
    fn as_scope(&self) -> &str;
    fn from_scope_arg(scope_arg: &str) -> Result<Permissions<Self>, ApiPermissionError> {
        Self::from_scope(scope_arg.split(' '))
    }
    fn from_scope<S>(
        scope: impl Iterator<Item = S>,
    ) -> Result<Permissions<Self>, ApiPermissionError>
    where
        S: AsRef<str>;
}

impl AsScope for VPermission {
    fn as_scope(&self) -> &str {
        match self {
            VPermission::CreateApiUser => "user:info:w",
            VPermission::GetApiUser(_) => "user:info:r",
            VPermission::GetApiUsers(_) => "user:info:r",
            VPermission::GetApiUserSelf => "user:info:r",
            VPermission::GetApiUsersAssigned => "user:info:r",
            VPermission::GetApiUsersAll => "user:info:r",
            VPermission::ManageApiUser(_) => "user:info:w",
            VPermission::ManageApiUsers(_) => "user:info:w",
            VPermission::ManageApiUsersAssigned => "user:info:w",
            VPermission::ManageApiUsersAll => "user:info:w",
            VPermission::CreateApiKey(_) => "user:key:w",
            VPermission::CreateApiKeySelf => "user:key:w",
            VPermission::CreateApiKeyAssigned => "user:key:w",
            VPermission::CreateApiKeyAll => "user:key:w",
            VPermission::GetApiKey(_) => "user:key:r",
            VPermission::GetApiKeys(_) => "user:key:r",
            VPermission::GetApiKeyAssigned => "user:key:r",
            VPermission::GetApiKeysAll => "user:key:r",
            VPermission::ManageApiKey(_) => "user:key:w",
            VPermission::ManageApiKeys(_) => "user:key:w",
            VPermission::ManageApiKeysAssigned => "user:key:w",
            VPermission::ManageApiKeysAll => "user:key:w",
            VPermission::CreateUserApiProviderLinkToken => "user:provider:w",
            VPermission::GetGroupsJoined => "group:info:r",
            VPermission::GetGroupsAll => "group:info:r",
            VPermission::CreateGroup => "group:info:w",
            VPermission::ManageGroup(_) => "group:info:w",
            VPermission::ManageGroups(_) => "group:info:w",
            VPermission::ManageGroupsAssigned => "group:info:w",
            VPermission::ManageGroupsAll => "group:info:w",
            VPermission::ManageGroupMembership(_) => "group:membership:w",
            VPermission::ManageGroupMemberships(_) => "group:membership:w",
            VPermission::ManageGroupMembershipsAssigned => "group:membership:w",
            VPermission::ManageGroupMembershipsAll => "group:membership:w",
            VPermission::CreateMapper => "mapper:w",
            VPermission::GetMappersAll => "mapper:r",
            VPermission::ManageMapper(_) => "mapper:w",
            VPermission::ManageMappers(_) => "mapper:w",
            VPermission::ManageMappersAssigned => "mapper:w",
            VPermission::ManageMappersAll => "mapper:w",
            VPermission::CreateOAuthClient => "oauth:client:w",
            VPermission::GetOAuthClient(_) => "oauth:client:r",
            VPermission::GetOAuthClients(_) => "oauth:client:r",
            VPermission::GetOAuthClientsAssigned => "oauth:client:r",
            VPermission::GetOAuthClientsAll => "oauth:client:r",
            VPermission::ManageOAuthClient(_) => "oauth:client:w",
            VPermission::ManageOAuthClients(_) => "oauth:client:w",
            VPermission::ManageOAuthClientsAssigned => "oauth:client:w",
            VPermission::ManageOAuthClientsAll => "oauth:client:w",
            VPermission::CreateAccessToken => "",
            VPermission::Removed => "",
        }
    }

    fn from_scope<S>(
        scope: impl Iterator<Item = S>,
    ) -> Result<Permissions<VPermission>, ApiPermissionError>
    where
        S: AsRef<str>,
    {
        let mut permissions = Permissions::new();

        for entry in scope {
            match entry.as_ref() {
                "user:info:r" => {
                    permissions.insert(VPermission::GetApiUserSelf);
                    permissions.insert(VPermission::GetApiUsersAssigned);
                    permissions.insert(VPermission::GetApiUsersAll);
                }
                "user:info:w" => {
                    permissions.insert(VPermission::CreateApiUser);
                    permissions.insert(VPermission::ManageApiUsersAssigned);
                    permissions.insert(VPermission::ManageApiUsersAll);
                }
                "user:provider:w" => {
                    permissions.insert(VPermission::CreateUserApiProviderLinkToken);
                }
                "user:token:r" => {
                    permissions.insert(VPermission::GetApiKeyAssigned);
                    permissions.insert(VPermission::GetApiKeysAll);
                }
                "user:token:w" => {
                    permissions.insert(VPermission::CreateApiKeySelf);
                    permissions.insert(VPermission::CreateApiKeyAssigned);
                    permissions.insert(VPermission::CreateApiKeyAll);
                    permissions.insert(VPermission::ManageApiKeysAssigned);
                    permissions.insert(VPermission::ManageApiKeysAll);
                }
                "group:r" => {
                    permissions.insert(VPermission::GetGroupsJoined);
                    permissions.insert(VPermission::GetGroupsAll);
                }
                "group:w" => {
                    permissions.insert(VPermission::CreateGroup);
                    permissions.insert(VPermission::ManageGroupsAssigned);
                    permissions.insert(VPermission::ManageGroupsAll);
                }
                "group:membership:w" => {
                    permissions.insert(VPermission::ManageGroupMembershipsAssigned);
                    permissions.insert(VPermission::ManageGroupMembershipsAll);
                }
                "mapper:r" => {
                    permissions.insert(VPermission::GetMappersAll);
                }
                "mapper:w" => {
                    permissions.insert(VPermission::CreateMapper);
                    permissions.insert(VPermission::ManageMappersAssigned);
                    permissions.insert(VPermission::ManageMappersAll);
                }
                "oauth:client:r" => {
                    permissions.insert(VPermission::GetOAuthClientsAssigned);
                    permissions.insert(VPermission::GetOAuthClientsAll);
                }
                "oauth:client:w" => {
                    permissions.insert(VPermission::CreateOAuthClient);
                    permissions.insert(VPermission::ManageOAuthClientsAssigned);
                    permissions.insert(VPermission::ManageOAuthClientsAll);
                }
                other => return Err(ApiPermissionError::InvalidScope(other.to_string())),
            }
        }

        Ok(permissions)
    }
}

pub trait PermissionStorage {
    fn contract(collection: &Permissions<Self>) -> Permissions<Self>
    where
        Self: Sized;
    fn expand(
        collection: &Permissions<Self>,
        actor: &TypedUuid<UserId>,
        actor_permissions: Option<&Permissions<Self>>,
    ) -> Permissions<Self>
    where
        Self: Sized;
}

impl PermissionStorage for VPermission {
    fn contract(collection: &Permissions<Self>) -> Permissions<Self> {
        let mut contracted = Vec::new();

        let mut read_users = BTreeSet::<TypedUuid<UserId>>::new();
        let mut write_users = BTreeSet::<TypedUuid<UserId>>::new();
        let mut read_keys = BTreeSet::<TypedUuid<ApiKeyId>>::new();
        let mut write_keys = BTreeSet::<TypedUuid<ApiKeyId>>::new();
        let mut write_groups = BTreeSet::<TypedUuid<AccessGroupId>>::new();
        let mut write_group_memberships = BTreeSet::<TypedUuid<AccessGroupId>>::new();
        let mut write_mappers = BTreeSet::<TypedUuid<MapperId>>::new();
        let mut read_oauth_clients = BTreeSet::<TypedUuid<OAuthClientId>>::new();
        let mut write_oauth_clients = BTreeSet::<TypedUuid<OAuthClientId>>::new();

        for p in collection.iter() {
            match p {
                // Contract user info permissions
                VPermission::GetApiUser(id) => {
                    read_users.insert(*id);
                }
                VPermission::GetApiUsers(ids) => {
                    read_users.extend(ids);
                }
                VPermission::ManageApiUser(id) => {
                    write_users.insert(*id);
                }
                VPermission::ManageApiUsers(ids) => {
                    write_users.extend(ids);
                }

                // Contract api key permissions
                VPermission::GetApiKey(id) => {
                    read_keys.insert(*id);
                }
                VPermission::GetApiKeys(ids) => {
                    read_keys.extend(ids);
                }
                VPermission::ManageApiKey(id) => {
                    write_keys.insert(*id);
                }
                VPermission::ManageApiKeys(ids) => {
                    write_keys.extend(ids);
                }

                // Contract group permissions
                VPermission::ManageGroup(id) => {
                    write_groups.insert(*id);
                }
                VPermission::ManageGroups(ids) => {
                    write_groups.extend(ids);
                }
                VPermission::ManageGroupMembership(id) => {
                    write_group_memberships.insert(*id);
                }
                VPermission::ManageGroupMemberships(ids) => {
                    write_group_memberships.extend(ids);
                }

                // Contract mapper permissions
                VPermission::ManageMapper(id) => {
                    write_mappers.insert(*id);
                }
                VPermission::ManageMappers(ids) => {
                    write_mappers.extend(ids);
                }

                // Contract oauth client permissions
                VPermission::GetOAuthClient(id) => {
                    read_oauth_clients.insert(*id);
                }
                VPermission::GetOAuthClients(ids) => {
                    read_oauth_clients.extend(ids);
                }
                VPermission::ManageOAuthClient(id) => {
                    write_oauth_clients.insert(*id);
                }
                VPermission::ManageOAuthClients(ids) => {
                    write_oauth_clients.extend(ids);
                }

                // Alias permissions contract in to nothing
                VPermission::GetApiUserSelf => (),
                VPermission::GetApiUsersAssigned => (),
                VPermission::ManageApiUsersAssigned => (),
                VPermission::CreateApiKeySelf => (),
                VPermission::CreateApiKeyAssigned => (),
                VPermission::GetApiKeyAssigned => (),
                VPermission::ManageApiKeysAssigned => (),
                VPermission::ManageGroupsAssigned => (),
                VPermission::ManageGroupMembershipsAssigned => (),
                VPermission::ManageMappersAssigned => (),
                VPermission::GetOAuthClientsAssigned => (),
                VPermission::ManageOAuthClientsAssigned => (),

                // Add the remaining permissions as is
                other => contracted.push(other.clone()),
            }
        }

        contracted.push(VPermission::GetApiUsers(read_users));
        contracted.push(VPermission::ManageApiUsers(write_users));
        contracted.push(VPermission::GetApiKeys(read_keys));
        contracted.push(VPermission::ManageApiKeys(write_keys));
        contracted.push(VPermission::ManageGroups(write_groups));
        contracted.push(VPermission::ManageGroupMemberships(write_group_memberships));
        contracted.push(VPermission::ManageMappers(write_mappers));
        contracted.push(VPermission::GetOAuthClients(read_oauth_clients));
        contracted.push(VPermission::ManageOAuthClients(write_oauth_clients));

        contracted.into()
    }

    fn expand(
        collection: &Permissions<Self>,
        actor: &TypedUuid<UserId>,
        actor_permissions: Option<&Permissions<Self>>,
    ) -> Permissions<Self> {
        let mut expanded = Vec::new();

        for p in collection.iter() {
            match p {
                VPermission::GetApiUserSelf => expanded.push(VPermission::GetApiUser(*actor)),
                VPermission::GetApiUsers(ids) => {
                    for id in ids {
                        expanded.push(VPermission::GetApiUser(*id))
                    }
                }
                VPermission::GetApiUsersAssigned => {
                    if let Some(actor_permissions) = actor_permissions {
                        expanded.extend(
                            actor_permissions
                                .iter()
                                .filter(|op| match op {
                                    VPermission::GetApiUser(_) => true,
                                    _ => false,
                                })
                                .cloned(),
                        );
                    }
                }
                VPermission::ManageApiUsers(ids) => {
                    for id in ids {
                        expanded.push(VPermission::ManageApiUser(*id))
                    }
                }
                VPermission::ManageApiUsersAssigned => {
                    if let Some(actor_permissions) = actor_permissions {
                        expanded.extend(
                            actor_permissions
                                .iter()
                                .filter(|op| match op {
                                    VPermission::ManageApiUser(_) => true,
                                    _ => false,
                                })
                                .cloned(),
                        );
                    }
                }

                VPermission::CreateApiKeySelf => {
                    expanded.push(VPermission::CreateApiKey(*actor));
                }
                VPermission::CreateApiKeyAssigned => {
                    if let Some(actor_permissions) = actor_permissions {
                        expanded.extend(
                            actor_permissions
                                .iter()
                                .filter(|op| match op {
                                    VPermission::CreateApiKey(_) => true,
                                    _ => false,
                                })
                                .cloned(),
                        );
                    }
                }
                VPermission::GetApiKeys(ids) => {
                    for id in ids {
                        expanded.push(VPermission::GetApiKey(*id))
                    }
                }
                VPermission::GetApiKeyAssigned => {
                    if let Some(actor_permissions) = actor_permissions {
                        expanded.extend(
                            actor_permissions
                                .iter()
                                .filter(|op| match op {
                                    VPermission::GetApiKey(_) => true,
                                    _ => false,
                                })
                                .cloned(),
                        );
                    }
                }
                VPermission::ManageApiKeys(ids) => {
                    for id in ids {
                        expanded.push(VPermission::ManageApiKey(*id))
                    }
                }
                VPermission::ManageApiKeysAssigned => {
                    if let Some(actor_permissions) = actor_permissions {
                        expanded.extend(
                            actor_permissions
                                .iter()
                                .filter(|op| match op {
                                    VPermission::ManageApiKey(_) => true,
                                    _ => false,
                                })
                                .cloned(),
                        );
                    }
                }

                VPermission::ManageGroups(ids) => {
                    for id in ids {
                        expanded.push(VPermission::ManageGroup(*id))
                    }
                }
                VPermission::ManageGroupsAssigned => {
                    if let Some(actor_permissions) = actor_permissions {
                        expanded.extend(
                            actor_permissions
                                .iter()
                                .filter(|op| match op {
                                    VPermission::ManageGroup(_) => true,
                                    _ => false,
                                })
                                .cloned(),
                        );
                    }
                }

                VPermission::ManageGroupMemberships(ids) => {
                    for id in ids {
                        expanded.push(VPermission::ManageGroupMembership(*id))
                    }
                }
                VPermission::ManageGroupMembershipsAssigned => {
                    if let Some(actor_permissions) = actor_permissions {
                        expanded.extend(
                            actor_permissions
                                .iter()
                                .filter(|op| match op {
                                    VPermission::ManageGroupMembership(_) => true,
                                    _ => false,
                                })
                                .cloned(),
                        );
                    }
                }

                VPermission::ManageMappers(ids) => {
                    for id in ids {
                        expanded.push(VPermission::ManageMapper(*id))
                    }
                }
                VPermission::ManageMappersAssigned => {
                    if let Some(actor_permissions) = actor_permissions {
                        expanded.extend(
                            actor_permissions
                                .iter()
                                .filter(|op| match op {
                                    VPermission::ManageMapper(_) => true,
                                    _ => false,
                                })
                                .cloned(),
                        );
                    }
                }

                VPermission::GetOAuthClients(ids) => {
                    for id in ids {
                        expanded.push(VPermission::GetOAuthClient(*id))
                    }
                }
                VPermission::GetOAuthClientsAssigned => {
                    if let Some(actor_permissions) = actor_permissions {
                        expanded.extend(
                            actor_permissions
                                .iter()
                                .filter(|op| match op {
                                    VPermission::GetOAuthClient(_) => true,
                                    _ => false,
                                })
                                .cloned(),
                        );
                    }
                }
                VPermission::ManageOAuthClients(ids) => {
                    for id in ids {
                        expanded.push(VPermission::ManageOAuthClient(*id))
                    }
                }
                VPermission::ManageOAuthClientsAssigned => {
                    if let Some(actor_permissions) = actor_permissions {
                        expanded.extend(
                            actor_permissions
                                .iter()
                                .filter(|op| match op {
                                    VPermission::ManageOAuthClient(_) => true,
                                    _ => false,
                                })
                                .cloned(),
                        );
                    }
                }

                other => expanded.push(other.clone()),
            }
        }

        expanded.into()
    }
}
