// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use partial_struct::partial;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;
use uuid::Uuid;
use v_api_permissions::{Permission, Permissions};

pub trait VAppPermission: Permission + From<VPermission> + AsScope {}
impl<T> VAppPermission for T where T: Permission + From<VPermission> + AsScope {}

pub trait VAppPermissionResponse: Permission {}
impl<T> VAppPermissionResponse for T where T: Permission {}

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
    CreateApiUserToken(Uuid),
    CreateApiUserTokenSelf,
    CreateApiUserTokenAssigned,
    CreateApiUserTokenAll,
    GetApiUser(Uuid),
    GetApiUserSelf,
    GetApiUserAssigned,
    GetApiUserAll,
    GetApiUserToken(Uuid),
    GetApiUserTokenSelf,
    GetApiUserTokenAssigned,
    GetApiUserTokenAll,
    DeleteApiUserToken(Uuid),
    DeleteApiUserTokenSelf,
    DeleteApiUserTokenAssigned,
    DeleteApiUserTokenAll,
    CreateApiUser,
    UpdateApiUser(Uuid),
    UpdateApiUserSelf,
    UpdateApiUserAssigned,
    UpdateApiUserAll,

    // User provider permissions
    CreateUserApiProviderLinkToken,

    // Group permissions,
    GetGroupsJoined,
    GetGroupsAll,
    CreateGroup,
    UpdateGroup(Uuid),
    AddToGroup(Uuid),
    RemoveFromGroup(Uuid),
    ManageGroupMembership(Uuid),
    ManageGroupMemberships(BTreeSet<Uuid>),
    ManageGroupMembershipAssigned,
    ManageGroupMembershipAll,
    DeleteGroup(Uuid),
    ManageGroup(Uuid),
    ManageGroups(BTreeSet<Uuid>),
    ManageGroupsAssigned,
    ManageGroupsAll,

    // Mapper permissions
    ListMappers,
    CreateMapper,
    UpdateMapper(Uuid),
    DeleteMapper(Uuid),
    ManageMapper(Uuid),
    ManageMappers(BTreeSet<Uuid>),
    ManageMappersAssigned,
    ManageMappersAll,

    // OAuth client manage permissions
    CreateOAuthClient,
    GetOAuthClient(Uuid),
    GetOAuthClients(BTreeSet<Uuid>),
    GetOAuthClientsAssigned,
    GetOAuthClientsAll,
    UpdateOAuthClient(Uuid),
    UpdateOAuthClients(BTreeSet<Uuid>),
    UpdateOAuthClientsAssigned,
    UpdateOAuthClientsAll,
    DeleteOAuthClient(Uuid),
    DeleteOAuthClients(BTreeSet<Uuid>),
    DeleteOAuthClientsAssigned,
    DeleteOAuthClientsAll,

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
            VPermission::CreateApiUserToken(_) => "user:token:w",
            VPermission::CreateApiUserTokenSelf => "user:token:w",
            VPermission::CreateApiUserTokenAssigned => "user:token:w",
            VPermission::CreateApiUserTokenAll => "user:token:w",
            VPermission::GetApiUser(_) => "user:info:r",
            VPermission::GetApiUserSelf => "user:info:r",
            VPermission::GetApiUserAssigned => "user:info:r",
            VPermission::GetApiUserAll => "user:info:r",
            VPermission::GetApiUserToken(_) => "user:token:r",
            VPermission::GetApiUserTokenSelf => "user:token:r",
            VPermission::GetApiUserTokenAssigned => "user:token:r",
            VPermission::GetApiUserTokenAll => "user:token:r",
            VPermission::DeleteApiUserToken(_) => "user:token:w",
            VPermission::DeleteApiUserTokenSelf => "user:token:w",
            VPermission::DeleteApiUserTokenAssigned => "user:token:w",
            VPermission::DeleteApiUserTokenAll => "user:token:w",
            VPermission::CreateApiUser => "user:info:w",
            VPermission::UpdateApiUser(_) => "user:info:w",
            VPermission::UpdateApiUserSelf => "user:info:w",
            VPermission::UpdateApiUserAssigned => "user:info:w",
            VPermission::UpdateApiUserAll => "user:info:w",

            VPermission::CreateUserApiProviderLinkToken => "user:provider:w",

            VPermission::GetGroupsJoined => "group:r",
            VPermission::GetGroupsAll => "group:r",
            VPermission::CreateGroup => "group:w",
            VPermission::UpdateGroup(_) => "group:w",
            VPermission::AddToGroup(_) => "group:membership:w",
            VPermission::RemoveFromGroup(_) => "group:membership:w",
            VPermission::ManageGroupMembership(_) => "group:membership:w",
            VPermission::ManageGroupMemberships(_) => "group:membership:w",
            VPermission::ManageGroupMembershipAssigned => "group:membership:w",
            VPermission::ManageGroupMembershipAll => "group:membership:w",
            VPermission::DeleteGroup(_) => "group:w",
            VPermission::ManageGroup(_) => "group:w",
            VPermission::ManageGroups(_) => "group:w",
            VPermission::ManageGroupsAssigned => "group:w",
            VPermission::ManageGroupsAll => "group:w",

            VPermission::ListMappers => "mapper:r",
            VPermission::CreateMapper => "mapper:w",
            VPermission::UpdateMapper(_) => "mapper:w",
            VPermission::DeleteMapper(_) => "mapper:w",
            VPermission::ManageMapper(_) => "mapper:w",
            VPermission::ManageMappers(_) => "mapper:w",
            VPermission::ManageMappersAssigned => "mapper:w",
            VPermission::ManageMappersAll => "mapper:w",

            VPermission::CreateOAuthClient => "oauth:client:w",
            VPermission::GetOAuthClient(_) => "oauth:client:r",
            VPermission::GetOAuthClients(_) => "oauth:client:r",
            VPermission::GetOAuthClientsAssigned => "oauth:client:r",
            VPermission::GetOAuthClientsAll => "oauth:client:r",
            VPermission::UpdateOAuthClient(_) => "oauth:client:w",
            VPermission::UpdateOAuthClients(_) => "oauth:client:w",
            VPermission::UpdateOAuthClientsAssigned => "oauth:client:w",
            VPermission::UpdateOAuthClientsAll => "oauth:client:w",
            VPermission::DeleteOAuthClient(_) => "oauth:client:w",
            VPermission::DeleteOAuthClients(_) => "oauth:client:w",
            VPermission::DeleteOAuthClientsAssigned => "oauth:client:w",
            VPermission::DeleteOAuthClientsAll => "oauth:client:w",

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
                    permissions.insert(VPermission::GetApiUserAll);
                }
                "user:info:w" => {
                    permissions.insert(VPermission::UpdateApiUserSelf);
                    permissions.insert(VPermission::UpdateApiUserAssigned);
                    permissions.insert(VPermission::UpdateApiUserAll);
                }
                "user:provider:w" => {
                    permissions.insert(VPermission::CreateUserApiProviderLinkToken);
                }
                "user:token:r" => {
                    permissions.insert(VPermission::GetApiUserTokenSelf);
                    permissions.insert(VPermission::GetApiUserTokenAssigned);
                    permissions.insert(VPermission::GetApiUserTokenAll);
                }
                "user:token:w" => {
                    permissions.insert(VPermission::CreateApiUserTokenSelf);
                    permissions.insert(VPermission::CreateApiUserTokenAssigned);
                    permissions.insert(VPermission::CreateApiUserTokenAll);
                    permissions.insert(VPermission::DeleteApiUserTokenSelf);
                    permissions.insert(VPermission::DeleteApiUserTokenAssigned);
                    permissions.insert(VPermission::DeleteApiUserTokenAll);
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
                    permissions.insert(VPermission::ManageGroupMembershipAssigned);
                    permissions.insert(VPermission::ManageGroupMembershipAll);
                }
                "mapper:r" => {
                    permissions.insert(VPermission::ListMappers);
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
                    permissions.insert(VPermission::UpdateOAuthClientsAssigned);
                    permissions.insert(VPermission::UpdateOAuthClientsAll);
                    permissions.insert(VPermission::DeleteOAuthClientsAssigned);
                    permissions.insert(VPermission::DeleteOAuthClientsAll);
                }
                other => return Err(ApiPermissionError::InvalidScope(other.to_string())),
            }
        }

        Ok(permissions)
    }
}

// pub trait PermissionStorage {
//     fn contract(&self, owner: &Uuid) -> Self;
//     fn expand(&self, owner: &Uuid, owner_permissions: Option<&Self>) -> Self;
// }

pub trait PermissionStorage {
    fn contract(collection: &Permissions<Self>, owner: &Uuid) -> Permissions<Self>
    where
        Self: Sized;
    fn expand(
        collection: &Permissions<Self>,
        owner: &Uuid,
        owner_permissions: Option<&Permissions<Self>>,
    ) -> Permissions<Self>
    where
        Self: Sized;
}

// impl PermissionStorage for Permissions<VPermission> {
//     fn contract(&self, owner: &Uuid) -> Self {
//         let mut contracted = Vec::new();

//         let mut manage_group_memberships = BTreeSet::<Uuid>::new();
//         let mut manage_groups = BTreeSet::<Uuid>::new();
//         let mut read_oauth_clients = BTreeSet::<Uuid>::new();
//         let mut update_oauth_clients = BTreeSet::<Uuid>::new();
//         let mut delete_oauth_clients = BTreeSet::<Uuid>::new();

//         for p in self.iter() {
//             match p {
//                 VPermission::GetApiUser(id) => contracted.push(if id == owner {
//                     VPermission::GetApiUserSelf
//                 } else {
//                     VPermission::GetApiUser(*id)
//                 }),
//                 VPermission::CreateApiUserToken(id) => contracted.push(if id == owner {
//                     VPermission::CreateApiUserTokenSelf
//                 } else {
//                     VPermission::CreateApiUserToken(*id)
//                 }),
//                 VPermission::GetApiUserToken(id) => contracted.push(if id == owner {
//                     VPermission::GetApiUserTokenSelf
//                 } else {
//                     VPermission::GetApiUserToken(*id)
//                 }),
//                 VPermission::DeleteApiUserToken(id) => contracted.push(if id == owner {
//                     VPermission::DeleteApiUserTokenSelf
//                 } else {
//                     VPermission::DeleteApiUserToken(*id)
//                 }),
//                 VPermission::UpdateApiUser(id) => contracted.push(if id == owner {
//                     VPermission::UpdateApiUserSelf
//                 } else {
//                     VPermission::UpdateApiUser(*id)
//                 }),

//                 VPermission::ManageGroupMembership(id) => {
//                     manage_group_memberships.insert(*id);
//                 }
//                 VPermission::ManageGroup(id) => {
//                     manage_groups.insert(*id);
//                 }

//                 VPermission::GetOAuthClient(id) => {
//                     read_oauth_clients.insert(*id);
//                 }
//                 VPermission::UpdateOAuthClient(id) => {
//                     update_oauth_clients.insert(*id);
//                 }
//                 VPermission::DeleteOAuthClient(id) => {
//                     delete_oauth_clients.insert(*id);
//                 }

//                 other => contracted.push(other.clone()),
//             }
//         }

//         contracted.push(VPermission::ManageGroupMemberships(
//             manage_group_memberships,
//         ));
//         contracted.push(VPermission::ManageGroups(manage_groups));
//         contracted.push(VPermission::GetOAuthClients(read_oauth_clients));
//         contracted.push(VPermission::UpdateOAuthClients(update_oauth_clients));
//         contracted.push(VPermission::DeleteOAuthClients(delete_oauth_clients));

//         contracted.into()
//     }

//     fn expand(&self, owner: &Uuid, owner_permissions: Option<&Permissions<VPermission>>) -> Self {
//         let mut expanded = Vec::new();

//         for p in self.iter() {
//             match p {
//                 VPermission::GetApiUserSelf => {
//                     expanded.push(p.clone());
//                     expanded.push(VPermission::GetApiUser(*owner))
//                 }
//                 VPermission::CreateApiUserTokenSelf => {
//                     expanded.push(p.clone());
//                     expanded.push(VPermission::CreateApiUserToken(*owner))
//                 }
//                 VPermission::GetApiUserTokenSelf => {
//                     expanded.push(p.clone());
//                     expanded.push(VPermission::GetApiUserToken(*owner))
//                 }
//                 VPermission::DeleteApiUserTokenSelf => {
//                     expanded.push(p.clone());
//                     expanded.push(VPermission::DeleteApiUserToken(*owner))
//                 }
//                 VPermission::UpdateApiUserSelf => {
//                     expanded.push(p.clone());
//                     expanded.push(VPermission::UpdateApiUser(*owner))
//                 }

//                 VPermission::ManageGroupMemberships(ids) => {
//                     for id in ids {
//                         expanded.push(VPermission::ManageGroupMembership(*id))
//                     }
//                 }
//                 VPermission::ManageGroups(ids) => {
//                     for id in ids {
//                         expanded.push(VPermission::ManageGroup(*id))
//                     }
//                 }

//                 VPermission::GetOAuthClients(ids) => {
//                     for id in ids {
//                         expanded.push(VPermission::GetOAuthClient(*id))
//                     }
//                 }
//                 VPermission::UpdateOAuthClients(ids) => {
//                     for id in ids {
//                         expanded.push(VPermission::UpdateOAuthClient(*id))
//                     }
//                 }
//                 VPermission::DeleteOAuthClients(ids) => {
//                     for id in ids {
//                         expanded.push(VPermission::DeleteOAuthClient(*id))
//                     }
//                 }

//                 VPermission::ManageGroupMembershipAssigned => {
//                     expanded.push(p.clone());

//                     if let Some(owner_permissions) = owner_permissions {
//                         for p in owner_permissions.iter() {
//                             match p {
//                                 VPermission::ManageGroupMembership(id) => {
//                                     expanded.push(VPermission::ManageGroupMembership(*id))
//                                 }
//                                 _ => (),
//                             }
//                         }
//                     }
//                 }
//                 VPermission::ManageGroupsAssigned => {
//                     expanded.push(p.clone());

//                     if let Some(owner_permissions) = owner_permissions {
//                         for p in owner_permissions.iter() {
//                             match p {
//                                 VPermission::ManageGroup(id) => {
//                                     expanded.push(VPermission::ManageGroup(*id))
//                                 }
//                                 _ => (),
//                             }
//                         }
//                     }
//                 }
//                 VPermission::GetOAuthClientsAssigned => {
//                     expanded.push(p.clone());

//                     if let Some(owner_permissions) = owner_permissions {
//                         for p in owner_permissions.iter() {
//                             match p {
//                                 VPermission::GetOAuthClient(id) => {
//                                     expanded.push(VPermission::GetOAuthClient(*id))
//                                 }
//                                 _ => (),
//                             }
//                         }
//                     }
//                 }
//                 VPermission::UpdateOAuthClientsAssigned => {
//                     expanded.push(p.clone());

//                     if let Some(owner_permissions) = owner_permissions {
//                         for p in owner_permissions.iter() {
//                             match p {
//                                 VPermission::UpdateOAuthClient(id) => {
//                                     expanded.push(VPermission::UpdateOAuthClient(*id))
//                                 }
//                                 _ => (),
//                             }
//                         }
//                     }
//                 }
//                 VPermission::DeleteOAuthClientsAssigned => {
//                     expanded.push(p.clone());

//                     if let Some(owner_permissions) = owner_permissions {
//                         for p in owner_permissions.iter() {
//                             match p {
//                                 VPermission::DeleteOAuthClient(id) => {
//                                     expanded.push(VPermission::DeleteOAuthClient(*id))
//                                 }
//                                 _ => (),
//                             }
//                         }
//                     }
//                 }

//                 other => expanded.push(other.clone()),
//             }
//         }

//         expanded.into()
//     }
// }

impl PermissionStorage for VPermission {
    fn contract(collection: &Permissions<Self>, owner: &Uuid) -> Permissions<Self> {
        let mut contracted = Vec::new();

        let mut manage_group_memberships = BTreeSet::<Uuid>::new();
        let mut manage_groups = BTreeSet::<Uuid>::new();
        let mut read_oauth_clients = BTreeSet::<Uuid>::new();
        let mut update_oauth_clients = BTreeSet::<Uuid>::new();
        let mut delete_oauth_clients = BTreeSet::<Uuid>::new();

        for p in collection.iter() {
            match p {
                VPermission::GetApiUser(id) => contracted.push(if id == owner {
                    VPermission::GetApiUserSelf
                } else {
                    VPermission::GetApiUser(*id)
                }),
                VPermission::CreateApiUserToken(id) => contracted.push(if id == owner {
                    VPermission::CreateApiUserTokenSelf
                } else {
                    VPermission::CreateApiUserToken(*id)
                }),
                VPermission::GetApiUserToken(id) => contracted.push(if id == owner {
                    VPermission::GetApiUserTokenSelf
                } else {
                    VPermission::GetApiUserToken(*id)
                }),
                VPermission::DeleteApiUserToken(id) => contracted.push(if id == owner {
                    VPermission::DeleteApiUserTokenSelf
                } else {
                    VPermission::DeleteApiUserToken(*id)
                }),
                VPermission::UpdateApiUser(id) => contracted.push(if id == owner {
                    VPermission::UpdateApiUserSelf
                } else {
                    VPermission::UpdateApiUser(*id)
                }),

                VPermission::ManageGroupMembership(id) => {
                    manage_group_memberships.insert(*id);
                }
                VPermission::ManageGroup(id) => {
                    manage_groups.insert(*id);
                }

                VPermission::GetOAuthClient(id) => {
                    read_oauth_clients.insert(*id);
                }
                VPermission::UpdateOAuthClient(id) => {
                    update_oauth_clients.insert(*id);
                }
                VPermission::DeleteOAuthClient(id) => {
                    delete_oauth_clients.insert(*id);
                }

                other => contracted.push(other.clone()),
            }
        }

        contracted.push(VPermission::ManageGroupMemberships(
            manage_group_memberships,
        ));
        contracted.push(VPermission::ManageGroups(manage_groups));
        contracted.push(VPermission::GetOAuthClients(read_oauth_clients));
        contracted.push(VPermission::UpdateOAuthClients(update_oauth_clients));
        contracted.push(VPermission::DeleteOAuthClients(delete_oauth_clients));

        contracted.into()
    }

    fn expand(
        collection: &Permissions<Self>,
        owner: &Uuid,
        owner_permissions: Option<&Permissions<Self>>,
    ) -> Permissions<Self> {
        let mut expanded = Vec::new();

        for p in collection.iter() {
            match p {
                VPermission::GetApiUserSelf => {
                    expanded.push(p.clone());
                    expanded.push(VPermission::GetApiUser(*owner))
                }
                VPermission::CreateApiUserTokenSelf => {
                    expanded.push(p.clone());
                    expanded.push(VPermission::CreateApiUserToken(*owner))
                }
                VPermission::GetApiUserTokenSelf => {
                    expanded.push(p.clone());
                    expanded.push(VPermission::GetApiUserToken(*owner))
                }
                VPermission::DeleteApiUserTokenSelf => {
                    expanded.push(p.clone());
                    expanded.push(VPermission::DeleteApiUserToken(*owner))
                }
                VPermission::UpdateApiUserSelf => {
                    expanded.push(p.clone());
                    expanded.push(VPermission::UpdateApiUser(*owner))
                }

                VPermission::ManageGroupMemberships(ids) => {
                    for id in ids {
                        expanded.push(VPermission::ManageGroupMembership(*id))
                    }
                }
                VPermission::ManageGroups(ids) => {
                    for id in ids {
                        expanded.push(VPermission::ManageGroup(*id))
                    }
                }

                VPermission::GetOAuthClients(ids) => {
                    for id in ids {
                        expanded.push(VPermission::GetOAuthClient(*id))
                    }
                }
                VPermission::UpdateOAuthClients(ids) => {
                    for id in ids {
                        expanded.push(VPermission::UpdateOAuthClient(*id))
                    }
                }
                VPermission::DeleteOAuthClients(ids) => {
                    for id in ids {
                        expanded.push(VPermission::DeleteOAuthClient(*id))
                    }
                }

                VPermission::ManageGroupMembershipAssigned => {
                    expanded.push(p.clone());

                    if let Some(owner_permissions) = owner_permissions {
                        for p in owner_permissions.iter() {
                            match p {
                                VPermission::ManageGroupMembership(id) => {
                                    expanded.push(VPermission::ManageGroupMembership(*id))
                                }
                                _ => (),
                            }
                        }
                    }
                }
                VPermission::ManageGroupsAssigned => {
                    expanded.push(p.clone());

                    if let Some(owner_permissions) = owner_permissions {
                        for p in owner_permissions.iter() {
                            match p {
                                VPermission::ManageGroup(id) => {
                                    expanded.push(VPermission::ManageGroup(*id))
                                }
                                _ => (),
                            }
                        }
                    }
                }
                VPermission::GetOAuthClientsAssigned => {
                    expanded.push(p.clone());

                    if let Some(owner_permissions) = owner_permissions {
                        for p in owner_permissions.iter() {
                            match p {
                                VPermission::GetOAuthClient(id) => {
                                    expanded.push(VPermission::GetOAuthClient(*id))
                                }
                                _ => (),
                            }
                        }
                    }
                }
                VPermission::UpdateOAuthClientsAssigned => {
                    expanded.push(p.clone());

                    if let Some(owner_permissions) = owner_permissions {
                        for p in owner_permissions.iter() {
                            match p {
                                VPermission::UpdateOAuthClient(id) => {
                                    expanded.push(VPermission::UpdateOAuthClient(*id))
                                }
                                _ => (),
                            }
                        }
                    }
                }
                VPermission::DeleteOAuthClientsAssigned => {
                    expanded.push(p.clone());

                    if let Some(owner_permissions) = owner_permissions {
                        for p in owner_permissions.iter() {
                            match p {
                                VPermission::DeleteOAuthClient(id) => {
                                    expanded.push(VPermission::DeleteOAuthClient(*id))
                                }
                                _ => (),
                            }
                        }
                    }
                }

                other => expanded.push(other.clone()),
            }
        }

        expanded.into()
    }
}
