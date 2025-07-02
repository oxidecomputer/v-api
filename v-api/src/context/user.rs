// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use chrono::Utc;
use newtype_uuid::{GenericUuid, TypedUuid};
use std::{
    collections::{BTreeSet, HashMap},
    error::Error,
    sync::Arc,
};
use thiserror::Error;
use tracing::{info_span, instrument, Instrument};
use uuid::Uuid;
use v_model::{
    permissions::{AsScope, Caller, Permission, PermissionError, PermissionStorage},
    storage::{
        AccessGroupFilter, AccessGroupStore, AccessTokenStore, ApiKeyFilter, ApiKeyStore,
        ApiUserContactEmailStore, ApiUserFilter, ApiUserProviderFilter, ApiUserProviderStore,
        ApiUserStore, ListPagination, StoreError,
    },
    AccessGroupId, AccessToken, ApiKey, ApiKeyId, ApiUser, ApiUserContactEmail, ApiUserInfo,
    ApiUserProvider, ArcMap, NewAccessToken, NewApiKey, NewApiUser, NewApiUserContactEmail,
    NewApiUserProvider, Permissions, UserId, UserProviderId,
};

use crate::{
    authn::{
        jwt::{Claims, JwtSigner, JwtSignerError},
        AuthToken, Signer,
    },
    permissions::{VAppPermission, VPermission},
    response::{resource_restricted, OptionalResource, ResourceError, ResourceResult},
    VApiStorage,
};

#[derive(Debug)]
enum BasePermissions<T: Permission> {
    Full,
    Restricted(Permissions<T>),
}

#[derive(Debug, Error)]
pub enum UserContextError {
    #[error("Failed to authenticate caller")]
    FailedToAuthenticate,
    #[error("Supplied API key is invalid")]
    InvalidKey,
    #[error("Supplied API token has an unknown id or has been revoked")]
    InvalidToken,
    #[error("JWT credential failed")]
    Jwt(#[from] JwtSignerError),
    #[error("Invalid scope: {0}")]
    Scope(#[from] PermissionError),
    #[error("Inner storage failure: {0}")]
    Storage(#[from] StoreError),
}

pub struct RegisteredAccessToken {
    pub access_token: AccessToken,
    pub signed_token: String,
    pub expires_in: i64,
}

pub type ExtensionError = Box<dyn Error + Send + Sync + 'static>;

#[async_trait]
pub trait CallerExtension<T>: Send + Sync + 'static {
    async fn inject(
        &self,
        user: &ApiUser<T>,
        extensions: &mut ArcMap,
    ) -> Result<(), ExtensionError>;
}
#[async_trait]
impl<T, F> CallerExtension<T> for F
where
    F: Fn(&ApiUser<T>, &mut ArcMap) -> Result<(), ExtensionError> + Send + Sync + 'static,
    T: VAppPermission,
{
    async fn inject(
        &self,
        user: &ApiUser<T>,
        extensions: &mut ArcMap,
    ) -> Result<(), ExtensionError> {
        (self)(user, extensions)
    }
}

#[derive(Clone)]
pub struct UserContext<T> {
    caller_extension_handlers: Vec<Arc<dyn CallerExtension<T>>>,
    storage: Arc<dyn VApiStorage<T>>,
}

impl<T> UserContext<T>
where
    T: VAppPermission,
{
    pub fn new(storage: Arc<dyn VApiStorage<T>>) -> Self {
        Self {
            caller_extension_handlers: Vec::new(),
            storage,
        }
    }

    pub fn set_storage(&mut self, storage: Arc<dyn VApiStorage<T>>) {
        self.storage = storage;
    }

    pub fn add_extension_handler(&mut self, handler: Arc<dyn CallerExtension<T>>) {
        self.caller_extension_handlers.push(handler);
    }

    #[instrument(skip(self, user), fields(user = ?user.id))]
    async fn get_extensions(&self, user: &ApiUser<T>) -> ArcMap {
        let mut extensions = HashMap::new();
        for handler in &self.caller_extension_handlers {
            // Handlers are not allowed to cause a login to fail. They only report errors
            if let Err(err) = handler.inject(user, &mut extensions).await {
                tracing::error!(?err, "Caller extension failed");
            }
        }

        extensions
    }

    #[instrument(skip(self, registration_user, signer, token))]
    pub async fn get_caller(
        &self,
        registration_user: &Caller<T>,
        signer: &dyn Signer,
        token: &AuthToken,
    ) -> Result<Caller<T>, UserContextError> {
        let (api_user_id, base_permissions) = self
            .get_base_permissions(registration_user, signer, token)
            .await?;

        match self.get_api_user(registration_user, &api_user_id).await {
            ResourceResult::Ok(info) => {
                let extensions = self.get_extensions(&info.user).await;

                // The permissions for the caller is the intersection of the user's permissions and the tokens permissions
                let user_permissions = self.get_user_permissions(&info.user, &extensions).await?;

                let combined_permissions = match &base_permissions {
                    BasePermissions::Full => user_permissions.clone(),
                    BasePermissions::Restricted(permissions) => {
                        let token_permissions = <T as PermissionStorage>::expand(
                            permissions,
                            &info.user,
                            Some(&user_permissions),
                            &extensions,
                        );
                        token_permissions.intersect(&user_permissions)
                    }
                };

                tracing::trace!(token = ?base_permissions, user = ?user_permissions, combined = ?combined_permissions, "Computed caller permissions");

                let caller: Caller<T> = Caller {
                    id: api_user_id,
                    permissions: combined_permissions
                        .into_iter()
                        .map(|p| p.into())
                        .collect::<Permissions<T>>(),
                    extensions,
                };

                tracing::info!(?caller.id, "Resolved caller");
                tracing::debug!(?caller.permissions, "Caller permissions");

                Ok(caller)
            }
            Err(ResourceError::Conflict) => {
                tracing::error!("User lookup resulted in a conflict. This should be impossible!");
                Err(UserContextError::FailedToAuthenticate)
            }
            Err(ResourceError::DoesNotExist) => {
                tracing::error!("User for verified token does not exist");
                Err(UserContextError::FailedToAuthenticate)
            }
            Err(ResourceError::Restricted) => {
                tracing::error!("Built in user did not have permission to retrieve caller");
                Err(UserContextError::FailedToAuthenticate)
            }
            Err(ResourceError::InternalError(err)) => {
                tracing::error!("Failed to lookup caller");
                Err(UserContextError::Storage(err))
            }
        }
    }

    async fn get_base_permissions(
        &self,
        caller: &Caller<T>,
        signer: &dyn Signer,
        auth: &AuthToken,
    ) -> Result<(TypedUuid<UserId>, BasePermissions<T>), UserContextError> {
        Ok(match auth {
            AuthToken::ApiKey(api_key) => {
                async {
                    tracing::debug!("Attempt to authenticate");

                    let id = TypedUuid::from_untyped_uuid(Uuid::from_slice(api_key.id()).map_err(|err| {
                        tracing::info!(?err, slice = ?api_key.id(), "Failed to parse id from API key");
                        UserContextError::InvalidKey
                    })?);

                    let mut key = if caller.any(&mut [VPermission::GetApiKey(id).into(), VPermission::GetApiKeysAll.into()].iter()) {
                        Ok(ApiKeyStore::list(
                            &*self.storage,
                            ApiKeyFilter {
                                id: Some(vec![id]),
                                expired: false,
                                deleted: false,
                                ..Default::default()
                            },
                            &ListPagination {
                                offset: 0,
                                limit: 1,
                            },
                        )
                        .await?)
                    } else {
                        tracing::error!("Calling user is not allowed to lookup user permissions");
                        Err(UserContextError::FailedToAuthenticate)
                    }?;

                    if let Some(key) = key.pop() {
                        if let Err(err) =
                            api_key.verify(signer, key.key_signature.as_bytes())
                        {
                            tracing::debug!(?err, "Failed to verify api key");
                            Err(UserContextError::FailedToAuthenticate)
                        } else {
                            tracing::debug!("Verified caller key");
                            Ok((
                                key.user_id,
                                key.permissions
                                    .map(BasePermissions::Restricted)
                                    .unwrap_or(BasePermissions::Full),
                            ))
                        }
                    } else {
                        tracing::debug!("Failed to find matching key");
                        Err(UserContextError::FailedToAuthenticate)
                    }
                }
                .instrument(info_span!("Test api key"))
                .await
            }
            AuthToken::Jwt(jwt) => {
                // AuthnToken::Jwt can only be generated from a verified JWT
                let permissions = match &jwt.claims.scp {
                    Some(scp) => BasePermissions::Restricted(<T as AsScope>::from_scope(scp.iter())?),
                    None => BasePermissions::Full,
                };

                // Verify that the access token has not been revoked and is known
                let token = AccessTokenStore::get(&*self.storage, &jwt.claims.jti, false).await?;
                if token.is_none() {
                    Err(UserContextError::InvalidToken)?
                }

                Ok((jwt.claims.sub, permissions))
            }
        }?)
    }

    #[instrument(skip(self), fields(user_id = ?user.id, groups = ?user.groups))]
    async fn get_user_permissions(
        &self,
        user: &ApiUser<T>,
        extensions: &ArcMap,
    ) -> Result<Permissions<T>, StoreError> {
        let mut group_permissions = self.get_user_group_permissions(&user, &extensions).await?;
        let mut permissions = user.permissions.clone();
        permissions.append(&mut group_permissions);

        Ok(permissions)
    }

    async fn get_user_group_permissions(
        &self,
        user: &ApiUser<T>,
        extensions: &ArcMap,
    ) -> Result<Permissions<T>, StoreError> {
        tracing::trace!("Expanding groups into permissions");

        let groups = AccessGroupStore::list(
            &*self.storage,
            AccessGroupFilter {
                id: Some(user.groups.iter().copied().collect()),
                ..Default::default()
            },
            &ListPagination::unlimited(),
        )
        .await?;

        tracing::trace!(?groups, "Found groups to map to permissions");

        let permissions = groups
            .into_iter()
            .fold(Permissions::new(), |mut aggregate, group| {
                let mut expanded = <T as PermissionStorage>::expand(&group.permissions, &user, Some(&user.permissions), extensions);

                tracing::trace!(group_id = ?group.id, group_name = ?group.name, permissions = ?expanded, "Transformed group into permission set");
                aggregate.append(&mut expanded);

                aggregate
            });

        Ok(permissions)
    }

    // API User Operations

    #[instrument(skip(self, caller), fields(caller = ?caller.id))]
    pub async fn get_api_user(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<UserId>,
    ) -> ResourceResult<ApiUserInfo<T>, StoreError> {
        if caller.any(
            &mut [
                VPermission::GetApiUser(*id).into(),
                VPermission::GetApiUsersAll.into(),
            ]
            .iter(),
        ) {
            let mut info = ApiUserStore::get(&*self.storage, id, false)
                .await
                .optional()?;

            let extensions = self.get_extensions(&info.user).await;

            info.user.permissions = <T as PermissionStorage>::expand(
                &info.user.permissions,
                &info.user,
                None,
                &extensions,
            );

            Ok(info)
        } else {
            resource_restricted()
        }
    }

    #[instrument(skip(self, caller, filter, pagination), fields(caller = ?caller.id))]
    pub async fn list_api_user(
        &self,
        caller: &Caller<T>,
        filter: ApiUserFilter,
        pagination: &ListPagination,
    ) -> ResourceResult<Vec<ApiUserInfo<T>>, StoreError> {
        let mut users = ApiUserStore::list(&*self.storage, filter, pagination).await?;

        users.retain(|info| {
            caller.any(
                &mut [
                    VPermission::GetApiUser(info.user.id).into(),
                    VPermission::GetApiUsersAll.into(),
                ]
                .iter(),
            )
        });

        Ok(users)
    }

    #[instrument(skip(self, caller), fields(caller = ?caller.id))]
    pub async fn create_api_user(
        &self,
        caller: &Caller<T>,
        permissions: Permissions<T>,
        groups: BTreeSet<TypedUuid<AccessGroupId>>,
    ) -> ResourceResult<ApiUserInfo<T>, StoreError> {
        if caller.can(&VPermission::CreateApiUser.into()) {
            let mut new_user = NewApiUser {
                id: TypedUuid::new_v4(),
                permissions: permissions,
                groups: groups,
            };
            new_user.permissions = <T as PermissionStorage>::contract(&new_user.permissions);
            Ok(ApiUserStore::upsert(&*self.storage, new_user).await?)
        } else {
            resource_restricted()
        }
    }

    #[instrument(skip(self, caller, api_user), fields(caller = ?caller.id))]
    pub async fn update_api_user(
        &self,
        caller: &Caller<T>,
        mut api_user: NewApiUser<T>,
    ) -> ResourceResult<ApiUserInfo<T>, StoreError> {
        if caller.any(
            &mut [
                VPermission::ManageApiUser(api_user.id).into(),
                VPermission::ManageApiUsersAll.into(),
            ]
            .iter(),
        ) {
            api_user.permissions = <T as PermissionStorage>::contract(&api_user.permissions);
            Ok(ApiUserStore::upsert(&*self.storage, api_user).await?)
        } else {
            resource_restricted()
        }
    }

    #[instrument(skip(self, caller, user_id, new_permissions), fields(caller = ?caller.id))]
    pub async fn add_permissions_to_user(
        &self,
        caller: &Caller<T>,
        user_id: &TypedUuid<UserId>,
        new_permissions: Permissions<T>,
    ) -> ResourceResult<ApiUserInfo<T>, StoreError> {
        if caller.any(
            &mut [
                VPermission::ManageApiUser(*user_id).into(),
                VPermission::ManageApiUsersAll.into(),
            ]
            .iter(),
        ) {
            let info = self.get_api_user(caller, user_id).await?;

            let mut user_update: NewApiUser<T> = info.user.into();
            for permission in new_permissions.into_iter() {
                tracing::info!(id = ?user_id, ?permission, "Adding permission to user");
                user_update.permissions.insert(permission);
            }

            self.update_api_user(caller, user_update).await
        } else {
            resource_restricted()
        }
    }

    #[instrument(skip(self, caller, token, api_user_id), fields(caller = ?caller.id))]
    pub async fn create_api_user_token(
        &self,
        caller: &Caller<T>,
        token: NewApiKey<T>,
        api_user_id: &TypedUuid<UserId>,
    ) -> ResourceResult<ApiKey<T>, StoreError> {
        if caller.any(
            &mut [
                VPermission::CreateApiKey(*api_user_id).into(),
                VPermission::CreateApiKeyAll.into(),
            ]
            .iter(),
        ) {
            Ok(ApiKeyStore::upsert(&*self.storage, token).await?)
        } else {
            resource_restricted()
        }
    }

    pub async fn get_api_user_token(
        &self,
        caller: &Caller<T>,
        api_key_id: &TypedUuid<ApiKeyId>,
    ) -> ResourceResult<ApiKey<T>, StoreError> {
        if caller.any(
            &mut [
                VPermission::GetApiKey(*api_key_id).into(),
                VPermission::GetApiKeysAll.into(),
            ]
            .iter(),
        ) {
            ApiKeyStore::get(&*self.storage, api_key_id, false)
                .await
                .optional()
        } else {
            resource_restricted()
        }
    }

    pub async fn get_api_user_tokens(
        &self,
        caller: &Caller<T>,
        api_user_id: &TypedUuid<UserId>,
        pagination: &ListPagination,
    ) -> ResourceResult<Vec<ApiKey<T>>, StoreError> {
        let mut tokens = ApiKeyStore::list(
            &*self.storage,
            ApiKeyFilter {
                api_user_id: Some(vec![*api_user_id]),
                expired: true,
                deleted: false,
                ..Default::default()
            },
            pagination,
        )
        .await?;

        tokens.retain(|token| {
            caller.any(
                &mut [
                    VPermission::GetApiKey(token.id).into(),
                    VPermission::GetApiKeysAll.into(),
                ]
                .iter(),
            )
        });

        Ok(tokens)
    }

    pub async fn set_api_user_contact_email(
        &self,
        caller: &Caller<T>,
        user_id: TypedUuid<UserId>,
        email: &str,
    ) -> ResourceResult<ApiUserContactEmail, StoreError> {
        if caller.any(
            &mut [
                VPermission::ManageApiUser(user_id).into(),
                VPermission::ManageApiUsersAll.into(),
            ]
            .iter(),
        ) {
            let user = self.get_api_user(caller, &user_id).await?;

            if user.owns_email(email) {
                Ok(ApiUserContactEmailStore::upsert(
                    &*self.storage,
                    NewApiUserContactEmail {
                        id: user
                            .email
                            .map(|email| email.id)
                            .unwrap_or_else(|| TypedUuid::new_v4()),
                        user_id,
                        email: email.to_string(),
                    },
                )
                .await?)
            } else {
                resource_restricted()
            }
        } else {
            resource_restricted()
        }
    }

    pub async fn get_api_user_provider(
        &self,
        caller: &Caller<T>,
        user_id: &TypedUuid<UserId>,
        provider_id: &TypedUuid<UserProviderId>,
    ) -> ResourceResult<ApiUserProvider, StoreError> {
        if caller.any(
            &mut [
                VPermission::GetApiUser(*user_id).into(),
                VPermission::GetApiUsersAll.into(),
            ]
            .iter(),
        ) {
            ApiUserProviderStore::get(&*self.storage, provider_id, false)
                .await
                .optional()
        } else {
            resource_restricted()
        }
    }

    pub async fn list_api_user_provider(
        &self,
        caller: &Caller<T>,
        filter: ApiUserProviderFilter,
        pagination: &ListPagination,
    ) -> ResourceResult<Vec<ApiUserProvider>, StoreError> {
        let mut providers = ApiUserProviderStore::list(&*self.storage, filter, pagination).await?;

        providers.retain(|provider| {
            caller.any(
                &mut [
                    VPermission::GetApiUser(provider.user_id).into(),
                    VPermission::GetApiUsersAll.into(),
                ]
                .iter(),
            )
        });

        Ok(providers)
    }

    pub async fn update_api_user_provider(
        &self,
        caller: &Caller<T>,
        api_user_provider: NewApiUserProvider,
    ) -> ResourceResult<ApiUserProvider, StoreError> {
        if caller.any(
            &mut [
                VPermission::ManageApiUser(api_user_provider.user_id).into(),
                VPermission::ManageApiUsersAll.into(),
            ]
            .iter(),
        ) {
            Ok(ApiUserProviderStore::upsert(&*self.storage, api_user_provider).await?)
        } else {
            resource_restricted()
        }
    }

    pub async fn delete_api_user_token(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<ApiKeyId>,
    ) -> ResourceResult<ApiKey<T>, UserContextError> {
        if caller.any(
            &mut [
                VPermission::ManageApiKey(*id).into(),
                VPermission::ManageApiKeysAll.into(),
            ]
            .iter(),
        ) {
            Ok(ApiKeyStore::delete(&*self.storage, id).await.optional()?)
        } else {
            resource_restricted()
        }
    }

    pub async fn create_access_token(
        &self,
        caller: &Caller<T>,
        access_token: NewAccessToken,
    ) -> ResourceResult<AccessToken, UserContextError> {
        if caller.can(&VPermission::CreateAccessToken.into()) {
            Ok(AccessTokenStore::upsert(&*self.storage, access_token).await?)
        } else {
            resource_restricted()
        }
    }

    #[instrument(skip(self), err(Debug))]
    async fn ensure_api_user(
        &self,
        caller: &Caller<T>,
        api_user_id: TypedUuid<UserId>,
        mut mapped_permissions: Permissions<T>,
        mut mapped_groups: BTreeSet<TypedUuid<AccessGroupId>>,
    ) -> ResourceResult<ApiUserInfo<T>, StoreError> {
        match self.get_api_user(caller, &api_user_id).await {
            ResourceResult::Ok(info) => {
                // Ensure that the existing user has "at least" the mapped permissions
                let mut update: NewApiUser<T> = info.user.into();
                update.permissions.append(&mut mapped_permissions);
                update.groups.append(&mut mapped_groups);

                self.update_api_user(caller, update).await
            }
            ResourceResult::Err(ResourceError::DoesNotExist) => {
                // TODO: Seems weird this is not a create call, indicates an issue higher up in
                // the call chain
                self.update_api_user(
                    caller,
                    NewApiUser {
                        id: api_user_id,
                        permissions: mapped_permissions,
                        groups: mapped_groups,
                    },
                )
                .await
            }
            other => other,
        }
    }

    pub async fn register_access_token(
        &self,
        caller: &Caller<T>,
        signer: &JwtSigner,
        api_user: &TypedUuid<UserId>,
        claims: &Claims,
    ) -> ResourceResult<RegisteredAccessToken, UserContextError> {
        let token = self
            .create_access_token(
                caller,
                NewAccessToken {
                    id: claims.jti,
                    user_id: *api_user,
                    revoked_at: None,
                },
            )
            .await?;

        let signed = signer
            .sign(&claims)
            .await
            .map_err(|err| ResourceError::InternalError(UserContextError::Jwt(err)))?;
        Ok(RegisteredAccessToken {
            access_token: token,
            signed_token: signed,
            expires_in: claims.exp - Utc::now().timestamp(),
        })
    }
}
