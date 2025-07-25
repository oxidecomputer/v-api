// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use auth::AuthContext;
use chrono::{TimeDelta, Utc};
use dropshot::{ClientErrorStatusCode, HttpError, RequestContext, ServerContext};
use jsonwebtoken::jwk::JwkSet;
use newtype_uuid::TypedUuid;
use std::{fmt::Debug, future::Future, sync::Arc};
use thiserror::Error;
use tracing::instrument;
use user::{RegisteredAccessToken, UserContextError};
use v_model::{
    permissions::{Caller, Permission},
    storage::{
        AccessGroupStore, AccessTokenStore, ApiKeyStore, ApiUserContactEmailStore,
        ApiUserProviderFilter, ApiUserProviderStore, ApiUserStore, LinkRequestStore,
        ListPagination, LoginAttemptStore, MagicLinkAttemptStore, MagicLinkRedirectUriStore,
        MagicLinkSecretStore, MagicLinkStore, MapperStore, OAuthClientRedirectUriStore,
        OAuthClientSecretStore, OAuthClientStore, StoreError,
    },
    AccessGroupId, ApiUserInfo, ApiUserProvider, InvalidValueError, LinkRequest, NewApiUser,
    NewApiUserProvider, NewLinkRequest, UserId, UserProviderId,
};

use crate::{
    authn::{
        jwt::{Claims, JwtSigner, JwtSignerError},
        AuthError, AuthToken, Signer, VerificationResult, Verifier,
    },
    config::{AsymmetricKey, JwtConfig},
    endpoints::login::{
        oauth::{
            ClientType, OAuthProvider, OAuthProviderError, OAuthProviderFn, OAuthProviderName,
        },
        UserInfo,
    },
    error::{ApiError, AppError},
    mapper::DefaultMappingEngine,
    permissions::{VAppPermission, VPermission},
    response::{OptionalResource, ResourceErrorInner},
    util::response::{
        client_error, internal_error, resource_error, resource_restricted, ResourceResult,
    },
};

pub mod auth;
pub mod group;
pub use group::GroupContext;
pub mod link;
pub use link::LinkContext;
pub mod login;
pub use login::LoginContext;
pub mod magic_link;
pub use magic_link::{MagicLinkContext, MagicLinkMessage, MagicLinkTarget};
pub mod mapping;
pub use mapping::MappingContext;
pub mod oauth;
pub use oauth::OAuthContext;
pub mod user;
pub use user::{CallerExtension, ExtensionError, UserContext};

pub trait VApiStorage<P: Send + Sync>:
    ApiUserStore<P>
    + ApiKeyStore<P>
    + ApiUserContactEmailStore
    + ApiUserProviderStore
    + AccessTokenStore
    + LoginAttemptStore
    + OAuthClientStore
    + OAuthClientSecretStore
    + OAuthClientRedirectUriStore
    + AccessGroupStore<P>
    + MapperStore
    + LinkRequestStore
    + MagicLinkStore
    + MagicLinkSecretStore
    + MagicLinkRedirectUriStore
    + MagicLinkAttemptStore
    + Send
    + Sync
    + 'static
{
}
impl<P, T> VApiStorage<P> for T
where
    P: Permission,
    T: ApiUserStore<P>
        + ApiKeyStore<P>
        + ApiUserContactEmailStore
        + ApiUserProviderStore
        + AccessTokenStore
        + LoginAttemptStore
        + OAuthClientStore
        + OAuthClientSecretStore
        + OAuthClientRedirectUriStore
        + AccessGroupStore<P>
        + MapperStore
        + LinkRequestStore
        + MagicLinkStore
        + MagicLinkSecretStore
        + MagicLinkRedirectUriStore
        + MagicLinkAttemptStore
        + Send
        + Sync
        + 'static,
{
}

pub struct VContext<T> {
    public_url: String,
    storage: Arc<dyn VApiStorage<T>>,
    auth: AuthContext<T>,
    pub group: GroupContext<T>,
    pub link: LinkContext<T>,
    pub login: LoginContext<T>,
    pub magic_link: MagicLinkContext<T>,
    pub mapping: MappingContext<T>,
    pub oauth: OAuthContext<T>,
    pub user: UserContext<T>,
}

pub trait ApiContext: ServerContext {
    type AppPermissions: VAppPermission;
    fn v_ctx(&self) -> &VContext<Self::AppPermissions>;
}

impl<T> ApiContext for VContext<T>
where
    T: VAppPermission,
{
    type AppPermissions = T;
    fn v_ctx(&self) -> &VContext<T> {
        &self
    }
}

impl<T> ApiContext for RequestContext<T>
where
    T: ApiContext,
{
    type AppPermissions = T::AppPermissions;
    fn v_ctx(&self) -> &VContext<T::AppPermissions> {
        self.context().v_ctx()
    }
}

pub trait VContextWithCaller<T>
where
    T: Permission,
{
    fn as_ctx(
        &self,
    ) -> impl Future<Output = Result<(&VContext<T>, Caller<T>), VContextCallerError>>;
}

#[derive(Debug, Error)]
pub enum VContextCallerError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Caller(#[from] UserContextError),
}

impl From<VContextCallerError> for HttpError {
    fn from(value: VContextCallerError) -> Self {
        match value {
            VContextCallerError::Auth(inner) => inner.into(),
            VContextCallerError::Caller(inner) => inner.into(),
        }
    }
}

impl<T, U> VContextWithCaller<T> for RequestContext<U>
where
    T: VAppPermission,
    U: ApiContext<AppPermissions = T>,
{
    async fn as_ctx(&self) -> Result<(&VContext<T>, Caller<T>), VContextCallerError> {
        let ctx = self.v_ctx();
        let caller = ctx.get_caller(self).await?;
        Ok((ctx, caller))
    }
}

impl From<UserContextError> for HttpError {
    fn from(error: UserContextError) -> Self {
        tracing::info!(?error, "Failed to authenticate caller");

        match error {
            UserContextError::FailedToAuthenticate => client_error(
                ClientErrorStatusCode::UNAUTHORIZED,
                "Failed to authenticate",
            ),
            UserContextError::InvalidKey => client_error(
                ClientErrorStatusCode::UNAUTHORIZED,
                "Failed to authenticate",
            ),
            UserContextError::InvalidToken => client_error(
                ClientErrorStatusCode::UNAUTHORIZED,
                "Failed to authenticate",
            ),
            UserContextError::Jwt(_) => internal_error("Credential signing failed"),
            UserContextError::Scope(_) => {
                client_error(ClientErrorStatusCode::UNAUTHORIZED, "Invalid scope")
            }
            UserContextError::Storage(_) => internal_error("Internal storage failed"),
        }
    }
}

#[derive(Debug, Error)]
pub enum LoginAttemptError {
    #[error(transparent)]
    FailedToCreate(#[from] InvalidValueError),
    #[error(transparent)]
    Storage(#[from] StoreError),
}

impl<T> VContext<T>
where
    T: VAppPermission,
{
    pub async fn new(
        public_url: String,
        storage: Arc<dyn VApiStorage<T>>,
        jwt: JwtConfig,
        keys: Vec<AsymmetricKey>,
    ) -> Result<Self, AppError> {
        let auth_ctx = AuthContext::new(jwt, keys)?;
        let group_ctx = GroupContext::new(storage.clone());
        let mut mapping_ctx = MappingContext::new(storage.clone());
        mapping_ctx.set_engine(Some(Arc::new(DefaultMappingEngine::new(
            auth_ctx.builtin_registration_user(),
            group_ctx.clone(),
        ))));

        Ok(Self {
            public_url,
            storage: storage.clone(),
            auth: auth_ctx,
            group: group_ctx,
            link: LinkContext::new(storage.clone()),
            login: LoginContext::new(storage.clone()),
            magic_link: MagicLinkContext::new(storage.clone()),
            mapping: mapping_ctx,
            oauth: OAuthContext::new(storage.clone()),
            user: UserContext::new(storage.clone()),
        })
    }

    pub fn device_client(&self) -> ClientType {
        ClientType::Device
    }

    pub fn web_client(&self) -> ClientType {
        ClientType::Web
    }

    pub fn set_storage(&mut self, storage: Arc<dyn VApiStorage<T>>) {
        self.storage = storage;
        self.group.set_storage(self.storage.clone());
        self.link.set_storage(self.storage.clone());
        self.login.set_storage(self.storage.clone());
        self.mapping.set_storage(self.storage.clone());
        self.oauth.set_storage(self.storage.clone());
        self.user.set_storage(self.storage.clone());
    }

    pub async fn jwks(&self) -> &JwkSet {
        self.auth.jwks().await
    }

    pub async fn sign_jwt(&self, claims: &Claims) -> Result<String, JwtSignerError> {
        self.auth.sign_jwt(claims).await
    }

    pub fn signer(&self) -> &dyn Signer {
        &*self.auth.signer()
    }

    pub fn jwt_signer(&self) -> &JwtSigner {
        &*self.auth.jwt_signer()
    }

    pub fn public_url(&self) -> &str {
        &self.public_url
    }

    pub fn with_public_url(&mut self, public_url: &str) -> &mut Self {
        self.public_url = public_url.to_string();
        self
    }

    pub fn builtin_unauthenticated_caller(&self) -> Caller<T> {
        self.auth.builtin_unauthenticated_caller()
    }

    pub fn add_unauthenticated_caller_permission(&mut self, permission: T) -> &mut Self {
        self.auth
            .builtin_unauthenticated_caller_mut()
            .permissions
            .insert(permission);
        self
    }

    pub fn remove_unauthenticated_caller_permission(&mut self, permission: &T) -> &mut Self {
        self.auth
            .builtin_unauthenticated_caller_mut()
            .permissions
            .remove(permission);
        self
    }

    pub fn builtin_registration_user(&self) -> Caller<T> {
        self.auth.builtin_registration_user()
    }

    pub fn add_registration_caller_permission(&mut self, permission: T) -> &mut Self {
        self.auth
            .builtin_registration_user_mut()
            .permissions
            .insert(permission);
        self
    }

    pub fn remove_registration_caller_permission(&mut self, permission: &T) -> &mut Self {
        self.auth
            .builtin_registration_user_mut()
            .permissions
            .remove(permission);
        self
    }

    pub fn generate_claims(
        &self,
        api_user: &TypedUuid<UserId>,
        api_user_provider: &TypedUuid<UserProviderId>,
        scope: Option<Vec<String>>,
    ) -> Claims {
        let expires_at =
            Utc::now() + TimeDelta::try_seconds(self.auth.default_jwt_expiration()).unwrap();
        Claims::new(self, None, &api_user, &api_user_provider, scope, expires_at)
    }

    pub fn insert_oauth_provider(
        &mut self,
        name: OAuthProviderName,
        provider_fn: Box<dyn OAuthProviderFn>,
    ) {
        self.auth.insert_oauth_provider(name, provider_fn);
    }

    pub async fn get_oauth_provider(
        &self,
        provider: &OAuthProviderName,
    ) -> Result<Box<dyn OAuthProvider + Send + Sync>, OAuthProviderError> {
        self.auth.get_oauth_provider(provider).await
    }

    pub async fn get_caller(
        &self,
        rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    ) -> Result<Caller<T>, VContextCallerError> {
        self.get_caller_from_token(self.auth.authn_token(&rqctx).await?.as_ref())
            .await
    }

    pub async fn get_caller_from_token(
        &self,
        auth: Option<&AuthToken>,
    ) -> Result<Caller<T>, VContextCallerError> {
        Ok(match auth {
            Some(token) => {
                self.user
                    .get_caller(&self.builtin_registration_user(), &self.auth, token)
                    .await?
            }
            None => {
                tracing::debug!("No token found in request. Falling back to unauthenticated user");
                self.builtin_unauthenticated_caller()
            }
        })
    }

    #[instrument(skip(self, info), fields(info.external_id))]
    pub async fn register_api_user(
        &self,
        caller: &Caller<T>,
        info: UserInfo,
    ) -> ResourceResult<(ApiUserInfo<T>, ApiUserProvider), ApiError> {
        // Check if we have seen this identity before
        let mut filter = ApiUserProviderFilter::default();
        filter.provider = Some(vec![info.external_id.provider().to_string()]);
        filter.provider_id = Some(vec![info.external_id.id().to_string()]);

        tracing::info!("Check for existing users matching the requested external id");

        let api_user_providers = self
            .user
            .list_api_user_provider(caller, filter, &ListPagination::latest())
            .await
            .inner_err_into()?;

        let (mut mapped_permissions, mut mapped_groups) = self
            .mapping
            .get_mapped_fields(caller, &info)
            .await
            .inner_err_into()?;

        tracing::debug!(?mapped_permissions, "Computed mapping permissions");
        tracing::debug!(?mapped_groups, "Computed mapped groups");

        let user = match api_user_providers.len() {
            0 => {
                tracing::info!(
                    ?mapped_permissions,
                    ?mapped_groups,
                    "Did not find any existing users. Registering a new user."
                );

                let user = self
                    .user
                    .create_api_user(caller, mapped_permissions, mapped_groups)
                    .await
                    .inner_err_into()?;

                let user_provider = self
                    .user
                    .update_api_user_provider(
                        caller,
                        NewApiUserProvider {
                            id: TypedUuid::new_v4(),
                            user_id: user.user.id,
                            emails: info.verified_emails,
                            provider: info.external_id.provider().to_string(),
                            provider_id: info.external_id.id().to_string(),
                            display_names: info
                                .display_name
                                .map(|name| vec![name])
                                .unwrap_or_default(),
                        },
                    )
                    .await
                    .inner_err_into()?;

                Ok((user, user_provider))
            }
            1 => {
                tracing::info!("Found an existing user provider. Ensuring mapped permissions and groups for user.");

                // This branch ensures that there is a 0th indexed item
                let mut provider = api_user_providers.into_iter().nth(0).unwrap();

                // Update the provider with the newest user info
                provider.emails = info.verified_emails;
                provider.display_names =
                    info.display_name.map(|name| vec![name]).unwrap_or_default();

                tracing::info!(?provider.id, "Updating provider for user");

                let provider = self
                    .user
                    .update_api_user_provider(caller, provider.clone().into())
                    .await
                    .inner_err_into()?;

                tracing::info!(?provider.id, ?provider.user_id, "Updating found user permissions and groups");

                // Update the found user to ensure it has at least the mapped permissions and groups
                let user = self
                    .user
                    .get_api_user(caller, &provider.user_id)
                    .await
                    .inner_err_into()?;

                tracing::info!(?user.user.id, "Updating found user permissions and groups");

                let mut update: NewApiUser<T> = user.user.into();
                update.permissions.append(&mut mapped_permissions);
                update.groups.append(&mut mapped_groups);

                let updated_user = self
                    .user
                    .update_api_user(caller, update)
                    .await
                    .inner_err_into()?;

                tracing::info!(?updated_user.user.id, "Updated user permissions and groups");

                Ok((updated_user, provider))
            }
            _ => {
                // If we found more than one provider, then we have encountered an inconsistency in
                // our database.
                tracing::error!(
                    count = api_user_providers.len(),
                    "Found multiple providers for external id"
                );

                resource_error(ApiError::from(StoreError::InvariantFailed(
                    "Multiple providers for external id found".to_string(),
                )))
            }
        };

        user
    }

    pub async fn generate_access_token(
        &self,
        caller: &Caller<T>,
        api_user: &TypedUuid<UserId>,
        api_user_provider: &TypedUuid<UserProviderId>,
        scope: Option<Vec<String>>,
    ) -> ResourceResult<RegisteredAccessToken, ApiError> {
        let claims = self.generate_claims(&api_user, &api_user_provider, scope);
        let token = self
            .user
            .register_access_token(caller, self.jwt_signer(), &api_user, &claims)
            .await
            // TODO: FIXME
            .unwrap();

        tracing::info!(api_user_id = ?api_user, "Generated access token");

        Ok(token)
    }

    pub async fn add_api_user_to_group(
        &self,
        caller: &Caller<T>,
        api_user_id: &TypedUuid<UserId>,
        group_id: &TypedUuid<AccessGroupId>,
    ) -> ResourceResult<ApiUserInfo<T>, StoreError> {
        if caller.any(
            &mut [
                VPermission::ManageGroupMembership(*group_id).into(),
                VPermission::ManageGroupMembershipsAll.into(),
            ]
            .iter(),
        ) {
            // TODO: This needs to be wrapped in a transaction. That requires reworking the way the
            // store traits are handled. Ideally we could have an API that still abstracts away the
            // underlying connection management while allowing for transactions. Possibly something
            // that takes a closure and passes in a connection that implements all of the expected
            // data store traits
            let info = ApiUserStore::get(&*self.storage, api_user_id, false)
                .await
                .optional()?;

            let mut update: NewApiUser<T> = info.user.into();
            update.groups.insert(*group_id);

            Ok(ApiUserStore::upsert(&*self.storage, update).await?)
        } else {
            resource_restricted()
        }
    }

    pub async fn remove_api_user_from_group(
        &self,
        caller: &Caller<T>,
        api_user_id: &TypedUuid<UserId>,
        group_id: &TypedUuid<AccessGroupId>,
    ) -> ResourceResult<ApiUserInfo<T>, StoreError> {
        if caller.any(
            &mut [
                VPermission::ManageGroupMembership(*group_id).into(),
                VPermission::ManageGroupMembershipsAll.into(),
            ]
            .iter(),
        ) {
            // TODO: This needs to be wrapped in a transaction. That requires reworking the way the
            // store traits are handled. Ideally we could have an API that still abstracts away the
            // underlying connection management while allowing for transactions. Possibly something
            // that takes a closure and passes in a connection that implements all of the expected
            // data store traits
            let info = ApiUserStore::get(&*self.storage, api_user_id, false)
                .await
                .optional()?;

            let mut update: NewApiUser<T> = info.user.into();
            update.groups.retain(|id| id != group_id);

            Ok(ApiUserStore::upsert(&*self.storage, update).await?)
        } else {
            resource_restricted()
        }
    }

    pub async fn complete_link_request(
        &self,
        caller: &Caller<T>,
        link_request: LinkRequest,
    ) -> ResourceResult<ApiUserProvider, StoreError> {
        let mut provider = self
            .user
            .get_api_user_provider(
                caller,
                &link_request.source_user_id,
                &link_request.source_provider_id,
            )
            .await?;

        // This check attempts to prevent a stolen link request from being activated
        if caller.can(&VPermission::ManageApiUser(link_request.source_user_id).into()) {
            provider.user_id = link_request.target_user_id;

            tracing::info!(?provider, "Created provider update");

            let source_user_id = link_request.source_user_id;
            let mut update_request: NewLinkRequest = link_request.into();
            update_request.completed_at = Some(Utc::now());
            LinkRequestStore::upsert(&*self.storage, &update_request).await?;

            Ok(
                ApiUserProviderStore::transfer(&*self.storage, provider.into(), source_user_id)
                    .await?,
            )
        } else {
            resource_restricted()
        }
    }
}

#[async_trait]
impl<T> Verifier for VContext<T>
where
    T: VAppPermission,
{
    fn verify(&self, message: &[u8], signature: &[u8]) -> VerificationResult {
        self.auth.verify(message, signature)
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeDelta, Utc};
    use mockall::predicate::eq;
    use newtype_uuid::TypedUuid;
    use std::{collections::BTreeSet, ops::Add, sync::Arc};
    use v_model::{
        permissions::Permissions,
        storage::{
            AccessGroupFilter, ListPagination, MockAccessGroupStore, MockAccessTokenStore,
            MockApiUserStore,
        },
        AccessGroup, AccessToken, AccessTokenId, ApiUser, ApiUserInfo, ApiUserProvider, UserId,
    };

    use crate::{
        authn::{
            jwt::{Claims, Jwt},
            AuthToken,
        },
        context::user::UserContextError,
        permissions::VPermission,
    };

    use super::{
        test_mocks::{mock_context, MockStorage},
        VContext, VContextCallerError,
    };

    async fn create_token(
        ctx: &VContext<VPermission>,
        token_id: TypedUuid<AccessTokenId>,
        user_id: TypedUuid<UserId>,
        scope: Vec<String>,
    ) -> AuthToken {
        let user: ApiUser<VPermission> = ApiUser {
            id: user_id,
            permissions: Permissions::new(),
            groups: BTreeSet::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };

        let provider = ApiUserProvider {
            id: TypedUuid::new_v4(),
            user_id: user_id,
            provider: "test".to_string(),
            provider_id: "test_id".to_string(),
            emails: vec![],
            display_names: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };

        let user_token = ctx
            .sign_jwt(&Claims::new(
                ctx,
                Some(token_id),
                &user.id,
                &provider.id,
                Some(scope),
                Utc::now().add(TimeDelta::try_seconds(300).unwrap()),
            ))
            .await
            .unwrap();

        let jwt = AuthToken::Jwt(Jwt::new(&ctx, &user_token).await.unwrap());

        jwt
    }

    #[tokio::test]
    async fn test_jwt_permissions() {
        let mut storage = MockStorage::new();

        // Initialize a test environment with a user belonging to a group
        let group_id = TypedUuid::new_v4();
        let group_permissions: Permissions<VPermission> = vec![VPermission::CreateGroup].into();
        let group = AccessGroup {
            id: group_id,
            name: "TestGroup".to_string(),
            permissions: group_permissions.clone(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };
        let pagination = ListPagination::unlimited();
        let mut group_store = MockAccessGroupStore::new();
        group_store
            .expect_list()
            .with(
                eq(AccessGroupFilter {
                    id: Some(vec![group_id]),
                    ..Default::default()
                }),
                eq(pagination),
            )
            .returning(move |_, _| Ok(vec![group.clone()]));

        let user_id = TypedUuid::new_v4();
        let user_permissions: Permissions<VPermission> = vec![VPermission::GetMappersAll].into();
        let mut groups = BTreeSet::new();
        groups.insert(group_id);
        let user = ApiUserInfo {
            user: ApiUser {
                id: user_id,
                permissions: user_permissions.clone(),
                groups,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                deleted_at: None,
            },
            email: None,
            providers: vec![],
        };

        let mut user_store = MockApiUserStore::new();
        user_store
            .expect_get()
            .with(eq(user.user.id), eq(false))
            .returning(move |_, _| Ok(Some(user.clone())));

        let mut token_store = MockAccessTokenStore::new();
        let valid_token_id = TypedUuid::new_v4();
        token_store
            .expect_get()
            .with(eq(valid_token_id), eq(false))
            .returning(move |_, _| {
                Ok(Some(AccessToken {
                    id: valid_token_id,
                    user_id: user_id,
                    revoked_at: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                }))
            });
        let invalid_token_id = TypedUuid::new_v4();
        token_store
            .expect_get()
            .with(eq(invalid_token_id), eq(false))
            .returning(move |_, _| Ok(None));

        storage.access_group_store = Some(Arc::new(group_store));
        storage.api_user_store = Some(Arc::new(user_store));
        storage.access_token_store = Some(Arc::new(token_store));

        let ctx = mock_context(Arc::new(storage)).await;

        // Construct a new token for test for the user without any scopes
        let token_with_no_scope = create_token(&ctx, valid_token_id, user_id, vec![]).await;

        // Verify the token
        let permissions = ctx
            .get_caller_from_token(Some(&token_with_no_scope))
            .await
            .unwrap();

        // Ensure the verified token has no permissions
        assert_eq!(Permissions::<VPermission>::new(), permissions.permissions);

        // Construct a new token for test for the user with scopes
        let token_with_read_user_info = create_token(
            &ctx,
            valid_token_id,
            user_id,
            vec![
                "group:info:w".to_string(),
                "mapper:r".to_string(),
                "user:info:r".to_string(),
            ],
        )
        .await;

        // Verify the token
        let permissions = ctx
            .get_caller_from_token(Some(&token_with_read_user_info))
            .await
            .unwrap();

        // Ensure the verified token has permission matching the intersection of the scopes
        // and the users permissions. Notably the user does not have any user permissions
        // and therefore the user:info:r scope confers no permissions
        assert_eq!(
            Permissions::<VPermission>::from(vec![
                VPermission::CreateGroup,
                VPermission::GetMappersAll,
            ]),
            permissions.permissions
        );

        // Construct a new token for test for the user that has been revoked
        let missing_token = create_token(
            &ctx,
            invalid_token_id,
            user_id,
            vec![
                "group:info:w".to_string(),
                "mapper:r".to_string(),
                "user:info:r".to_string(),
            ],
        )
        .await;

        // Verify the token
        let verification = ctx.get_caller_from_token(Some(&missing_token)).await;

        // The token verification should have failed at this point
        assert!(verification.is_err());
        match verification.unwrap_err() {
            VContextCallerError::Caller(UserContextError::InvalidToken) => (),
            other => panic!(
                "Exected to receive UserContextError::InvalidToken error. Instead found {:?}",
                other
            ),
        }
    }
}

#[cfg(test)]
pub(crate) mod test_mocks {
    use async_trait::async_trait;
    use chrono::Utc;
    use newtype_uuid::{GenericUuid, TypedUuid};
    use std::{collections::HashMap, sync::Arc};
    use uuid::Uuid;
    use v_model::{
        permissions::Caller,
        schema_ext::MagicLinkAttemptState,
        storage::{
            AccessGroupStore, AccessTokenStore, ApiKeyStore, ApiUserContactEmailStore,
            ApiUserProviderStore, ApiUserStore, LinkRequestStore, ListPagination,
            LoginAttemptStore, MagicLinkAttemptFilter, MagicLinkAttemptStore, MagicLinkFilter,
            MagicLinkRedirectUriStore, MagicLinkSecretStore, MagicLinkStore, MapperStore,
            MockAccessGroupStore, MockAccessTokenStore, MockApiKeyStore,
            MockApiUserContactEmailStore, MockApiUserProviderStore, MockApiUserStore,
            MockLinkRequestStore, MockLoginAttemptStore, MockMagicLinkAttemptStore,
            MockMagicLinkRedirectUriStore, MockMagicLinkSecretStore, MockMagicLinkStore,
            MockMapperStore, MockOAuthClientRedirectUriStore, MockOAuthClientSecretStore,
            MockOAuthClientStore, OAuthClientRedirectUriStore, OAuthClientSecretStore,
            OAuthClientStore, StoreError,
        },
        AccessGroupId, AccessToken, AccessTokenId, ApiKey, ApiKeyId, ApiUserContactEmail,
        ApiUserProvider, LinkRequestId, LoginAttemptId, MagicLink, MagicLinkAttempt,
        MagicLinkAttemptId, MagicLinkId, MagicLinkRedirectUri, MagicLinkRedirectUriId,
        MagicLinkSecret, MagicLinkSecretId, MapperId, NewAccessGroup, NewAccessToken, NewApiKey,
        NewApiUser, NewApiUserContactEmail, NewApiUserProvider, NewLoginAttempt, NewMagicLink,
        NewMagicLinkAttempt, NewMagicLinkRedirectUri, NewMagicLinkSecret, NewMapper, OAuthClientId,
        OAuthRedirectUriId, OAuthSecretId, UserContactEmailId, UserId, UserProviderId,
    };

    use crate::{
        config::JwtConfig,
        endpoints::login::oauth::{google::GoogleOAuthProvider, OAuthProviderName},
        mapper::DefaultMappingEngine,
        permissions::VPermission,
        util::tests::{mock_key, MockKey},
    };

    use super::VContext;

    // Construct a mock context that can be used in tests
    pub async fn mock_context(storage: Arc<MockStorage>) -> VContext<VPermission> {
        let MockKey { signer, verifier } = mock_key("test");
        let mut ctx = VContext::new(
            "".to_string(),
            storage,
            JwtConfig::default(),
            vec![
                // We are in the context of a test and do not care about the key leaking
                signer, verifier,
            ],
        )
        .await
        .unwrap();

        let mapping_engine = Arc::new(DefaultMappingEngine::new(
            ctx.builtin_registration_user(),
            ctx.group.clone(),
        ));
        ctx.mapping.set_engine(Some(mapping_engine));

        ctx.auth.insert_oauth_provider(
            OAuthProviderName::Google,
            Box::new(move || {
                Box::new(GoogleOAuthProvider::new(
                    "google_device_client_id".to_string(),
                    "google_device_client_secret".to_string().into(),
                    "google_web_client_id".to_string(),
                    "google_web_client_secret".to_string().into(),
                    None,
                ))
            }),
        );

        ctx
    }

    // Construct a mock storage engine that can be wrapped in an ApiContext for testing
    pub struct MockStorage {
        pub api_user_store: Option<Arc<MockApiUserStore<VPermission>>>,
        pub api_user_token_store: Option<Arc<MockApiKeyStore<VPermission>>>,
        pub api_user_contact_email_store: Option<Arc<MockApiUserContactEmailStore>>,
        pub api_user_provider_store: Option<Arc<MockApiUserProviderStore>>,
        pub access_token_store: Option<Arc<MockAccessTokenStore>>,
        pub login_attempt_store: Option<Arc<MockLoginAttemptStore>>,
        pub oauth_client_store: Option<Arc<MockOAuthClientStore>>,
        pub oauth_client_secret_store: Option<Arc<MockOAuthClientSecretStore>>,
        pub oauth_client_redirect_uri_store: Option<Arc<MockOAuthClientRedirectUriStore>>,
        pub access_group_store: Option<Arc<MockAccessGroupStore<VPermission>>>,
        pub mapper_store: Option<Arc<MockMapperStore>>,
        pub link_request_store: Option<Arc<MockLinkRequestStore>>,
        pub magic_link_store: Option<Arc<MockMagicLinkStore>>,
        pub magic_link_secret_store: Option<Arc<MockMagicLinkSecretStore>>,
        pub magic_link_redirect_store: Option<Arc<MockMagicLinkRedirectUriStore>>,
        pub magic_link_attempt_store: Option<Arc<MockMagicLinkAttemptStore>>,
    }

    impl MockStorage {
        pub fn new() -> Self {
            Self {
                api_user_store: None,
                api_user_token_store: None,
                api_user_contact_email_store: None,
                api_user_provider_store: None,
                access_token_store: None,
                login_attempt_store: None,
                oauth_client_store: None,
                oauth_client_secret_store: None,
                oauth_client_redirect_uri_store: None,
                access_group_store: None,
                mapper_store: None,
                link_request_store: None,
                magic_link_store: None,
                magic_link_secret_store: None,
                magic_link_redirect_store: None,
                magic_link_attempt_store: None,
            }
        }
    }

    #[async_trait]
    impl ApiUserStore<VPermission> for MockStorage {
        async fn get(
            &self,
            id: &TypedUuid<UserId>,
            deleted: bool,
        ) -> Result<Option<v_model::ApiUserInfo<VPermission>>, v_model::storage::StoreError>
        {
            self.api_user_store.as_ref().unwrap().get(id, deleted).await
        }

        async fn list(
            &self,
            filter: v_model::storage::ApiUserFilter,
            pagination: &ListPagination,
        ) -> Result<Vec<v_model::ApiUserInfo<VPermission>>, v_model::storage::StoreError> {
            self.api_user_store
                .as_ref()
                .unwrap()
                .list(filter, pagination)
                .await
        }

        async fn upsert(
            &self,
            api_user: NewApiUser<VPermission>,
        ) -> Result<v_model::ApiUserInfo<VPermission>, v_model::storage::StoreError> {
            self.api_user_store.as_ref().unwrap().upsert(api_user).await
        }

        async fn delete(
            &self,
            id: &TypedUuid<UserId>,
        ) -> Result<Option<v_model::ApiUserInfo<VPermission>>, v_model::storage::StoreError>
        {
            self.api_user_store.as_ref().unwrap().delete(id).await
        }
    }

    #[async_trait]
    impl ApiKeyStore<VPermission> for MockStorage {
        async fn get(
            &self,
            id: &TypedUuid<ApiKeyId>,
            deleted: bool,
        ) -> Result<Option<ApiKey<VPermission>>, v_model::storage::StoreError> {
            self.api_user_token_store
                .as_ref()
                .unwrap()
                .get(id, deleted)
                .await
        }

        async fn list(
            &self,
            filter: v_model::storage::ApiKeyFilter,
            pagination: &ListPagination,
        ) -> Result<Vec<ApiKey<VPermission>>, v_model::storage::StoreError> {
            self.api_user_token_store
                .as_ref()
                .unwrap()
                .list(filter, pagination)
                .await
        }

        async fn upsert(
            &self,
            token: NewApiKey<VPermission>,
        ) -> Result<ApiKey<VPermission>, v_model::storage::StoreError> {
            self.api_user_token_store
                .as_ref()
                .unwrap()
                .upsert(token)
                .await
        }

        async fn delete(
            &self,
            id: &TypedUuid<ApiKeyId>,
        ) -> Result<Option<ApiKey<VPermission>>, v_model::storage::StoreError> {
            self.api_user_token_store.as_ref().unwrap().delete(id).await
        }
    }

    #[async_trait]
    impl ApiUserContactEmailStore for MockStorage {
        async fn get(
            &self,
            id: &TypedUuid<UserContactEmailId>,
            deleted: bool,
        ) -> Result<Option<ApiUserContactEmail>, v_model::storage::StoreError> {
            self.api_user_contact_email_store
                .as_ref()
                .unwrap()
                .get(id, deleted)
                .await
        }

        async fn list(
            &self,
            filter: v_model::storage::ApiUserContactEmailFilter,
            pagination: &ListPagination,
        ) -> Result<Vec<ApiUserContactEmail>, v_model::storage::StoreError> {
            self.api_user_contact_email_store
                .as_ref()
                .unwrap()
                .list(filter, pagination)
                .await
        }

        async fn upsert(
            &self,
            provider: NewApiUserContactEmail,
        ) -> Result<ApiUserContactEmail, v_model::storage::StoreError> {
            self.api_user_contact_email_store
                .as_ref()
                .unwrap()
                .upsert(provider)
                .await
        }

        async fn delete(
            &self,
            id: &TypedUuid<UserContactEmailId>,
        ) -> Result<Option<ApiUserContactEmail>, v_model::storage::StoreError> {
            self.api_user_contact_email_store
                .as_ref()
                .unwrap()
                .delete(id)
                .await
        }
    }

    #[async_trait]
    impl ApiUserProviderStore for MockStorage {
        async fn get(
            &self,
            id: &TypedUuid<UserProviderId>,
            deleted: bool,
        ) -> Result<Option<ApiUserProvider>, v_model::storage::StoreError> {
            self.api_user_provider_store
                .as_ref()
                .unwrap()
                .get(id, deleted)
                .await
        }

        async fn list(
            &self,
            filter: v_model::storage::ApiUserProviderFilter,
            pagination: &ListPagination,
        ) -> Result<Vec<ApiUserProvider>, v_model::storage::StoreError> {
            self.api_user_provider_store
                .as_ref()
                .unwrap()
                .list(filter, pagination)
                .await
        }

        async fn upsert(
            &self,
            provider: NewApiUserProvider,
        ) -> Result<ApiUserProvider, v_model::storage::StoreError> {
            self.api_user_provider_store
                .as_ref()
                .unwrap()
                .upsert(provider)
                .await
        }

        async fn transfer(
            &self,
            provider: NewApiUserProvider,
            current_api_user_id: TypedUuid<UserId>,
        ) -> Result<ApiUserProvider, v_model::storage::StoreError> {
            self.api_user_provider_store
                .as_ref()
                .unwrap()
                .transfer(provider, current_api_user_id)
                .await
        }

        async fn delete(
            &self,
            id: &TypedUuid<UserProviderId>,
        ) -> Result<Option<ApiUserProvider>, v_model::storage::StoreError> {
            self.api_user_provider_store
                .as_ref()
                .unwrap()
                .delete(id)
                .await
        }
    }

    #[async_trait]
    impl AccessTokenStore for MockStorage {
        async fn get(
            &self,
            id: &TypedUuid<AccessTokenId>,
            revoked: bool,
        ) -> Result<Option<v_model::AccessToken>, v_model::storage::StoreError> {
            self.access_token_store
                .as_ref()
                .unwrap()
                .get(id, revoked)
                .await
        }

        async fn list(
            &self,
            filter: v_model::storage::AccessTokenFilter,
            pagination: &ListPagination,
        ) -> Result<Vec<v_model::AccessToken>, v_model::storage::StoreError> {
            self.access_token_store
                .as_ref()
                .unwrap()
                .list(filter, pagination)
                .await
        }

        async fn upsert(
            &self,
            token: NewAccessToken,
        ) -> Result<v_model::AccessToken, v_model::storage::StoreError> {
            self.access_token_store
                .as_ref()
                .unwrap()
                .upsert(token)
                .await
        }
    }

    #[async_trait]
    impl LoginAttemptStore for MockStorage {
        async fn get(
            &self,
            id: &TypedUuid<LoginAttemptId>,
        ) -> Result<Option<v_model::LoginAttempt>, v_model::storage::StoreError> {
            self.login_attempt_store.as_ref().unwrap().get(id).await
        }

        async fn list(
            &self,
            filter: v_model::storage::LoginAttemptFilter,
            pagination: &ListPagination,
        ) -> Result<Vec<v_model::LoginAttempt>, v_model::storage::StoreError> {
            self.login_attempt_store
                .as_ref()
                .unwrap()
                .list(filter, pagination)
                .await
        }

        async fn upsert(
            &self,
            attempt: NewLoginAttempt,
        ) -> Result<v_model::LoginAttempt, v_model::storage::StoreError> {
            self.login_attempt_store
                .as_ref()
                .unwrap()
                .upsert(attempt)
                .await
        }
    }

    #[async_trait]
    impl OAuthClientStore for MockStorage {
        async fn get(
            &self,
            id: &TypedUuid<OAuthClientId>,
            deleted: bool,
        ) -> Result<Option<v_model::OAuthClient>, v_model::storage::StoreError> {
            self.oauth_client_store
                .as_ref()
                .unwrap()
                .get(id, deleted)
                .await
        }

        async fn list(
            &self,
            filter: v_model::storage::OAuthClientFilter,
            pagination: &ListPagination,
        ) -> Result<Vec<v_model::OAuthClient>, v_model::storage::StoreError> {
            self.oauth_client_store
                .as_ref()
                .unwrap()
                .list(filter, pagination)
                .await
        }

        async fn upsert(
            &self,
            client: v_model::NewOAuthClient,
        ) -> Result<v_model::OAuthClient, v_model::storage::StoreError> {
            self.oauth_client_store
                .as_ref()
                .unwrap()
                .upsert(client)
                .await
        }

        async fn delete(
            &self,
            id: &TypedUuid<OAuthClientId>,
        ) -> Result<Option<v_model::OAuthClient>, v_model::storage::StoreError> {
            self.oauth_client_store.as_ref().unwrap().delete(id).await
        }
    }

    #[async_trait]
    impl OAuthClientSecretStore for MockStorage {
        async fn upsert(
            &self,
            secret: v_model::NewOAuthClientSecret,
        ) -> Result<v_model::OAuthClientSecret, v_model::storage::StoreError> {
            self.oauth_client_secret_store
                .as_ref()
                .unwrap()
                .upsert(secret)
                .await
        }

        async fn delete(
            &self,
            id: &TypedUuid<OAuthSecretId>,
        ) -> Result<Option<v_model::OAuthClientSecret>, v_model::storage::StoreError> {
            self.oauth_client_secret_store
                .as_ref()
                .unwrap()
                .delete(id)
                .await
        }
    }

    #[async_trait]
    impl OAuthClientRedirectUriStore for MockStorage {
        async fn upsert(
            &self,
            redirect_uri: v_model::NewOAuthClientRedirectUri,
        ) -> Result<v_model::OAuthClientRedirectUri, v_model::storage::StoreError> {
            self.oauth_client_redirect_uri_store
                .as_ref()
                .unwrap()
                .upsert(redirect_uri)
                .await
        }

        async fn delete(
            &self,
            id: &TypedUuid<OAuthRedirectUriId>,
        ) -> Result<Option<v_model::OAuthClientRedirectUri>, v_model::storage::StoreError> {
            self.oauth_client_redirect_uri_store
                .as_ref()
                .unwrap()
                .delete(id)
                .await
        }
    }

    #[async_trait]
    impl AccessGroupStore<VPermission> for MockStorage {
        async fn get(
            &self,
            id: &TypedUuid<AccessGroupId>,
            deleted: bool,
        ) -> Result<Option<v_model::AccessGroup<VPermission>>, v_model::storage::StoreError>
        {
            self.access_group_store
                .as_ref()
                .unwrap()
                .get(id, deleted)
                .await
        }

        async fn list(
            &self,
            filter: v_model::storage::AccessGroupFilter,
            pagination: &ListPagination,
        ) -> Result<Vec<v_model::AccessGroup<VPermission>>, v_model::storage::StoreError> {
            self.access_group_store
                .as_ref()
                .unwrap()
                .list(filter, pagination)
                .await
        }

        async fn upsert(
            &self,
            group: &NewAccessGroup<VPermission>,
        ) -> Result<v_model::AccessGroup<VPermission>, v_model::storage::StoreError> {
            self.access_group_store
                .as_ref()
                .unwrap()
                .upsert(group)
                .await
        }

        async fn delete(
            &self,
            id: &TypedUuid<AccessGroupId>,
        ) -> Result<Option<v_model::AccessGroup<VPermission>>, v_model::storage::StoreError>
        {
            self.access_group_store.as_ref().unwrap().delete(id).await
        }
    }

    #[async_trait]
    impl MapperStore for MockStorage {
        async fn get(
            &self,
            id: &TypedUuid<MapperId>,
            used: bool,
            deleted: bool,
        ) -> Result<Option<v_model::Mapper>, v_model::storage::StoreError> {
            self.mapper_store
                .as_ref()
                .unwrap()
                .get(id, used, deleted)
                .await
        }

        async fn list(
            &self,
            filter: v_model::storage::MapperFilter,
            pagination: &ListPagination,
        ) -> Result<Vec<v_model::Mapper>, v_model::storage::StoreError> {
            self.mapper_store
                .as_ref()
                .unwrap()
                .list(filter, pagination)
                .await
        }

        async fn upsert(
            &self,
            new_mapper: &NewMapper,
        ) -> Result<v_model::Mapper, v_model::storage::StoreError> {
            self.mapper_store.as_ref().unwrap().upsert(new_mapper).await
        }

        async fn delete(
            &self,
            id: &TypedUuid<MapperId>,
        ) -> Result<Option<v_model::Mapper>, v_model::storage::StoreError> {
            self.mapper_store.as_ref().unwrap().delete(id).await
        }
    }

    #[async_trait]
    impl LinkRequestStore for MockStorage {
        async fn get(
            &self,
            id: &TypedUuid<LinkRequestId>,
            expired: bool,
            completed: bool,
        ) -> Result<Option<v_model::LinkRequest>, v_model::storage::StoreError> {
            self.link_request_store
                .as_ref()
                .unwrap()
                .get(id, expired, completed)
                .await
        }

        async fn list(
            &self,
            filter: v_model::storage::LinkRequestFilter,
            pagination: &ListPagination,
        ) -> Result<Vec<v_model::LinkRequest>, v_model::storage::StoreError> {
            self.link_request_store
                .as_ref()
                .unwrap()
                .list(filter, pagination)
                .await
        }

        async fn upsert(
            &self,
            request: &v_model::NewLinkRequest,
        ) -> Result<v_model::LinkRequest, v_model::storage::StoreError> {
            self.link_request_store
                .as_ref()
                .unwrap()
                .upsert(request)
                .await
        }
    }

    #[async_trait]
    impl MagicLinkStore for MockStorage {
        async fn get(
            &self,
            id: &TypedUuid<MagicLinkId>,
            deleted: bool,
        ) -> Result<Option<MagicLink>, StoreError> {
            self.magic_link_store
                .as_ref()
                .unwrap()
                .get(id, deleted)
                .await
        }
        async fn list(
            &self,
            filter: MagicLinkFilter,
            pagination: &ListPagination,
        ) -> Result<Vec<MagicLink>, StoreError> {
            self.magic_link_store
                .as_ref()
                .unwrap()
                .list(filter, pagination)
                .await
        }
        async fn upsert(&self, client: NewMagicLink) -> Result<MagicLink, StoreError> {
            self.magic_link_store.as_ref().unwrap().upsert(client).await
        }
        async fn delete(
            &self,
            id: &TypedUuid<MagicLinkId>,
        ) -> Result<Option<MagicLink>, StoreError> {
            self.magic_link_store.as_ref().unwrap().delete(id).await
        }
    }

    #[async_trait]
    impl MagicLinkRedirectUriStore for MockStorage {
        async fn upsert(
            &self,
            redirect_uri: NewMagicLinkRedirectUri,
        ) -> Result<MagicLinkRedirectUri, StoreError> {
            self.magic_link_redirect_store
                .as_ref()
                .unwrap()
                .upsert(redirect_uri)
                .await
        }
        async fn delete(
            &self,
            id: &TypedUuid<MagicLinkRedirectUriId>,
        ) -> Result<Option<MagicLinkRedirectUri>, StoreError> {
            self.magic_link_redirect_store
                .as_ref()
                .unwrap()
                .delete(id)
                .await
        }
    }

    #[async_trait]
    impl MagicLinkSecretStore for MockStorage {
        async fn upsert(&self, secret: NewMagicLinkSecret) -> Result<MagicLinkSecret, StoreError> {
            self.magic_link_secret_store
                .as_ref()
                .unwrap()
                .upsert(secret)
                .await
        }
        async fn delete(
            &self,
            id: &TypedUuid<MagicLinkSecretId>,
        ) -> Result<Option<MagicLinkSecret>, StoreError> {
            self.magic_link_secret_store
                .as_ref()
                .unwrap()
                .delete(id)
                .await
        }
    }

    #[async_trait]
    impl MagicLinkAttemptStore for MockStorage {
        async fn get(
            &self,
            id: &TypedUuid<MagicLinkAttemptId>,
        ) -> Result<Option<MagicLinkAttempt>, StoreError> {
            self.magic_link_attempt_store
                .as_ref()
                .unwrap()
                .get(id)
                .await
        }
        async fn list(
            &self,
            filter: MagicLinkAttemptFilter,
            pagination: &ListPagination,
        ) -> Result<Vec<MagicLinkAttempt>, StoreError> {
            self.magic_link_attempt_store
                .as_ref()
                .unwrap()
                .list(filter, pagination)
                .await
        }
        async fn upsert(
            &self,
            attempt: NewMagicLinkAttempt,
        ) -> Result<MagicLinkAttempt, StoreError> {
            self.magic_link_attempt_store
                .as_ref()
                .unwrap()
                .upsert(attempt)
                .await
        }
        async fn transition(
            &self,
            id: &TypedUuid<MagicLinkAttemptId>,
            signature: &str,
            from: MagicLinkAttemptState,
            to: MagicLinkAttemptState,
        ) -> Result<Option<MagicLinkAttempt>, StoreError> {
            self.magic_link_attempt_store
                .as_ref()
                .unwrap()
                .transition(id, signature, from, to)
                .await
        }
    }

    #[tokio::test]
    async fn test_generate_access_token_calls_store() {
        let mut storage = MockStorage::new();

        // Test data
        let api_user_id = TypedUuid::new_v4();
        let api_user_provider_id = TypedUuid::new_v4();

        // Setup the mock expectation for upsert
        let mut access_token_store = MockAccessTokenStore::new();
        access_token_store
            .expect_upsert()
            .withf(move |token| token.user_id == api_user_id && token.id != TypedUuid::default())
            .times(1)
            .returning(move |token| {
                Ok(AccessToken {
                    id: token.id,
                    user_id: token.user_id,
                    revoked_at: None,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                })
            });
        storage.access_token_store = Some(Arc::new(access_token_store));

        let ctx = mock_context(Arc::new(storage)).await;

        // Call the function
        let result = ctx
            .generate_access_token(
                &Caller {
                    id: TypedUuid::from_untyped_uuid(Uuid::new_v4()),
                    permissions: vec![VPermission::CreateAccessToken].into(),
                    extensions: HashMap::default(),
                },
                &api_user_id,
                &api_user_provider_id,
                None,
            )
            .await;

        // Verify the call succeeded
        assert!(result.is_ok());
    }
}
