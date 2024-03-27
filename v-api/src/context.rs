// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{DateTime, TimeDelta, Utc};
use dropshot::{HttpError, RequestContext, ServerContext};
use http::StatusCode;
use jsonwebtoken::jwk::JwkSet;
use newtype_uuid::{GenericUuid, TypedUuid};
use oauth2::CsrfToken;
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Debug,
    ops::Add,
    sync::Arc,
};
use thiserror::Error;
use tracing::{info_span, instrument, Instrument};
use uuid::Uuid;
use v_model::{
    permissions::{
        AsScopeInternal, Caller, Permission, PermissionError, PermissionStorageInternal,
        Permissions,
    },
    schema_ext::LoginAttemptState,
    storage::{
        AccessGroupFilter, AccessGroupStore, AccessTokenStore, ApiKeyFilter, ApiKeyStore,
        ApiUserFilter, ApiUserProviderFilter, ApiUserProviderStore, ApiUserStore, LinkRequestStore,
        ListPagination, LoginAttemptFilter, LoginAttemptStore, MapperFilter, MapperStore,
        OAuthClientFilter, OAuthClientRedirectUriStore, OAuthClientSecretStore, OAuthClientStore,
        StoreError,
    },
    AccessGroup, AccessGroupId, AccessToken, ApiKey, ApiKeyId, ApiUser, ApiUserProvider,
    InvalidValueError, LinkRequest, LinkRequestId, LoginAttempt, LoginAttemptId, Mapper, MapperId,
    NewAccessGroup, NewAccessToken, NewApiKey, NewApiUser, NewApiUserProvider, NewLinkRequest,
    NewLoginAttempt, NewMapper, NewOAuthClient, NewOAuthClientRedirectUri, NewOAuthClientSecret,
    OAuthClient, OAuthClientId, OAuthClientRedirectUri, OAuthClientSecret, OAuthRedirectUriId,
    OAuthSecretId, UserId, UserProviderId,
};

use crate::{
    authn::{
        jwt::{Claims, JwtSigner, JwtSignerError},
        key::{RawApiKey, SignedApiKey},
        AuthError, AuthToken, Signer,
    },
    config::{AsymmetricKey, JwtConfig},
    endpoints::login::{
        oauth::{
            ClientType, OAuthProvider, OAuthProviderError, OAuthProviderFn, OAuthProviderName,
        },
        UserInfo,
    },
    error::{ApiError, AppError},
    mapper::{MapperRule, Mapping},
    permissions::{VAppPermission, VPermission},
    util::response::{
        bad_request, client_error, internal_error, resource_error, resource_restricted,
        ResourceError, ResourceResult, ToResourceResult, ToResourceResultOpt,
    },
};

static UNLIMITED: i64 = 9999999;

pub trait VApiStorage<P: Send + Sync>:
    ApiUserStore<P>
    + ApiKeyStore<P>
    + ApiUserProviderStore
    + AccessTokenStore
    + LoginAttemptStore
    + OAuthClientStore
    + OAuthClientSecretStore
    + OAuthClientRedirectUriStore
    + AccessGroupStore<P>
    + MapperStore
    + LinkRequestStore
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
        + ApiUserProviderStore
        + AccessTokenStore
        + LoginAttemptStore
        + OAuthClientStore
        + OAuthClientSecretStore
        + OAuthClientRedirectUriStore
        + AccessGroupStore<P>
        + MapperStore
        + LinkRequestStore
        + Send
        + Sync
        + 'static,
{
}

pub struct VContext<T> {
    public_url: String,
    storage: Arc<dyn VApiStorage<T>>,
    unauthenticated_caller: Caller<T>,
    registration_caller: Caller<T>,
    jwt: JwtContext,
    secrets: SecretContext,
    oauth_providers: HashMap<OAuthProviderName, Box<dyn OAuthProviderFn>>,
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
    async fn as_ctx(&self) -> Result<(&VContext<T>, Caller<T>), VContextCallerError>;
}

#[derive(Debug, Error)]
pub enum VContextCallerError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Caller(#[from] CallerError),
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
        let auth = ctx.authn_token(&self).await?;
        let caller = ctx.get_caller(auth.as_ref()).await?;
        Ok((ctx, caller))
    }
}

pub struct JwtContext {
    pub default_expiration: i64,
    pub signers: Vec<JwtSigner>,
    pub jwks: JwkSet,
}

pub struct SecretContext {
    pub signer: Arc<dyn Signer>,
}

pub struct RegisteredAccessToken {
    pub access_token: AccessToken,
    pub signed_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum CallerError {
    #[error("Failed to authenticate caller")]
    FailedToAuthenticate,
    #[error("Supplied API key is invalid")]
    InvalidKey,
    #[error("Invalid scope: {0}")]
    Scope(#[from] PermissionError),
    #[error("Inner storage failure: {0}")]
    Storage(#[from] StoreError),
}

impl From<CallerError> for HttpError {
    fn from(error: CallerError) -> Self {
        tracing::info!(?error, "Failed to authenticate caller");

        match error {
            CallerError::FailedToAuthenticate => {
                client_error(StatusCode::UNAUTHORIZED, "Failed to authenticate")
            }
            CallerError::InvalidKey => {
                client_error(StatusCode::UNAUTHORIZED, "Failed to authenticate")
            }
            CallerError::Scope(_) => bad_request("Invalid scope"),
            CallerError::Storage(_) => internal_error("Internal storage failed"),
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

#[derive(Debug)]
enum BasePermissions<T: Permission> {
    Full,
    Restricted(Permissions<T>),
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
        let mut jwt_signers = vec![];

        for key in &keys {
            jwt_signers.push(JwtSigner::new(&key).await.unwrap())
        }

        Ok(Self {
            public_url,
            storage,

            unauthenticated_caller: Caller {
                id: "00000000-0000-4000-8000-000000000000".parse().unwrap(),
                permissions: vec![].into(),
            },
            registration_caller: Caller {
                id: "00000000-0000-4000-8000-000000000001".parse().unwrap(),
                permissions: vec![
                    VPermission::CreateApiUser.into(),
                    VPermission::GetApiUsersAll.into(),
                    VPermission::ManageApiUsersAll.into(),
                    VPermission::CreateGroup.into(),
                    VPermission::GetGroupsAll.into(),
                    VPermission::CreateMapper.into(),
                    VPermission::GetMappersAll.into(),
                    VPermission::GetOAuthClientsAll.into(),
                    VPermission::CreateAccessToken.into(),
                ]
                .into(),
            },
            jwt: JwtContext {
                default_expiration: jwt.default_expiration,
                jwks: JwkSet {
                    keys: jwt_signers.iter().map(|k| k.jwk()).cloned().collect(),
                },
                signers: jwt_signers,
            },
            secrets: SecretContext {
                signer: keys[0].as_signer().await?,
            },
            oauth_providers: HashMap::new(),
        })
    }

    pub fn device_client(&self) -> ClientType {
        ClientType::Device
    }

    pub fn web_client(&self) -> ClientType {
        ClientType::Web {
            prefix: self.public_url.to_string(),
        }
    }

    pub fn set_storage(&mut self, storage: Arc<dyn VApiStorage<T>>) {
        self.storage = storage;
    }

    pub async fn authn_token(
        &self,
        rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    ) -> Result<Option<AuthToken>, AuthError> {
        match AuthToken::extract(rqctx).await {
            Ok(token) => Ok(Some(token)),
            Err(err) => match err {
                AuthError::NoToken => Ok(None),
                other => Err(other),
            },
        }
    }

    pub fn default_jwt_expiration(&self) -> i64 {
        self.jwt.default_expiration
    }

    pub async fn jwks(&self) -> &JwkSet {
        &self.jwt.jwks
    }

    pub async fn sign_jwt(&self, claims: &Claims) -> Result<String, JwtSignerError> {
        let signer = self.jwt.signers.first().unwrap();
        signer.sign(claims).await
    }

    pub fn signer(&self) -> &dyn Signer {
        &*self.secrets.signer
    }

    pub fn public_url(&self) -> &str {
        &self.public_url
    }

    pub fn with_public_url(&mut self, public_url: &str) -> &mut Self {
        self.public_url = public_url.to_string();
        self
    }

    #[instrument(skip(self, auth))]
    pub async fn get_caller(&self, auth: Option<&AuthToken>) -> Result<Caller<T>, CallerError> {
        match auth {
            Some(token) => {
                let (api_user_id, base_permissions) = self.get_base_permissions(&token).await?;

                match self
                    .get_api_user(&self.builtin_registration_user(), &api_user_id)
                    .await
                {
                    ResourceResult::Ok(user) => {
                        // The permissions for the caller is the intersection of the user's permissions and the tokens permissions
                        let user_permissions = self.get_user_permissions(&user).await?;

                        let combined_permissions = match &base_permissions {
                            BasePermissions::Full => user_permissions.clone(),
                            BasePermissions::Restricted(permissions) => {
                                let token_permissions = <T as PermissionStorageInternal>::expand(
                                    permissions,
                                    &user.id,
                                    Some(&user_permissions),
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
                        };

                        tracing::info!(?caller.id, "Resolved caller");
                        tracing::debug!(?caller.permissions, "Caller permissions");

                        Ok(caller)
                    }
                    Err(ResourceError::DoesNotExist) => {
                        tracing::error!("User for verified token does not exist");
                        Err(CallerError::FailedToAuthenticate)
                    }
                    Err(ResourceError::Restricted) => {
                        tracing::error!("Built in user did not have permission to retrieve caller");
                        Err(CallerError::FailedToAuthenticate)
                    }
                    Err(ResourceError::InternalError(err)) => {
                        tracing::error!("Failed to lookup caller");
                        Err(CallerError::Storage(err))
                    }
                }
            }
            None => Ok(self.builtin_unauthenticated_caller()),
        }
    }

    pub fn builtin_unauthenticated_caller(&self) -> Caller<T> {
        Caller {
            id: self.unauthenticated_caller.id,
            permissions: self
                .unauthenticated_caller
                .clone()
                .permissions
                .into_iter()
                .map(|p| p.into())
                .collect::<Permissions<T>>(),
        }
    }

    pub fn builtin_registration_user(&self) -> Caller<T> {
        Caller {
            id: self.registration_caller.id,
            permissions: self
                .registration_caller
                .clone()
                .permissions
                .into_iter()
                .map(|p| p.into())
                .collect::<Permissions<T>>(),
        }
    }

    async fn get_base_permissions(
        &self,
        auth: &AuthToken,
    ) -> Result<(TypedUuid<UserId>, BasePermissions<T>), CallerError> {
        Ok(match auth {
            AuthToken::ApiKey(api_key) => {
                async {
                    tracing::debug!("Attempt to authenticate");

                    let id = TypedUuid::from_untyped_uuid(Uuid::from_slice(api_key.id()).map_err(|err| {
                        tracing::info!(?err, slice = ?api_key.id(), "Failed to parse id from API key");
                        CallerError::InvalidKey
                    })?);

                    let mut key = ApiKeyStore::list(
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
                    .await?;

                    if let Some(key) = key.pop() {
                        if let Err(err) =
                            api_key.verify(&*self.secrets.signer, key.key_signature.as_bytes())
                        {
                            tracing::debug!(?err, "Failed to verify api key");
                            Err(CallerError::FailedToAuthenticate)
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
                        Err(CallerError::FailedToAuthenticate)
                    }
                }
                .instrument(info_span!("Test api key"))
                .await
            }
            AuthToken::Jwt(jwt) => {
                // AuthnToken::Jwt can only be generated from a verified JWT
                let permissions = match &jwt.claims.scp {
                    Some(scp) => BasePermissions::Restricted(<T as AsScopeInternal>::from_scope(scp.iter())),
                    None => BasePermissions::Full,
                };
                Ok((jwt.claims.sub, permissions))
            }
        }?)
    }

    #[instrument(skip(self), fields(user_id = ?user.id, groups = ?user.groups))]
    async fn get_user_permissions(&self, user: &ApiUser<T>) -> Result<Permissions<T>, StoreError> {
        let mut group_permissions = self.get_user_group_permissions(&user).await?;
        let mut permissions = user.permissions.clone();
        permissions.append(&mut group_permissions);

        Ok(permissions)
    }

    async fn get_user_group_permissions(
        &self,
        user: &ApiUser<T>,
    ) -> Result<Permissions<T>, StoreError> {
        tracing::trace!("Expanding groups into permissions");

        let groups = AccessGroupStore::list(
            &*self.storage,
            AccessGroupFilter {
                id: Some(user.groups.iter().copied().collect()),
                ..Default::default()
            },
            &ListPagination::default().limit(UNLIMITED),
        )
        .await?;

        tracing::trace!(?groups, "Found groups to map to permissions");

        let permissions = groups
            .into_iter()
            .fold(Permissions::new(), |mut aggregate, group| {
                let mut expanded = <T as PermissionStorageInternal>::expand(&group.permissions, &user.id, Some(&user.permissions));

                tracing::trace!(group_id = ?group.id, group_name = ?group.name, permissions = ?expanded, "Transformed group into permission set");
                aggregate.append(&mut expanded);

                aggregate
            });

        Ok(permissions)
    }

    pub async fn is_empty(&self) -> Result<bool, StoreError> {
        let mut user_filter = ApiUserFilter::default();
        user_filter.deleted = true;

        let users =
            ApiUserStore::list(&*self.storage, user_filter, &ListPagination::latest()).await?;

        let mut token_filter = ApiKeyFilter::default();
        token_filter.deleted = true;

        let tokens =
            ApiKeyStore::list(&*self.storage, token_filter, &ListPagination::latest()).await?;

        Ok(users.len() == 0 && tokens.len() == 0)
    }

    pub fn insert_oauth_provider(
        &mut self,
        name: OAuthProviderName,
        provider_fn: Box<dyn OAuthProviderFn>,
    ) {
        self.oauth_providers.insert(name, provider_fn);
    }

    pub async fn get_oauth_provider(
        &self,
        provider: &OAuthProviderName,
    ) -> Result<Box<dyn OAuthProvider + Send + Sync>, OAuthProviderError> {
        self.oauth_providers
            .get(provider)
            .map(|factory| (*factory)())
            .ok_or(OAuthProviderError::FailToCreateInvalidProvider)
    }

    // Login Operations

    #[instrument(skip(self, info), fields(info.external_id))]
    pub async fn register_api_user(
        &self,
        caller: &Caller<T>,
        info: UserInfo,
    ) -> ResourceResult<(ApiUser<T>, ApiUserProvider), ApiError> {
        // Check if we have seen this identity before
        let mut filter = ApiUserProviderFilter::default();
        filter.provider = Some(vec![info.external_id.provider().to_string()]);
        filter.provider_id = Some(vec![info.external_id.id().to_string()]);

        tracing::info!("Check for existing users matching the requested external id");

        let api_user_providers = self
            .list_api_user_provider(caller, filter, &ListPagination::latest())
            .await
            .map_err(|err| ApiError::from(err))
            .to_resource_result()?;

        let (mut mapped_permissions, mut mapped_groups) = self
            .get_mapped_fields(caller, &info)
            .await
            .map_err(|err| ApiError::from(err))
            .to_resource_result()?;

        match api_user_providers.len() {
            0 => {
                tracing::info!(
                    ?mapped_permissions,
                    ?mapped_groups,
                    "Did not find any existing users. Registering a new user."
                );

                let user = self
                    .create_api_user(caller, mapped_permissions, mapped_groups)
                    .await
                    .map_err(|err| ApiError::from(err))
                    .to_resource_result()?;

                let user_provider = self
                    .update_api_user_provider(
                        caller,
                        NewApiUserProvider {
                            id: TypedUuid::new_v4(),
                            user_id: user.id,
                            emails: info.verified_emails,
                            provider: info.external_id.provider().to_string(),
                            provider_id: info.external_id.id().to_string(),
                            // TODO: Refactor in generic display name across providers. This cascades
                            // into changes needed within mappers
                            display_names: info
                                .github_username
                                .map(|name| vec![name])
                                .unwrap_or_default(),
                        },
                    )
                    .await
                    .map_err(|err| ApiError::from(err))
                    .to_resource_result()?;

                Ok((user, user_provider))
            }
            1 => {
                tracing::info!("Found an existing user. Ensuring mapped permissions and groups.");

                // This branch ensures that there is a 0th indexed item
                let mut provider = api_user_providers.into_iter().nth(0).unwrap();

                // Update the provider with the newest user info
                provider.emails = info.verified_emails;
                provider.display_names = info
                    .github_username
                    .map(|name| vec![name])
                    .unwrap_or_default();

                tracing::info!(?provider.id, "Updating provider for user");

                self.update_api_user_provider(caller, provider.clone().into())
                    .await
                    .map_err(|err| err.into())
                    .to_resource_result()?;

                // Update the found user to ensure it has at least the mapped permissions and groups
                let user = self
                    .get_api_user(caller, &provider.user_id)
                    .await
                    .map_err(|err| ApiError::from(err))
                    .to_resource_result()?;
                let mut update: NewApiUser<T> = user.into();
                update.permissions.append(&mut mapped_permissions);
                update.groups.append(&mut mapped_groups);

                Ok((
                    self.update_api_user(caller, update)
                        .await
                        .map_err(|err| ApiError::from(err))
                        .to_resource_result()?,
                    provider,
                ))
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
        }
    }

    async fn get_mapped_fields(
        &self,
        caller: &Caller<T>,
        info: &UserInfo,
    ) -> ResourceResult<(Permissions<T>, BTreeSet<TypedUuid<AccessGroupId>>), StoreError> {
        let mut mapped_permissions = Permissions::new();
        let mut mapped_groups = BTreeSet::new();

        // We optimistically load mappers here. We do not want to take a lock on the mappers and
        // instead handle mappers that become depleted before we can evaluate them at evaluation
        // time.
        for mapping in self.get_mappings(caller).await? {
            let (permissions, groups) = (
                mapping
                    .rule
                    .permissions_for(&self, &info)
                    .await
                    .to_resource_result()?,
                mapping.rule.groups_for(&self, &info).await?,
            );

            // If a rule is set to apply a permission or group to a user, then the rule needs to be
            // checked for usage. If it does not have an activation limit then nothing is needed.
            // If it does have a limit then we need to attempt to consume an activation. If the
            // consumption works then we add the permissions. If they fail then we do not, but we
            // do not fail the entire mapping process
            let apply = if !permissions.is_empty() || !groups.is_empty() {
                if mapping.max_activations.is_some() {
                    match self.consume_mapping_activation(&mapping).await {
                        Ok(_) => true,
                        Err(err) => {
                            // TODO: Inspect the error. We expect to see a conflict error, and
                            // should is expected to be seen. Other errors are problematic.
                            tracing::warn!(?err, "Login may have attempted to use depleted mapper. This may be ok if it is an isolated occurrence, but should occur repeatedly.");
                            false
                        }
                    }
                } else {
                    true
                }
            } else {
                false
            };

            if apply {
                mapped_permissions.append(
                    &mut mapping
                        .rule
                        .permissions_for(&self, &info)
                        .await
                        .to_resource_result()?,
                );
                mapped_groups.append(&mut mapping.rule.groups_for(&self, &info).await?);
            }
        }

        Ok((mapped_permissions, mapped_groups))
    }

    #[instrument(skip(self), err(Debug))]
    async fn ensure_api_user(
        &self,
        caller: &Caller<T>,
        api_user_id: TypedUuid<UserId>,
        mut mapped_permissions: Permissions<T>,
        mut mapped_groups: BTreeSet<TypedUuid<AccessGroupId>>,
    ) -> ResourceResult<ApiUser<T>, StoreError> {
        match self.get_api_user(caller, &api_user_id).await {
            ResourceResult::Ok(api_user) => {
                // Ensure that the existing user has "at least" the mapped permissions
                let mut update: NewApiUser<T> = api_user.into();
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

    // TODO: Need to pass in caller to be able to eventually pass it down to create_access_token
    pub async fn register_access_token(
        &self,
        caller: &Caller<T>,
        api_user: &ApiUser<T>,
        api_user_provider: &ApiUserProvider,
        scope: Option<Vec<String>>,
    ) -> Result<RegisteredAccessToken, ApiError> {
        let expires_at =
            Utc::now() + TimeDelta::try_seconds(self.default_jwt_expiration()).unwrap();

        let claims = Claims::new(self, &api_user, &api_user_provider, scope, expires_at);
        let token = self
            .create_access_token(
                caller,
                NewAccessToken {
                    id: claims.jti,
                    user_id: api_user.id,
                    revoked_at: None,
                },
            )
            .await?;

        let signed = self.sign_jwt(&claims).await?;

        Ok(RegisteredAccessToken {
            access_token: token,
            signed_token: signed,
            expires_at,
        })
    }

    // API User Operations

    pub async fn get_api_user(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<UserId>,
    ) -> ResourceResult<ApiUser<T>, StoreError> {
        if caller.any(&[
            &VPermission::GetApiUser(*id).into(),
            &VPermission::GetApiUsersAll.into(),
        ]) {
            ApiUserStore::get(&*self.storage, id, false)
                .await
                .map(|opt| {
                    opt.map(|mut user| {
                        user.permissions = <T as PermissionStorageInternal>::expand(
                            &user.permissions,
                            &user.id,
                            None,
                        );
                        user
                    })
                })
                .opt_to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn list_api_user(
        &self,
        caller: &Caller<T>,
        filter: ApiUserFilter,
        pagination: &ListPagination,
    ) -> ResourceResult<Vec<ApiUser<T>>, StoreError> {
        let mut users = ApiUserStore::list(&*self.storage, filter, pagination)
            .await
            .to_resource_result()?;

        users.retain(|user| {
            caller.any(&[
                &VPermission::GetApiUser(user.id).into(),
                &VPermission::GetApiUsersAll.into(),
            ])
        });

        Ok(users)
    }

    #[instrument(skip(self))]
    pub async fn create_api_user(
        &self,
        caller: &Caller<T>,
        permissions: Permissions<T>,
        groups: BTreeSet<TypedUuid<AccessGroupId>>,
    ) -> ResourceResult<ApiUser<T>, StoreError> {
        if caller.can(&VPermission::CreateApiUser.into()) {
            let mut new_user = NewApiUser {
                id: TypedUuid::new_v4(),
                permissions: permissions,
                groups: groups,
            };
            new_user.permissions =
                <T as PermissionStorageInternal>::contract(&new_user.permissions);
            ApiUserStore::upsert(&*self.storage, new_user)
                .await
                .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    #[instrument(skip(self))]
    pub async fn update_api_user(
        &self,
        caller: &Caller<T>,
        mut api_user: NewApiUser<T>,
    ) -> ResourceResult<ApiUser<T>, StoreError> {
        if caller.any(&[
            &VPermission::ManageApiUser(api_user.id).into(),
            &VPermission::ManageApiUsersAll.into(),
        ]) {
            api_user.permissions =
                <T as PermissionStorageInternal>::contract(&api_user.permissions);
            ApiUserStore::upsert(&*self.storage, api_user)
                .await
                .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn add_permissions_to_user(
        &self,
        caller: &Caller<T>,
        user_id: &TypedUuid<UserId>,
        new_permissions: Permissions<T>,
    ) -> ResourceResult<ApiUser<T>, StoreError> {
        if caller.any(&[
            &VPermission::ManageApiUser(*user_id).into(),
            &VPermission::ManageApiUsersAll.into(),
        ]) {
            let user = self.get_api_user(caller, user_id).await?;

            let mut user_update: NewApiUser<T> = user.into();
            for permission in new_permissions.into_iter() {
                tracing::info!(id = ?user_id, ?permission, "Adding permission to user");
                user_update.permissions.insert(permission);
            }

            self.update_api_user(caller, user_update).await
        } else {
            resource_restricted()
        }
    }

    pub async fn create_api_user_token(
        &self,
        caller: &Caller<T>,
        token: NewApiKey<T>,
        api_user_id: &TypedUuid<UserId>,
    ) -> ResourceResult<ApiKey<T>, StoreError> {
        if caller.any(&[
            &VPermission::CreateApiKey(*api_user_id).into(),
            &VPermission::CreateApiKeyAll.into(),
        ]) {
            ApiKeyStore::upsert(&*self.storage, token)
                .await
                .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn get_api_user_token(
        &self,
        caller: &Caller<T>,
        api_key_id: &TypedUuid<ApiKeyId>,
    ) -> ResourceResult<ApiKey<T>, StoreError> {
        if caller.any(&[
            &VPermission::GetApiKey(*api_key_id).into(),
            &VPermission::GetApiKeysAll.into(),
        ]) {
            ApiKeyStore::get(&*self.storage, api_key_id, false)
                .await
                .opt_to_resource_result()
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
        .await
        .to_resource_result()?;

        tokens.retain(|token| {
            caller.any(&[
                &VPermission::GetApiKey(token.id).into(),
                &VPermission::GetApiKeysAll.into(),
            ])
        });

        Ok(tokens)
    }

    pub async fn get_api_user_provider(
        &self,
        caller: &Caller<T>,
        user_id: &TypedUuid<UserId>,
        provider_id: &TypedUuid<UserProviderId>,
    ) -> ResourceResult<ApiUserProvider, StoreError> {
        if caller.any(&[
            &VPermission::GetApiUser(*user_id).into(),
            &VPermission::GetApiUsersAll.into(),
        ]) {
            ApiUserProviderStore::get(&*self.storage, provider_id, false)
                .await
                .opt_to_resource_result()
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
        let mut providers = ApiUserProviderStore::list(&*self.storage, filter, pagination)
            .await
            .to_resource_result()?;

        providers.retain(|provider| {
            caller.any(&[
                &VPermission::GetApiUser(provider.user_id).into(),
                &VPermission::GetApiUsersAll.into(),
            ])
        });

        Ok(providers)
    }

    pub async fn update_api_user_provider(
        &self,
        caller: &Caller<T>,
        api_user_provider: NewApiUserProvider,
    ) -> ResourceResult<ApiUserProvider, StoreError> {
        if caller.any(&[
            &VPermission::ManageApiUser(api_user_provider.user_id).into(),
            &VPermission::ManageApiUsersAll.into(),
        ]) {
            ApiUserProviderStore::upsert(&*self.storage, api_user_provider)
                .await
                .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn delete_api_user_token(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<ApiKeyId>,
    ) -> ResourceResult<ApiKey<T>, StoreError> {
        if caller.any(&[
            &VPermission::ManageApiKey(*id).into(),
            &VPermission::ManageApiKeysAll.into(),
        ]) {
            ApiKeyStore::delete(&*self.storage, id)
                .await
                .opt_to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn create_access_token(
        &self,
        caller: &Caller<T>,
        access_token: NewAccessToken,
    ) -> ResourceResult<AccessToken, StoreError> {
        if caller.can(&VPermission::CreateAccessToken.into()) {
            AccessTokenStore::upsert(&*self.storage, access_token)
                .await
                .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    // Login Attempt Operations

    // TODO: Create permissions around login attempts that are assigned to only the builtin
    // registration user

    pub async fn create_login_attempt(
        &self,
        attempt: NewLoginAttempt,
    ) -> Result<LoginAttempt, StoreError> {
        LoginAttemptStore::upsert(&*self.storage, attempt).await
    }

    pub async fn set_login_provider_authz_code(
        &self,
        attempt: LoginAttempt,
        code: String,
    ) -> Result<LoginAttempt, StoreError> {
        let mut attempt: NewLoginAttempt = attempt.into();
        attempt.provider_authz_code = Some(code);

        // TODO: Internal state changes to the struct
        attempt.attempt_state = LoginAttemptState::RemoteAuthenticated;
        attempt.authz_code = Some(CsrfToken::new_random().secret().to_string());

        LoginAttemptStore::upsert(&*self.storage, attempt).await
    }

    pub async fn get_login_attempt(
        &self,
        id: &TypedUuid<LoginAttemptId>,
    ) -> Result<Option<LoginAttempt>, StoreError> {
        LoginAttemptStore::get(&*self.storage, id).await
    }

    pub async fn get_login_attempt_for_code(
        &self,
        code: &str,
    ) -> Result<Option<LoginAttempt>, StoreError> {
        let filter = LoginAttemptFilter {
            attempt_state: Some(vec![LoginAttemptState::RemoteAuthenticated]),
            authz_code: Some(vec![code.to_string()]),
            ..Default::default()
        };

        let mut attempts = LoginAttemptStore::list(
            &*self.storage,
            filter,
            &ListPagination {
                offset: 0,
                limit: 1,
            },
        )
        .await?;

        Ok(attempts.pop())
    }

    pub async fn fail_login_attempt(
        &self,
        attempt: LoginAttempt,
        error: Option<&str>,
        provider_error: Option<&str>,
    ) -> Result<LoginAttempt, StoreError> {
        let mut attempt: NewLoginAttempt = attempt.into();
        attempt.attempt_state = LoginAttemptState::Failed;
        attempt.error = error.map(|s| s.to_string());
        attempt.provider_error = provider_error.map(|s| s.to_string());
        LoginAttemptStore::upsert(&*self.storage, attempt).await
    }

    // OAuth Client Operations

    pub async fn create_oauth_client(
        &self,
        caller: &Caller<T>,
    ) -> ResourceResult<OAuthClient, StoreError> {
        if caller.can(&VPermission::CreateOAuthClient.into()) {
            OAuthClientStore::upsert(
                &*self.storage,
                NewOAuthClient {
                    id: TypedUuid::new_v4(),
                },
            )
            .await
            .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn get_oauth_client(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<OAuthClientId>,
    ) -> ResourceResult<OAuthClient, StoreError> {
        if caller.any(&[
            &VPermission::GetOAuthClient(*id).into(),
            &VPermission::GetOAuthClientsAll.into(),
        ]) {
            OAuthClientStore::get(&*self.storage, id, false)
                .await
                .opt_to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn list_oauth_clients(
        &self,
        caller: &Caller<T>,
    ) -> ResourceResult<Vec<OAuthClient>, StoreError> {
        let mut clients = OAuthClientStore::list(
            &*self.storage,
            OAuthClientFilter {
                id: None,
                deleted: false,
            },
            &ListPagination::default(),
        )
        .await
        .to_resource_result()?;

        clients.retain(|client| {
            caller.any(&[
                &VPermission::GetOAuthClient(client.id).into(),
                &VPermission::GetOAuthClientsAll.into(),
            ])
        });

        Ok(clients)
    }

    pub async fn add_oauth_secret(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<OAuthSecretId>,
        client_id: &TypedUuid<OAuthClientId>,
        secret: &str,
    ) -> ResourceResult<OAuthClientSecret, StoreError> {
        if caller.any(&[
            &VPermission::ManageOAuthClient(*client_id).into(),
            &VPermission::ManageOAuthClientsAll.into(),
        ]) {
            OAuthClientSecretStore::upsert(
                &*self.storage,
                NewOAuthClientSecret {
                    id: *id,
                    oauth_client_id: *client_id,
                    secret_signature: secret.to_string(),
                },
            )
            .await
            .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn delete_oauth_secret(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<OAuthSecretId>,
        client_id: &TypedUuid<OAuthClientId>,
    ) -> ResourceResult<OAuthClientSecret, StoreError> {
        if caller.any(&[
            &VPermission::ManageOAuthClient(*client_id).into(),
            &VPermission::ManageOAuthClientsAll.into(),
        ]) {
            OAuthClientSecretStore::delete(&*self.storage, id)
                .await
                .opt_to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn add_oauth_redirect_uri(
        &self,
        caller: &Caller<T>,
        client_id: &TypedUuid<OAuthClientId>,
        uri: &str,
    ) -> ResourceResult<OAuthClientRedirectUri, StoreError> {
        if caller.any(&[
            &VPermission::ManageOAuthClient(*client_id).into(),
            &VPermission::ManageOAuthClientsAll.into(),
        ]) {
            OAuthClientRedirectUriStore::upsert(
                &*self.storage,
                NewOAuthClientRedirectUri {
                    id: TypedUuid::new_v4(),
                    oauth_client_id: *client_id,
                    redirect_uri: uri.to_string(),
                },
            )
            .await
            .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn delete_oauth_redirect_uri(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<OAuthRedirectUriId>,
        client_id: &TypedUuid<OAuthClientId>,
    ) -> ResourceResult<OAuthClientRedirectUri, StoreError> {
        if caller.any(&[
            &VPermission::ManageOAuthClient(*client_id).into(),
            &VPermission::ManageOAuthClientsAll.into(),
        ]) {
            OAuthClientRedirectUriStore::delete(&*self.storage, id)
                .await
                .opt_to_resource_result()
        } else {
            resource_restricted()
        }
    }

    // Group Operations
    pub async fn get_groups(
        &self,
        caller: &Caller<T>,
    ) -> ResourceResult<Vec<AccessGroup<T>>, StoreError> {
        // Callers will fall in to one of three permission groups:
        //   - Has GetGroupsAll
        //   - Has GetGroupsJoined
        //   - No permissions
        //
        // Based on this hierarchy we can create a filter that includes only the groups they have
        // access to.
        let mut filter = AccessGroupFilter {
            id: None,
            name: None,
            deleted: false,
        };

        if caller.can(&VPermission::GetGroupsAll.into()) {
            // Nothing we need to do, the filter is already setup for this
        } else if caller.can(&VPermission::GetGroupsJoined.into()) {
            // If a caller can only view the groups they are a member of then we need to fetch the
            // callers user record to determine what those are
            let user = self.get_api_user(caller, &caller.id).await?;
            filter.id = Some(user.groups.into_iter().collect::<Vec<_>>());
        } else {
            // The caller does not have any permissions to view groups
            filter.id = Some(vec![])
        };

        AccessGroupStore::list(
            &*self.storage,
            filter,
            &ListPagination::default().limit(UNLIMITED),
        )
        .await
        .to_resource_result()
    }

    pub async fn create_group(
        &self,
        caller: &Caller<T>,
        group: NewAccessGroup<T>,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        if caller.can(&VPermission::CreateGroup.into()) {
            AccessGroupStore::upsert(&*self.storage, &group)
                .await
                .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn update_group(
        &self,
        caller: &Caller<T>,
        group: NewAccessGroup<T>,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        if caller.any(&[
            &VPermission::ManageGroup(group.id).into(),
            &VPermission::ManageGroupsAll.into(),
        ]) {
            AccessGroupStore::upsert(&*self.storage, &group)
                .await
                .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn delete_group(
        &self,
        caller: &Caller<T>,
        group_id: &TypedUuid<AccessGroupId>,
    ) -> ResourceResult<AccessGroup<T>, StoreError> {
        if caller.any(&[
            &VPermission::ManageGroup(*group_id).into(),
            &VPermission::ManageGroupsAll.into(),
        ]) {
            AccessGroupStore::delete(&*self.storage, group_id)
                .await
                .opt_to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn add_api_user_to_group(
        &self,
        caller: &Caller<T>,
        api_user_id: &TypedUuid<UserId>,
        group_id: &TypedUuid<AccessGroupId>,
    ) -> ResourceResult<ApiUser<T>, StoreError> {
        if caller.any(&[
            &VPermission::ManageGroupMembership(*group_id).into(),
            &VPermission::ManageGroupMembershipsAll.into(),
        ]) {
            // TODO: This needs to be wrapped in a transaction. That requires reworking the way the
            // store traits are handled. Ideally we could have an API that still abstracts away the
            // underlying connection management while allowing for transactions. Possibly something
            // that takes a closure and passes in a connection that implements all of the expected
            // data store traits
            let user = ApiUserStore::get(&*self.storage, api_user_id, false)
                .await
                .opt_to_resource_result()?;

            let mut update: NewApiUser<T> = user.into();
            update.groups.insert(*group_id);

            ApiUserStore::upsert(&*self.storage, update)
                .await
                .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn remove_api_user_from_group(
        &self,
        caller: &Caller<T>,
        api_user_id: &TypedUuid<UserId>,
        group_id: &TypedUuid<AccessGroupId>,
    ) -> ResourceResult<ApiUser<T>, StoreError> {
        if caller.any(&[
            &VPermission::ManageGroupMembership(*group_id).into(),
            &VPermission::ManageGroupMembershipsAll.into(),
        ]) {
            // TODO: This needs to be wrapped in a transaction. That requires reworking the way the
            // store traits are handled. Ideally we could have an API that still abstracts away the
            // underlying connection management while allowing for transactions. Possibly something
            // that takes a closure and passes in a connection that implements all of the expected
            // data store traits
            let user = ApiUserStore::get(&*self.storage, api_user_id, false)
                .await
                .opt_to_resource_result()?;

            let mut update: NewApiUser<T> = user.into();
            update.groups.retain(|id| id != group_id);

            ApiUserStore::upsert(&*self.storage, update)
                .await
                .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    // Mapper Operations

    async fn get_mappings(
        &self,
        caller: &Caller<T>,
    ) -> ResourceResult<Vec<Mapping<T>>, StoreError> {
        let mappers = self
            .get_mappers(caller, false)
            .await?
            .into_iter()
            .filter_map(|mapper| mapper.try_into().ok())
            .collect::<Vec<_>>();

        tracing::trace!(?mappers, "Fetched list of mappers to test");

        Ok(mappers)
    }

    pub async fn get_mappers(
        &self,
        caller: &Caller<T>,
        included_depleted: bool,
    ) -> ResourceResult<Vec<Mapper>, StoreError> {
        if caller.can(&VPermission::GetMappersAll.into()) {
            MapperStore::list(
                &*self.storage,
                MapperFilter::default().depleted(included_depleted),
                &ListPagination::default().limit(UNLIMITED),
            )
            .await
            .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn add_mapper(
        &self,
        caller: &Caller<T>,
        new_mapper: &NewMapper,
    ) -> ResourceResult<Mapper, StoreError> {
        if caller.can(&VPermission::CreateMapper.into()) {
            MapperStore::upsert(&*self.storage, new_mapper)
                .await
                .to_resource_result()
        } else {
            resource_restricted()
        }
    }

    pub async fn remove_mapper(
        &self,
        caller: &Caller<T>,
        id: &TypedUuid<MapperId>,
    ) -> ResourceResult<Mapper, StoreError> {
        if caller.any(&[
            &VPermission::ManageMapper(*id).into(),
            &VPermission::ManageMappersAll.into(),
        ]) {
            MapperStore::delete(&*self.storage, id)
                .await
                .opt_to_resource_result()
        } else {
            resource_restricted()
        }
    }

    // TODO: Create a permission for this that only the registration user has
    async fn consume_mapping_activation(&self, mapping: &Mapping<T>) -> Result<(), StoreError> {
        // Activations are only incremented if the rule actually has a max activation value
        let activations = mapping
            .max_activations
            .map(|_| mapping.activations.unwrap_or(0) + 1);

        Ok(MapperStore::upsert(
            &*self.storage,
            &NewMapper {
                id: mapping.id,
                name: mapping.name.clone(),
                // If a rule fails to serialize, then something critical has gone wrong. Rules should
                // never be modified after they are created, and rules must be persisted before they
                // can be used for an activation. So if a rule fails to serialize, then the stored rule
                // has become corrupted or something in the application has manipulated the rule.
                rule: serde_json::to_value(&mapping.rule)
                    .expect("Store rules must be able to be re-serialized"),
                activations: activations,
                max_activations: mapping.max_activations,
            },
        )
        .await
        .map(|_| ())?)
    }

    // TODO: Need a permission for this action
    pub async fn get_link_request(
        &self,
        id: &TypedUuid<LinkRequestId>,
    ) -> Result<Option<LinkRequest>, StoreError> {
        Ok(LinkRequestStore::get(&*self.storage, id, false, false).await?)
    }

    pub async fn create_link_request_token(
        &self,
        caller: &Caller<T>,
        source_provider: &TypedUuid<UserProviderId>,
        source_user: &TypedUuid<UserId>,
        target: &TypedUuid<UserId>,
    ) -> ResourceResult<SignedApiKey, StoreError> {
        if caller.can(&VPermission::CreateUserApiProviderLinkToken.into()) {
            let link_id = TypedUuid::new_v4();
            let secret = RawApiKey::generate::<8>(link_id.as_untyped_uuid());
            let signed = secret.sign(&*self.secrets.signer).await.unwrap();

            LinkRequestStore::upsert(
                &*self.storage,
                &NewLinkRequest {
                    id: link_id,
                    source_provider_id: *source_provider,
                    source_user_id: *source_user,
                    target_user_id: *target,
                    secret_signature: signed.signature().to_string(),
                    expires_at: Utc::now().add(TimeDelta::try_minutes(15).unwrap()),
                    completed_at: None,
                },
            )
            .await
            .map(|_| signed)
            .to_resource_result()
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
            LinkRequestStore::upsert(&*self.storage, &update_request)
                .await
                .to_resource_result()?;

            ApiUserProviderStore::transfer(&*self.storage, provider.into(), source_user_id)
                .await
                .to_resource_result()
        } else {
            resource_restricted()
        }
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
        storage::{AccessGroupFilter, ListPagination, MockAccessGroupStore, MockApiUserStore},
        AccessGroup, ApiUser, ApiUserProvider, UserId,
    };

    use crate::{
        authn::{
            jwt::{Claims, Jwt},
            AuthToken,
        },
        context::UNLIMITED,
        permissions::VPermission,
    };

    use super::{
        test_mocks::{mock_context, MockStorage},
        VContext,
    };

    async fn create_token(
        ctx: &VContext<VPermission>,
        user_id: TypedUuid<UserId>,
        scope: Vec<String>,
    ) -> AuthToken {
        let user = ApiUser {
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

        let user_token = ctx.jwt.signers[0]
            .sign(&Claims::new(
                ctx,
                &user,
                &provider,
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
        let pagination = ListPagination::default().limit(UNLIMITED);
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
        let user = ApiUser {
            id: user_id,
            permissions: user_permissions.clone(),
            groups,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };

        let mut user_store = MockApiUserStore::new();
        user_store
            .expect_get()
            .with(eq(user.id), eq(false))
            .returning(move |_, _| Ok(Some(user.clone())));

        storage.access_group_store = Some(Arc::new(group_store));
        storage.api_user_store = Some(Arc::new(user_store));
        let ctx = mock_context(storage).await;

        let token_with_no_scope = create_token(&ctx, user_id, vec![]).await;
        let permissions = ctx.get_caller(Some(&token_with_no_scope)).await.unwrap();
        assert_eq!(Permissions::<VPermission>::new(), permissions.permissions);

        let token_with_read_user_info = create_token(
            &ctx,
            user_id,
            vec![
                "group:w".to_string(),
                "mapper:r".to_string(),
                "user:info:r".to_string(),
            ],
        )
        .await;
        let permissions = ctx
            .get_caller(Some(&token_with_read_user_info))
            .await
            .unwrap();
        assert_eq!(
            Permissions::<VPermission>::from(vec![
                VPermission::CreateGroup,
                VPermission::GetMappersAll,
            ]),
            permissions.permissions
        );
    }
}

#[cfg(test)]
pub(crate) mod test_mocks {
    use async_trait::async_trait;
    use newtype_uuid::TypedUuid;
    use std::sync::Arc;
    use v_model::{
        permissions::Caller,
        storage::{
            AccessGroupStore, AccessTokenStore, ApiKeyStore, ApiUserProviderStore, ApiUserStore,
            LinkRequestStore, ListPagination, LoginAttemptStore, MapperStore, MockAccessGroupStore,
            MockAccessTokenStore, MockApiKeyStore, MockApiUserProviderStore, MockApiUserStore,
            MockLinkRequestStore, MockLoginAttemptStore, MockMapperStore,
            MockOAuthClientRedirectUriStore, MockOAuthClientSecretStore, MockOAuthClientStore,
            OAuthClientRedirectUriStore, OAuthClientSecretStore, OAuthClientStore,
        },
        AccessGroupId, AccessTokenId, ApiKey, ApiKeyId, ApiUserProvider, LinkRequestId,
        LoginAttemptId, MapperId, NewAccessGroup, NewAccessToken, NewApiKey, NewApiUser,
        NewApiUserProvider, NewLoginAttempt, NewMapper, OAuthClientId, OAuthRedirectUriId,
        OAuthSecretId, UserId, UserProviderId,
    };

    use crate::{
        config::JwtConfig,
        endpoints::login::oauth::{google::GoogleOAuthProvider, OAuthProviderName},
        permissions::VPermission,
        util::tests::mock_key,
    };

    use super::VContext;

    // Construct a mock context that can be used in tests
    pub async fn mock_context(storage: MockStorage) -> VContext<VPermission> {
        let mut ctx = VContext::new(
            "".to_string(),
            Arc::new(storage),
            JwtConfig::default(),
            vec![
                // We are in the context of a test and do not care about the key leaking
                mock_key(),
            ],
        )
        .await
        .unwrap();

        ctx.insert_oauth_provider(
            OAuthProviderName::Google,
            Box::new(move || {
                Box::new(GoogleOAuthProvider::new(
                    "google_device_client_id".to_string(),
                    "google_device_client_secret".to_string().into(),
                    "google_web_client_id".to_string(),
                    "google_web_client_secret".to_string().into(),
                ))
            }),
        );

        ctx
    }

    // Construct a mock storage engine that can be wrapped in an ApiContext for testing
    pub struct MockStorage {
        pub caller: Option<Caller<VPermission>>,
        pub api_user_store: Option<Arc<MockApiUserStore<VPermission>>>,
        pub api_user_token_store: Option<Arc<MockApiKeyStore<VPermission>>>,
        pub api_user_provider_store: Option<Arc<MockApiUserProviderStore>>,
        pub device_token_store: Option<Arc<MockAccessTokenStore>>,
        pub login_attempt_store: Option<Arc<MockLoginAttemptStore>>,
        pub oauth_client_store: Option<Arc<MockOAuthClientStore>>,
        pub oauth_client_secret_store: Option<Arc<MockOAuthClientSecretStore>>,
        pub oauth_client_redirect_uri_store: Option<Arc<MockOAuthClientRedirectUriStore>>,
        pub access_group_store: Option<Arc<MockAccessGroupStore<VPermission>>>,
        pub mapper_store: Option<Arc<MockMapperStore>>,
        pub link_request_store: Option<Arc<MockLinkRequestStore>>,
    }

    impl MockStorage {
        pub fn new() -> Self {
            Self {
                caller: None,
                api_user_store: None,
                api_user_token_store: None,
                api_user_provider_store: None,
                device_token_store: None,
                login_attempt_store: None,
                oauth_client_store: None,
                oauth_client_secret_store: None,
                oauth_client_redirect_uri_store: None,
                access_group_store: None,
                mapper_store: None,
                link_request_store: None,
            }
        }
    }

    #[async_trait]
    impl ApiUserStore<VPermission> for MockStorage {
        async fn get(
            &self,
            id: &TypedUuid<UserId>,
            deleted: bool,
        ) -> Result<Option<v_model::ApiUser<VPermission>>, v_model::storage::StoreError> {
            self.api_user_store.as_ref().unwrap().get(id, deleted).await
        }

        async fn list(
            &self,
            filter: v_model::storage::ApiUserFilter,
            pagination: &ListPagination,
        ) -> Result<Vec<v_model::ApiUser<VPermission>>, v_model::storage::StoreError> {
            self.api_user_store
                .as_ref()
                .unwrap()
                .list(filter, pagination)
                .await
        }

        async fn upsert(
            &self,
            api_user: NewApiUser<VPermission>,
        ) -> Result<v_model::ApiUser<VPermission>, v_model::storage::StoreError> {
            self.api_user_store.as_ref().unwrap().upsert(api_user).await
        }

        async fn delete(
            &self,
            id: &TypedUuid<UserId>,
        ) -> Result<Option<v_model::ApiUser<VPermission>>, v_model::storage::StoreError> {
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
            self.device_token_store
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
            self.device_token_store
                .as_ref()
                .unwrap()
                .list(filter, pagination)
                .await
        }

        async fn upsert(
            &self,
            token: NewAccessToken,
        ) -> Result<v_model::AccessToken, v_model::storage::StoreError> {
            self.device_token_store
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
}
