// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::{hash_map::Entry, BTreeSet, HashMap};

use chrono::{DateTime, Utc};
use dropshot::{
    HttpError, HttpResponseCreated, HttpResponseOk, HttpResponseUpdatedNoContent, Path,
    RequestContext, TypedBody,
};
use newtype_uuid::{GenericUuid, TypedUuid};
use partial_struct::partial;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tap::TapFallible;
use tracing::instrument;
use uuid::Uuid;
use v_model::{
    permissions::{Caller, Permission, PermissionStorage, Permissions},
    storage::{ApiUserFilter, ApiUserProviderFilter, ListPagination},
    AccessGroupId, ApiKeyId, ApiUser, ApiUserContactEmail, ApiUserProvider, NewApiKey, NewApiUser,
    UserId,
};

use crate::{
    authn::key::RawKey,
    context::{user::BasePermissions, ApiContext, VContextWithCaller},
    error::ApiError,
    permissions::{VAppPermission, VAppPermissionResponse},
    secrets::OpenApiSecretString,
    util::response::{bad_request, not_found, to_internal_error, unauthorized},
    VContext,
};

fn into_user_response<T, U>(user: ApiUser<T>) -> ApiUser<U>
where
    T: Permission,
    U: Permission + From<T>,
{
    ApiUser {
        id: user.id,
        permissions: user
            .permissions
            .into_iter()
            .map(|p| p.into())
            .collect::<Permissions<U>>(),
        groups: user.groups,
        created_at: user.created_at,
        updated_at: user.updated_at,
        deleted_at: user.deleted_at,
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetUserResponse<T> {
    info: ApiUser<T>,
    providers: Vec<ApiUserProvider>,
}

impl<T> GetUserResponse<T>
where
    T: Permission,
{
    pub fn new<U>(user: ApiUser<U>, providers: Vec<ApiUserProvider>) -> Self
    where
        T: From<U>,
        U: Permission,
    {
        let info = into_user_response(user);
        Self { info, providers }
    }
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn get_self_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
) -> Result<HttpResponseOk<GetUserResponse<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let info = ctx.user.get_api_user(&caller, &caller.id).await?;

    let filter = ApiUserProviderFilter {
        api_user_id: Some(vec![info.user.id]),
        ..Default::default()
    };
    let providers = ctx
        .user
        .list_api_user_provider(&caller, filter, &ListPagination::default().limit(10))
        .await?;

    tracing::trace!(user = ?serde_json::to_string(&info.user), "Found user");
    Ok(HttpResponseOk(GetUserResponse::new(info.user, providers)))
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn get_api_user_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<ApiUserPath>,
) -> Result<HttpResponseOk<GetUserResponse<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let path = path.into_inner();
    let info = ctx.user.get_api_user(&caller, &path.user_id).await?;

    let filter = ApiUserProviderFilter {
        api_user_id: Some(vec![info.user.id]),
        ..Default::default()
    };
    let providers = ctx
        .user
        .list_api_user_provider(&caller, filter, &ListPagination::default().limit(10))
        .await?;

    tracing::trace!(user = ?serde_json::to_string(&info.user), "Found user");
    Ok(HttpResponseOk(GetUserResponse::new(info.user, providers)))
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct CallerResponse<T> {
    pub id: TypedUuid<UserId>,
    pub permissions: Permissions<T>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn resolve_api_user_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<ApiUserPath>,
) -> Result<HttpResponseOk<CallerResponse<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let path = path.into_inner();
    let info = ctx.user.get_api_user(&caller, &path.user_id).await?;

    let resolved_caller = ctx
        .user
        .resolve_caller(&info, BasePermissions::Full)
        .await?;

    tracing::trace!(caller = ?resolved_caller, "Resolved caller");
    Ok(HttpResponseOk(CallerResponse {
        id: resolved_caller.id,
        permissions: resolved_caller
            .permissions
            .into_iter()
            .map(|p| p.into())
            .collect::<Permissions<U>>(),
    }))
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn list_api_user_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
) -> Result<HttpResponseOk<Vec<GetUserResponse<U>>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let info = ctx
        .user
        .list_api_user(
            &caller,
            ApiUserFilter::default(),
            &ListPagination::unlimited(),
        )
        .await?;

    let filter = ApiUserProviderFilter {
        api_user_id: Some(info.iter().map(|info| info.user.id).collect()),
        ..Default::default()
    };
    let providers: HashMap<TypedUuid<UserId>, Vec<ApiUserProvider>> = ctx
        .user
        .list_api_user_provider(&caller, filter, &ListPagination::unlimited())
        .await?
        .into_iter()
        .fold(HashMap::new(), |mut map, provider| {
            let entry = map.entry(provider.user_id);
            match entry {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().push(provider);
                }
                Entry::Vacant(entry) => {
                    entry.insert(vec![provider]);
                }
            }
            map
        });

    tracing::trace!(users = info.len(), "Found users");

    let responses = info
        .into_iter()
        .map(|info| {
            let providers = providers.get(&info.user.id).cloned().unwrap_or_default();
            GetUserResponse::new(info.user, providers)
        })
        .collect();

    Ok(HttpResponseOk(responses))
}

#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
pub struct ApiUserUpdateParams<T> {
    permissions: Permissions<T>,
    group_ids: BTreeSet<TypedUuid<AccessGroupId>>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn create_api_user_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    body: TypedBody<ApiUserUpdateParams<T>>,
) -> Result<HttpResponseCreated<ApiUser<U>>, HttpError>
where
    T: VAppPermission + JsonSchema + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let body = body.into_inner();

    create_api_user_inner(ctx, caller, body).await
}

#[instrument(skip(ctx, body))]
pub async fn create_api_user_inner<T, U>(
    ctx: &VContext<T>,
    caller: Caller<T>,
    body: ApiUserUpdateParams<T>,
) -> Result<HttpResponseCreated<ApiUser<U>>, HttpError>
where
    T: VAppPermission + JsonSchema + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let info = ctx
        .user
        .create_api_user(&caller, body.permissions, body.group_ids)
        .await?;

    Ok(HttpResponseCreated(into_user_response(info.user)))
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct ApiUserPath {
    user_id: TypedUuid<UserId>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn update_api_user_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: ApiUserPath,
    body: ApiUserUpdateParams<T>,
) -> Result<HttpResponseOk<ApiUser<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    update_api_user_inner(ctx, caller, path, body).await
}

#[instrument(skip(ctx, body))]
pub async fn update_api_user_inner<T, U>(
    ctx: &VContext<T>,
    caller: Caller<T>,
    path: ApiUserPath,
    body: ApiUserUpdateParams<T>,
) -> Result<HttpResponseOk<ApiUser<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let info = ctx
        .user
        .update_api_user(
            &caller,
            NewApiUser {
                id: path.user_id,
                permissions: body.permissions,
                groups: body.group_ids,
            },
        )
        .await?;

    Ok(HttpResponseOk(into_user_response(info.user)))
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn list_api_user_tokens_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: ApiUserPath,
) -> Result<HttpResponseOk<Vec<ApiKeyResponse<U>>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    list_api_user_tokens_inner(ctx, caller, path).await
}

#[instrument(skip(ctx))]
pub async fn list_api_user_tokens_inner<T, U>(
    ctx: &VContext<T>,
    caller: Caller<T>,
    path: ApiUserPath,
) -> Result<HttpResponseOk<Vec<ApiKeyResponse<U>>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    tracing::info!("Fetch token list");

    let tokens = ctx
        .user
        .get_api_user_tokens(&caller, &path.user_id, &ListPagination::default())
        .await?;

    tracing::info!(count = ?tokens.len(), "Retrieved token list");

    Ok(HttpResponseOk(
        tokens
            .into_iter()
            .map(|token| ApiKeyResponse {
                id: token.id,
                permissions: into_permissions_response(token.permissions),
                created_at: token.created_at,
            })
            .collect(),
    ))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ApiUserEmailUpdateParams {
    email: String,
}

#[instrument(skip(rqctx, body), err(Debug))]
pub async fn set_api_user_contact_email_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: ApiUserPath,
    body: ApiUserEmailUpdateParams,
) -> Result<HttpResponseOk<ApiUserContactEmail>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    set_api_user_contact_email_inner(ctx, caller, path, body).await
}

#[instrument(skip(ctx, body))]
pub async fn set_api_user_contact_email_inner<T>(
    ctx: &VContext<T>,
    caller: Caller<T>,
    path: ApiUserPath,
    body: ApiUserEmailUpdateParams,
) -> Result<HttpResponseOk<ApiUserContactEmail>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    tracing::info!("Setting contact email for user");

    let email = ctx
        .user
        .set_api_user_contact_email(&caller, path.user_id, &body.email)
        .await?;

    tracing::info!("Set contact email for user");

    Ok(HttpResponseOk(email))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ApiKeyCreateParams<T> {
    permissions: Option<Permissions<T>>,
    expires_at: DateTime<Utc>,
}

#[partial(ApiKeyResponse)]
#[derive(Debug, Serialize, JsonSchema)]
pub struct InitialApiKeyResponse<T> {
    pub id: TypedUuid<ApiKeyId>,
    #[partial(ApiKeyResponse(skip))]
    pub key: OpenApiSecretString,
    pub permissions: Option<Permissions<T>>,
    pub created_at: DateTime<Utc>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn create_api_user_token_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: ApiUserPath,
    body: ApiKeyCreateParams<T>,
) -> Result<HttpResponseCreated<InitialApiKeyResponse<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    create_api_user_token_inner(ctx, caller, path, body).await
}

#[instrument(skip(ctx, body))]
pub async fn create_api_user_token_inner<T, U>(
    ctx: &VContext<T>,
    caller: Caller<T>,
    path: ApiUserPath,
    body: ApiKeyCreateParams<T>,
) -> Result<HttpResponseCreated<InitialApiKeyResponse<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let info = ctx.user.get_api_user(&caller, &path.user_id).await?;
    let key_id = TypedUuid::new_v4();
    let key = RawKey::generate::<24>(key_id.as_untyped_uuid())
        .sign(ctx.signer())
        .await
        .map_err(to_internal_error)?;

    let user_key = ctx
        .user
        .create_api_user_token(
            &caller,
            NewApiKey {
                id: key_id,
                user_id: path.user_id,
                key_signature: key.signature().to_string(),
                permissions: into_permissions(body.permissions),
                expires_at: body.expires_at,
            },
            &info.user.id,
        )
        .await?;

    // Returning an api token will return the hashed version, but we need to return the
    // plaintext token as we do not store a copy
    Ok(HttpResponseCreated(InitialApiKeyResponse {
        id: user_key.id,
        key: key.key().into(),
        permissions: into_permissions_response(user_key.permissions),
        created_at: user_key.created_at,
    }))
}

// The identifier field is currently unused
#[allow(dead_code)]
#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct ApiUserTokenPath {
    user_id: TypedUuid<UserId>,
    api_key_id: TypedUuid<ApiKeyId>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn get_api_user_token_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: ApiUserTokenPath,
) -> Result<HttpResponseOk<ApiKeyResponse<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    get_api_user_token_inner(ctx, caller, path).await
}

#[instrument(skip(ctx))]
pub async fn get_api_user_token_inner<T, U>(
    ctx: &VContext<T>,
    caller: Caller<T>,
    path: ApiUserTokenPath,
) -> Result<HttpResponseOk<ApiKeyResponse<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let token = ctx
        .user
        .get_api_user_token(&caller, &path.api_key_id)
        .await?;
    Ok(HttpResponseOk(ApiKeyResponse {
        id: token.id,
        permissions: into_permissions_response(token.permissions),
        created_at: token.created_at,
    }))
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn delete_api_user_token_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: ApiUserTokenPath,
) -> Result<HttpResponseOk<ApiKeyResponse<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    delete_api_user_token_inner(ctx, caller, path).await
}

#[instrument(skip(ctx))]
pub async fn delete_api_user_token_inner<T, U>(
    ctx: &VContext<T>,
    caller: Caller<T>,
    path: ApiUserTokenPath,
) -> Result<HttpResponseOk<ApiKeyResponse<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let token = ctx
        .user
        .delete_api_user_token(&caller, &path.api_key_id)
        .await?;
    Ok(HttpResponseOk(ApiKeyResponse {
        id: token.id,
        permissions: into_permissions_response(token.permissions),
        created_at: token.created_at,
    }))
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddGroupBody {
    group_id: TypedUuid<AccessGroupId>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn add_api_user_to_group_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: ApiUserPath,
    body: AddGroupBody,
) -> Result<HttpResponseOk<ApiUser<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let info = ctx
        .add_api_user_to_group(&caller, &path.user_id, &body.group_id)
        .await?;

    Ok(HttpResponseOk(into_user_response(info.user)))
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApiUserRemoveGroupPath {
    user_id: TypedUuid<UserId>,
    group_id: TypedUuid<AccessGroupId>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn remove_api_user_from_group_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: ApiUserRemoveGroupPath,
) -> Result<HttpResponseOk<ApiUser<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let info = ctx
        .remove_api_user_from_group(&caller, &path.user_id, &path.group_id)
        .await?;

    Ok(HttpResponseOk(into_user_response(info.user)))
}

// TODO: Needs to be implemented

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApiUserProviderLinkPayload {
    token: String,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn link_provider_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: ApiUserPath,
    body: ApiUserProviderLinkPayload,
) -> Result<HttpResponseUpdatedNoContent, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;

    // TODO: This permission check indicates that the permission modeling for this functionality
    // is not sufficient. Need to rethink it
    //
    // This endpoint can only be called by the user themselves, it can not be performed on behalf
    // of a user
    if path.user_id == caller.id {
        let secret = RawKey::try_from(body.token.as_str()).map_err(|err| {
            tracing::debug!(?err, "Invalid link request token");
            bad_request("Malformed link request token")
        })?;
        let link_request_id =
            TypedUuid::from_untyped_uuid(Uuid::from_slice(secret.id()).map_err(|err| {
                tracing::debug!(?err, "Failed to parse link request id from token");
                bad_request("Invalid link request token")
            })?);

        // TODO: We need an actual permission for reading a LinkRequest
        let link_request = ctx
            .link
            .get_link_request(&link_request_id)
            .await
            .map_err(ApiError::Storage)?
            .ok_or_else(|| not_found("Failed to find identifier"))?;

        // TODO: How can this check be lowered to the context (including a proper permission check)

        // Verify that the found link request is assigned to the user calling the endpoint and that
        // the token provided matches the stored signature
        if link_request.target_user_id == caller.id
            && secret
                .verify(ctx, link_request.secret_signature.as_bytes())
                .is_ok()
        {
            let provider = ctx
                .complete_link_request(&caller, link_request)
                .await
                .tap_err(|err| tracing::error!(?err, "Failed to complete link request"))?;

            tracing::info!(?provider, "Completed link request");
            Ok(HttpResponseUpdatedNoContent())
        } else {
            Err(unauthorized())
        }
    } else {
        Err(unauthorized())
    }
}

fn into_permissions<T, U>(permissions: Option<Permissions<T>>) -> Option<Permissions<U>>
where
    T: Permission,
    U: Permission + From<T>,
{
    permissions.map(|permissions| {
        permissions
            .into_iter()
            .map(|p| p.into())
            .collect::<Permissions<U>>()
    })
}

fn into_permissions_response<T, U>(permissions: Option<Permissions<T>>) -> Option<Permissions<U>>
where
    T: Permission,
    U: Permission + From<T>,
{
    permissions.map(|permissions| {
        permissions
            .into_iter()
            .map(|p| p.into())
            .collect::<Permissions<U>>()
    })
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, HashMap},
        sync::Arc,
    };

    use chrono::{TimeDelta, Utc};
    use http::StatusCode;
    use mockall::predicate::eq;
    use newtype_uuid::TypedUuid;
    use v_model::{
        permissions::{Caller, Permissions},
        storage::{
            ApiKeyFilter, ListPagination, MockApiKeyStore, MockApiUserContactEmailStore,
            MockApiUserStore, StoreError,
        },
        ApiKey, ApiUser, ApiUserContactEmail, ApiUserInfo, ApiUserProvider, NewApiUser,
    };

    use crate::{
        context::test_mocks::{mock_context, MockStorage},
        endpoints::api_user::{
            create_api_user_inner, create_api_user_token_inner, delete_api_user_token_inner,
            get_api_user_token_inner, list_api_user_tokens_inner, set_api_user_contact_email_inner,
            update_api_user_inner, ApiKeyCreateParams, ApiUserEmailUpdateParams, ApiUserPath,
            ApiUserTokenPath,
        },
        permissions::{VPermission, VPermissionResponse},
        util::tests::get_status,
    };

    use super::ApiUserUpdateParams;

    fn mock_user() -> ApiUser<VPermission> {
        ApiUser {
            id: TypedUuid::new_v4(),
            permissions: Permissions::new(),
            groups: BTreeSet::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        }
    }

    #[tokio::test]
    async fn test_create_api_user_permissions() {
        let successful_update = ApiUserUpdateParams {
            permissions: vec![VPermission::CreateApiUser].into(),
            group_ids: BTreeSet::new(),
        };

        let failure_update = ApiUserUpdateParams {
            permissions: vec![VPermission::GetApiUsersAll].into(),
            group_ids: BTreeSet::new(),
        };

        let mut store = MockApiUserStore::new();
        store
            .expect_upsert()
            .withf(|x: &NewApiUser<VPermission>| {
                x.permissions.can(&VPermission::CreateApiUser.into())
            })
            .returning(|user| {
                Ok(ApiUserInfo {
                    user: ApiUser {
                        id: user.id,
                        permissions: user.permissions,
                        groups: BTreeSet::new(),
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                        deleted_at: None,
                    },
                    email: None,
                    providers: vec![],
                })
            });
        store
            .expect_upsert()
            .withf(|x: &NewApiUser<VPermission>| {
                x.permissions.can(&VPermission::GetApiUsersAll.into())
            })
            .returning(|_| Err(StoreError::Unknown));

        let mut storage = MockStorage::new();
        storage.api_user_store = Some(Arc::new(store));

        let ctx = mock_context(Arc::new(storage)).await;

        let user1 = mock_user();

        // 1. Fail to create due to lack of permissions
        let no_permissions = Caller {
            id: user1.id,
            permissions: Permissions::new(),
            extensions: HashMap::default(),
        };

        let resp = create_api_user_inner::<VPermission, VPermissionResponse>(
            &ctx,
            no_permissions,
            successful_update.clone(),
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);

        let user2 = mock_user();

        // 2. Succeed in creating new api user
        let with_permissions = Caller {
            id: user2.id,
            permissions: vec![VPermission::CreateApiUser].into(),
            extensions: HashMap::default(),
        };

        let resp = create_api_user_inner::<VPermission, VPermissionResponse>(
            &ctx,
            with_permissions.clone(),
            successful_update.clone(),
        )
        .await;

        assert!(resp.is_ok());
        assert_eq!(get_status(&resp), StatusCode::CREATED);

        // 3. Handle storage failure and return error
        let resp = create_api_user_inner::<VPermission, VPermissionResponse>(
            &ctx,
            with_permissions,
            failure_update.clone(),
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_update_api_user_permissions() {
        let success_id = TypedUuid::new_v4();
        let successful_update = ApiUserUpdateParams {
            permissions: Permissions::new(),
            group_ids: BTreeSet::new(),
        };

        let failure_id = TypedUuid::new_v4();
        let failure_update = ApiUserUpdateParams {
            permissions: Permissions::new(),
            group_ids: BTreeSet::new(),
        };

        let mut store = MockApiUserStore::new();
        store
            .expect_upsert()
            .withf(move |x: &NewApiUser<VPermission>| &x.id == &success_id)
            .returning(|user| {
                Ok(ApiUserInfo {
                    user: ApiUser {
                        id: user.id,
                        permissions: user.permissions,
                        groups: BTreeSet::new(),
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                        deleted_at: None,
                    },
                    email: None,
                    providers: vec![],
                })
            });
        store
            .expect_upsert()
            .withf(move |x: &NewApiUser<VPermission>| &x.id == &failure_id)
            .returning(|_| Err(StoreError::Unknown));

        let mut storage = MockStorage::new();
        storage.api_user_store = Some(Arc::new(store));

        let ctx = mock_context(Arc::new(storage)).await;

        let success_path = ApiUserPath {
            user_id: success_id,
        };
        let failure_path = ApiUserPath {
            user_id: failure_id,
        };

        let user1 = mock_user();

        // 1. Fail to create due to lack of permissions
        let no_permissions = Caller {
            id: user1.id,
            permissions: Permissions::new(),
            extensions: HashMap::default(),
        };

        let resp = update_api_user_inner::<VPermission, VPermissionResponse>(
            &ctx,
            no_permissions,
            success_path.clone(),
            successful_update.clone(),
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);

        let user2 = mock_user();

        // 2. Succeed in updating api user with direct permission
        let with_specific_permissions = Caller {
            id: user2.id,
            permissions: vec![VPermission::ManageApiUser(success_path.user_id)].into(),
            extensions: HashMap::default(),
        };

        let resp = update_api_user_inner::<VPermission, VPermissionResponse>(
            &ctx,
            with_specific_permissions,
            success_path.clone(),
            successful_update.clone(),
        )
        .await;

        assert!(resp.is_ok());
        assert_eq!(get_status(&resp), StatusCode::OK);

        let user3 = mock_user();

        // 3. Succeed in updating api user with general permission
        let with_general_permissions = Caller {
            id: user3.id,
            permissions: vec![VPermission::ManageApiUsersAll].into(),
            extensions: HashMap::default(),
        };

        let resp = update_api_user_inner::<VPermission, VPermissionResponse>(
            &ctx,
            with_general_permissions.clone(),
            success_path,
            successful_update.clone(),
        )
        .await;

        assert!(resp.is_ok());
        assert_eq!(get_status(&resp), StatusCode::OK);

        // 4. Handle storage failure and return error
        let resp = update_api_user_inner::<VPermission, VPermissionResponse>(
            &ctx,
            with_general_permissions,
            failure_path,
            failure_update.clone(),
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_list_api_user_token_permissions() {
        let success_id = TypedUuid::new_v4();
        let failure_id = TypedUuid::new_v4();

        let mut store = MockApiKeyStore::new();
        store
            .expect_list()
            .withf(move |x: &ApiKeyFilter, _: &ListPagination| {
                x.api_user_id
                    .as_ref()
                    .map(|id| id.contains(&success_id))
                    .unwrap_or(false)
            })
            .returning(|_, _| Ok(vec![]));
        store
            .expect_list()
            .withf(move |x: &ApiKeyFilter, _: &ListPagination| {
                x.api_user_id
                    .as_ref()
                    .map(|id| id.contains(&failure_id))
                    .unwrap_or(false)
            })
            .returning(|_, _| Err(StoreError::Unknown));

        let mut storage = MockStorage::new();
        storage.api_user_token_store = Some(Arc::new(store));

        let ctx = mock_context(Arc::new(storage)).await;

        let user1 = mock_user();

        // 1. Fail to list due to lack of permissions
        let no_permissions = Caller {
            id: user1.id,
            permissions: Permissions::new(),
            extensions: HashMap::default(),
        };

        let resp = list_api_user_tokens_inner::<VPermission, VPermissionResponse>(
            &ctx,
            no_permissions,
            ApiUserPath {
                user_id: success_id,
            },
        )
        .await;

        assert!(resp.is_ok());
        assert_eq!(resp.unwrap().0.len(), 0);

        let user2 = mock_user();

        // 2. Fail to list due to incorrect permissions
        let incorrect_permissions = Caller {
            id: user2.id,
            permissions: vec![VPermission::GetApiKey(TypedUuid::new_v4())].into(),
            extensions: HashMap::default(),
        };

        let resp = list_api_user_tokens_inner::<VPermission, VPermissionResponse>(
            &ctx,
            incorrect_permissions,
            ApiUserPath {
                user_id: success_id,
            },
        )
        .await;

        assert!(resp.is_ok());
        assert_eq!(resp.unwrap().0.len(), 0);

        let user3 = mock_user();

        // 3. Succeed in list tokens
        let success_permissions = Caller {
            id: user3.id,
            permissions: vec![VPermission::GetApiKey(TypedUuid::new_v4())].into(),
            extensions: HashMap::default(),
        };

        let resp = list_api_user_tokens_inner::<VPermission, VPermissionResponse>(
            &ctx,
            success_permissions,
            ApiUserPath {
                user_id: success_id,
            },
        )
        .await;

        assert!(resp.is_ok());
        assert_eq!(get_status(&resp), StatusCode::OK);

        let user4 = mock_user();

        // 4. Handle storage failure and return error
        let failure_permissions = Caller {
            id: user4.id,
            permissions: vec![VPermission::GetApiKey(TypedUuid::new_v4())].into(),
            extensions: HashMap::default(),
        };

        let resp = list_api_user_tokens_inner::<VPermission, VPermissionResponse>(
            &ctx,
            failure_permissions,
            ApiUserPath {
                user_id: failure_id,
            },
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_create_api_user_token_permissions() {
        let api_user_id = TypedUuid::new_v4();
        let api_key_id = TypedUuid::new_v4();

        let api_user = ApiUser {
            id: api_user_id,
            permissions: vec![VPermission::GetApiKey(api_key_id)].into(),
            groups: BTreeSet::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };

        let api_user_path = ApiUserPath {
            user_id: api_user.id,
        };

        let failure_api_user_path = ApiUserPath {
            user_id: TypedUuid::new_v4(),
        };

        let unknown_api_user_path = ApiUserPath {
            user_id: TypedUuid::new_v4(),
        };

        let new_token = ApiKeyCreateParams {
            permissions: None,
            expires_at: Utc::now() + TimeDelta::try_seconds(5 * 60).unwrap(),
        };

        let mut api_user_store = MockApiUserStore::new();
        api_user_store
            .expect_get()
            .with(eq(api_user_path.user_id), eq(false))
            .returning(move |_, _| {
                Ok(Some(ApiUserInfo {
                    user: api_user.clone(),
                    email: None,
                    providers: vec![],
                }))
            });
        api_user_store
            .expect_get()
            .with(eq(failure_api_user_path.user_id), eq(false))
            .returning(|_, _| Err(StoreError::Unknown));
        api_user_store
            .expect_get()
            .with(eq(unknown_api_user_path.user_id), eq(false))
            .returning(move |_, _| Ok(None));

        let mut token_store = MockApiKeyStore::new();
        token_store
            .expect_upsert()
            // .withf(move |_, user| user.id == api_user_id)
            .returning(move |key| {
                Ok(ApiKey {
                    id: TypedUuid::new_v4(),
                    user_id: api_user_id,
                    key_signature: key.key_signature,
                    permissions: key.permissions,
                    expires_at: key.expires_at,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    deleted_at: None,
                })
            });

        let mut storage = MockStorage::new();
        storage.api_user_store = Some(Arc::new(api_user_store));
        storage.api_user_token_store = Some(Arc::new(token_store));

        let ctx = mock_context(Arc::new(storage)).await;

        let user1 = mock_user();

        // 1. Fail to create due to lack of permissions
        let no_permissions = Caller {
            id: user1.id,
            permissions: Permissions::new(),
            extensions: HashMap::default(),
        };

        let resp = create_api_user_token_inner::<VPermission, VPermissionResponse>(
            &ctx,
            no_permissions,
            api_user_path.clone(),
            new_token.clone(),
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);

        let user2 = mock_user();

        // 2. Fail to create due to incorrect permissions
        let incorrect_permissions = Caller {
            id: user2.id,
            permissions: vec![VPermission::CreateApiKey(TypedUuid::new_v4())].into(),
            extensions: HashMap::default(),
        };

        let resp = create_api_user_token_inner::<VPermission, VPermissionResponse>(
            &ctx,
            incorrect_permissions,
            api_user_path.clone(),
            new_token.clone(),
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);

        let user3 = mock_user();

        // 3. Fail to create due to unknown user
        let incorrect_permissions = Caller {
            id: user3.id,
            permissions: vec![
                VPermission::GetApiUser(unknown_api_user_path.user_id),
                VPermission::CreateApiKey(unknown_api_user_path.user_id),
            ]
            .into(),
            extensions: HashMap::default(),
        };

        let resp = create_api_user_token_inner::<VPermission, VPermissionResponse>(
            &ctx,
            incorrect_permissions,
            unknown_api_user_path,
            new_token.clone(),
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::NOT_FOUND);

        let user4 = mock_user();

        // 4. Succeed in creating token
        let success_permissions = Caller {
            id: user4.id,
            permissions: vec![
                VPermission::GetApiUser(api_user_path.user_id),
                VPermission::CreateApiKey(api_user_path.user_id),
            ]
            .into(),
            extensions: HashMap::default(),
        };

        let resp = create_api_user_token_inner(
            &ctx,
            success_permissions,
            api_user_path,
            new_token.clone(),
        )
        .await;

        assert!(resp.is_ok());
        assert_eq!(get_status(&resp), StatusCode::CREATED);
        assert_eq!(resp.as_ref().unwrap().0.permissions, new_token.permissions);

        let user5 = mock_user();

        // 5. Handle storage failure and return error
        let failure_permissions = Caller {
            id: user5.id,
            permissions: vec![
                VPermission::GetApiUser(failure_api_user_path.user_id),
                VPermission::CreateApiKey(failure_api_user_path.user_id),
            ]
            .into(),
            extensions: HashMap::default(),
        };

        let resp = create_api_user_token_inner::<VPermission, VPermissionResponse>(
            &ctx,
            failure_permissions,
            failure_api_user_path,
            new_token,
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_get_api_user_token_permissions() {
        let api_user_id = TypedUuid::new_v4();

        let token = ApiKey {
            id: TypedUuid::new_v4(),
            user_id: api_user_id,
            key_signature: "encrypted_key".to_string(),
            permissions: None,
            expires_at: Utc::now() + TimeDelta::try_seconds(5 * 60).unwrap(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };

        let api_user_token_path = ApiUserTokenPath {
            user_id: api_user_id,
            api_key_id: token.id,
        };

        let failure_api_user_token_path = ApiUserTokenPath {
            user_id: api_user_id,
            api_key_id: TypedUuid::new_v4(),
        };

        let unknown_api_user_token_path = ApiUserTokenPath {
            user_id: api_user_id,
            api_key_id: TypedUuid::new_v4(),
        };

        let mut token_store = MockApiKeyStore::new();
        token_store
            .expect_get()
            .with(eq(api_user_token_path.api_key_id.clone()), eq(false))
            .returning(move |_, _| Ok(Some(token.clone())));
        token_store
            .expect_get()
            .with(eq(failure_api_user_token_path.api_key_id), eq(false))
            .returning(move |_, _| Err(StoreError::Unknown));
        token_store
            .expect_get()
            .with(eq(unknown_api_user_token_path.api_key_id), eq(false))
            .returning(move |_, _| Ok(None));

        let mut storage = MockStorage::new();
        storage.api_user_token_store = Some(Arc::new(token_store));

        let ctx = mock_context(Arc::new(storage)).await;

        let user1 = mock_user();

        // 1. Fail to get due to lack of permissions
        let no_permissions = Caller {
            id: user1.id,
            permissions: Permissions::new(),
            extensions: HashMap::default(),
        };

        let resp = get_api_user_token_inner::<VPermission, VPermissionResponse>(
            &ctx,
            no_permissions,
            api_user_token_path.clone(),
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);

        let user2 = mock_user();

        // 2. Fail to get due to incorrect permissions
        let incorrect_permissions = Caller {
            id: user2.id,
            permissions: vec![VPermission::GetApiKey(TypedUuid::new_v4())].into(),
            extensions: HashMap::default(),
        };

        let resp = get_api_user_token_inner::<VPermission, VPermissionResponse>(
            &ctx,
            incorrect_permissions,
            api_user_token_path.clone(),
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);

        let user3 = mock_user();

        // 3. Fail to get due to unknown token id
        let incorrect_permissions = Caller {
            id: user3.id,
            permissions: vec![VPermission::GetApiKey(
                unknown_api_user_token_path.api_key_id,
            )]
            .into(),
            extensions: HashMap::default(),
        };

        let resp = get_api_user_token_inner::<VPermission, VPermissionResponse>(
            &ctx,
            incorrect_permissions,
            unknown_api_user_token_path,
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::NOT_FOUND);

        let user4 = mock_user();

        // 4. Succeed in getting token
        let success_permissions = Caller {
            id: user4.id,
            permissions: vec![VPermission::GetApiKey(api_user_token_path.api_key_id)].into(),
            extensions: HashMap::default(),
        };

        let resp = get_api_user_token_inner::<VPermission, VPermissionResponse>(
            &ctx,
            success_permissions,
            api_user_token_path,
        )
        .await;

        assert!(resp.is_ok());
        assert_eq!(get_status(&resp), StatusCode::OK);

        let user5 = mock_user();

        // 5. Handle storage failure and return error
        let failure_permissions = Caller {
            id: user5.id,
            permissions: vec![VPermission::GetApiKey(
                failure_api_user_token_path.api_key_id,
            )]
            .into(),
            extensions: HashMap::default(),
        };

        let resp = get_api_user_token_inner::<VPermission, VPermissionResponse>(
            &ctx,
            failure_permissions,
            failure_api_user_token_path,
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_delete_api_user_token_permissions() {
        let api_user_id = TypedUuid::new_v4();

        let token = ApiKey {
            id: TypedUuid::new_v4(),
            user_id: api_user_id,
            key_signature: "encrypted_key".to_string(),
            permissions: None,
            expires_at: Utc::now() + TimeDelta::try_seconds(5 * 60).unwrap(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };

        let api_user_token_path = ApiUserTokenPath {
            user_id: api_user_id,
            api_key_id: token.id,
        };

        let failure_api_user_token_path = ApiUserTokenPath {
            user_id: api_user_id,
            api_key_id: TypedUuid::new_v4(),
        };

        let unknown_api_user_token_path = ApiUserTokenPath {
            user_id: api_user_id,
            api_key_id: TypedUuid::new_v4(),
        };

        let mut token_store = MockApiKeyStore::new();
        token_store
            .expect_delete()
            .with(eq(api_user_token_path.api_key_id))
            .returning(move |_| Ok(Some(token.clone())));
        token_store
            .expect_delete()
            .with(eq(failure_api_user_token_path.api_key_id))
            .returning(move |_| Err(StoreError::Unknown));
        token_store
            .expect_delete()
            .with(eq(unknown_api_user_token_path.api_key_id))
            .returning(move |_| Ok(None));

        let mut storage = MockStorage::new();
        storage.api_user_token_store = Some(Arc::new(token_store));

        let ctx = mock_context(Arc::new(storage)).await;

        let user1 = mock_user();

        // 1. Fail to get due to lack of permissions
        let no_permissions = Caller {
            id: user1.id,
            permissions: Permissions::new(),
            extensions: HashMap::default(),
        };

        let resp = delete_api_user_token_inner::<VPermission, VPermissionResponse>(
            &ctx,
            no_permissions,
            api_user_token_path.clone(),
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);

        let user2 = mock_user();

        // 2. Fail to get due to incorrect permissions
        let incorrect_permissions = Caller {
            id: user2.id,
            permissions: vec![VPermission::ManageApiKey(TypedUuid::new_v4())].into(),
            extensions: HashMap::default(),
        };

        let resp = delete_api_user_token_inner::<VPermission, VPermissionResponse>(
            &ctx,
            incorrect_permissions,
            api_user_token_path.clone(),
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);

        let user3 = mock_user();

        // 3. Fail to get due to unknown token id
        let incorrect_permissions = Caller {
            id: user3.id,
            permissions: vec![VPermission::ManageApiKey(
                unknown_api_user_token_path.api_key_id,
            )]
            .into(),
            extensions: HashMap::default(),
        };

        let resp = delete_api_user_token_inner::<VPermission, VPermissionResponse>(
            &ctx,
            incorrect_permissions,
            unknown_api_user_token_path,
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::NOT_FOUND);

        let user4 = mock_user();

        // 4. Succeed in getting token
        let success_permissions = Caller {
            id: user4.id,
            permissions: vec![VPermission::ManageApiKey(api_user_token_path.api_key_id)].into(),
            extensions: HashMap::default(),
        };

        let resp = delete_api_user_token_inner::<VPermission, VPermissionResponse>(
            &ctx,
            success_permissions,
            api_user_token_path,
        )
        .await;

        assert!(resp.is_ok());
        assert_eq!(get_status(&resp), StatusCode::OK);

        let user5 = mock_user();

        // 5. Handle storage failure and return error
        let failure_permissions = Caller {
            id: user5.id,
            permissions: vec![VPermission::ManageApiKey(
                failure_api_user_token_path.api_key_id,
            )]
            .into(),
            extensions: HashMap::default(),
        };

        let resp = delete_api_user_token_inner::<VPermission, VPermissionResponse>(
            &ctx,
            failure_permissions,
            failure_api_user_token_path,
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_set_api_user_contact_email() {
        let user = mock_user();

        let mut user_store = MockApiUserStore::new();
        let get_user = user.clone();
        user_store
            .expect_get()
            .with(eq(get_user.id), eq(false))
            .returning(move |_id, _deleted| {
                Ok(Some(ApiUserInfo {
                    user: ApiUser {
                        id: get_user.id,
                        permissions: get_user.permissions.clone(),
                        groups: BTreeSet::default(),
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                        deleted_at: None,
                    },
                    email: None,
                    providers: vec![ApiUserProvider {
                        id: TypedUuid::default(),
                        user_id: get_user.id,
                        provider: "custom".to_string(),
                        provider_id: "123".to_string(),
                        emails: vec!["user@company".to_string()],
                        display_names: vec![],
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                        deleted_at: None,
                    }],
                }))
            });
        let mut email_store = MockApiUserContactEmailStore::new();
        email_store
            .expect_upsert()
            .withf(move |arg| arg.user_id == user.id && arg.email == "user@company".to_string())
            .returning(|new| {
                Ok(ApiUserContactEmail {
                    id: new.id,
                    user_id: new.user_id,
                    email: new.email,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    deleted_at: None,
                })
            });

        let mut storage = MockStorage::new();
        storage.api_user_store = Some(Arc::new(user_store));
        storage.api_user_contact_email_store = Some(Arc::new(email_store));

        let ctx = mock_context(Arc::new(storage)).await;

        // 1. Fail to update due to no access
        let no_permissions = Caller {
            id: user.id,
            permissions: Permissions::new(),
            extensions: HashMap::default(),
        };
        let resp = set_api_user_contact_email_inner(
            &ctx,
            no_permissions,
            ApiUserPath { user_id: user.id },
            ApiUserEmailUpdateParams {
                email: "user@company".to_string(),
            },
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);

        // 2. Fail due to lack of write permission
        let no_write_permissions = Caller {
            id: user.id,
            permissions: vec![VPermission::GetApiUser(user.id)].into(),
            extensions: HashMap::default(),
        };
        let resp = set_api_user_contact_email_inner(
            &ctx,
            no_write_permissions,
            ApiUserPath { user_id: user.id },
            ApiUserEmailUpdateParams {
                email: "user@company".to_string(),
            },
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);

        // 4. Fail to update to non-owned email
        let write_permission = Caller {
            id: user.id,
            permissions: vec![VPermission::GetApiUser(user.id)].into(),
            extensions: HashMap::default(),
        };
        let resp = set_api_user_contact_email_inner(
            &ctx,
            write_permission,
            ApiUserPath { user_id: user.id },
            ApiUserEmailUpdateParams {
                email: "user-other@company".to_string(),
            },
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);

        // 5. Succeed in creating email
        let write_permission = Caller {
            id: user.id,
            permissions: vec![
                VPermission::GetApiUser(user.id),
                VPermission::ManageApiUser(user.id),
            ]
            .into(),
            extensions: HashMap::default(),
        };
        let resp = set_api_user_contact_email_inner(
            &ctx,
            write_permission,
            ApiUserPath { user_id: user.id },
            ApiUserEmailUpdateParams {
                email: "user@company".to_string(),
            },
        )
        .await;

        assert!(resp.is_ok());
        assert_eq!(get_status(&resp), StatusCode::OK);
        assert_eq!("user@company".to_string(), resp.unwrap().0.email);
    }
}
