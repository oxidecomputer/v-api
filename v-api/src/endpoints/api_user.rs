// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use dropshot::{
    HttpError, HttpResponseCreated, HttpResponseOk, HttpResponseUpdatedNoContent, Path,
    RequestContext, TypedBody,
};
use partial_struct::partial;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tap::TapFallible;
use tracing::instrument;
use uuid::Uuid;
use v_api_permissions::{Caller, Permission, Permissions};
use v_model::{
    storage::{ApiUserProviderFilter, ListPagination},
    ApiUser, ApiUserProvider, NewApiKey, NewApiUser,
};

use crate::{
    authn::key::RawApiKey,
    context::ApiContext,
    error::ApiError,
    permissions::{PermissionStorage, VAppPermission, VAppPermissionResponse},
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
    let ctx = rqctx.v_ctx();
    let auth = ctx.authn_token(&rqctx).await?;
    let caller = ctx.get_caller(auth.as_ref()).await?;
    let user = ctx.get_api_user(&caller, &caller.id).await?;

    let mut filter = ApiUserProviderFilter::default();
    filter.api_user_id = Some(vec![user.id]);
    let providers = ctx
        .list_api_user_provider(&caller, filter, &ListPagination::default().limit(10))
        .await?;

    tracing::trace!(user = ?serde_json::to_string(&user), "Found user");
    Ok(HttpResponseOk(GetUserResponse::new(user, providers)))
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
    let ctx = rqctx.v_ctx();
    let auth = ctx.authn_token(&rqctx).await?;
    let caller = ctx.get_caller(auth.as_ref()).await?;
    let path = path.into_inner();
    let user = ctx.get_api_user(&caller, &path.identifier).await?;

    let mut filter = ApiUserProviderFilter::default();
    filter.api_user_id = Some(vec![user.id]);
    let providers = ctx
        .list_api_user_provider(&caller, filter, &ListPagination::default().limit(10))
        .await?;

    tracing::trace!(user = ?serde_json::to_string(&user), "Found user");
    Ok(HttpResponseOk(GetUserResponse::new(user, providers)))
}

#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
pub struct ApiUserUpdateParams<T> {
    permissions: Permissions<T>,
    groups: BTreeSet<Uuid>,
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
    let ctx = rqctx.v_ctx();
    let auth = ctx.authn_token(&rqctx).await?;
    let caller = ctx.get_caller(auth.as_ref()).await?;
    let body = body.into_inner();

    create_api_user_inner(ctx, caller, body).await
}

pub async fn create_api_user_inner<T, U>(
    ctx: &VContext<T>,
    caller: Caller<T>,
    body: ApiUserUpdateParams<T>,
) -> Result<HttpResponseCreated<ApiUser<U>>, HttpError>
where
    T: VAppPermission + JsonSchema + PermissionStorage,
    U: VAppPermissionResponse + From<T> + JsonSchema,
{
    let user = ctx
        .create_api_user(&caller, body.permissions, body.groups)
        .await?;

    Ok(HttpResponseCreated(into_user_response(user)))
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct ApiUserPath {
    identifier: Uuid,
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
    let ctx = rqctx.v_ctx();
    let auth = ctx.authn_token(&rqctx).await?;
    let caller = ctx.get_caller(auth.as_ref()).await?;
    update_api_user_inner(ctx, caller, path, body).await
}

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
    let user = ctx
        .update_api_user(
            &caller,
            NewApiUser {
                id: path.identifier,
                permissions: body.permissions,
                groups: body.groups,
            },
        )
        .await?;

    Ok(HttpResponseOk(into_user_response(user)))
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
    let ctx = rqctx.v_ctx();
    let auth = ctx.authn_token(&rqctx).await?;
    let caller = ctx.get_caller(auth.as_ref()).await?;
    list_api_user_tokens_inner(ctx, caller, path).await
}

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
        .get_api_user_tokens(&caller, &path.identifier, &ListPagination::default())
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
pub struct ApiKeyCreateParams<T> {
    permissions: Option<Permissions<T>>,
    expires_at: DateTime<Utc>,
}

#[partial(ApiKeyResponse)]
#[derive(Debug, Serialize, JsonSchema)]
pub struct InitialApiKeyResponse<T> {
    pub id: Uuid,
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
    let ctx = rqctx.v_ctx();
    let auth = ctx.authn_token(&rqctx).await?;
    let caller = ctx.get_caller(auth.as_ref()).await?;
    create_api_user_token_inner(ctx, caller, path, body).await
}

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
    let api_user = ctx.get_api_user(&caller, &path.identifier).await?;

    let key_id = Uuid::new_v4();
    let key = RawApiKey::generate::<24>(&key_id)
        .sign(ctx.signer())
        .await
        .map_err(to_internal_error)?;

    let user_key = ctx
        .create_api_user_token(
            &caller,
            NewApiKey {
                id: key_id,
                api_user_id: path.identifier,
                key_signature: key.signature().to_string(),
                permissions: into_permissions(body.permissions),
                expires_at: body.expires_at,
            },
            &api_user.id,
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
    identifier: Uuid,
    token_identifier: Uuid,
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
    let ctx = rqctx.v_ctx();
    let auth = ctx.authn_token(&rqctx).await?;
    let caller = ctx.get_caller(auth.as_ref()).await?;
    get_api_user_token_inner(ctx, caller, path).await
}

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
        .get_api_user_token(&caller, &path.token_identifier)
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
    let ctx = rqctx.v_ctx();
    let auth = ctx.authn_token(&rqctx).await?;
    let caller = ctx.get_caller(auth.as_ref()).await?;
    delete_api_user_token_inner(ctx, caller, path).await
}

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
        .delete_api_user_token(&caller, &path.token_identifier)
        .await?;

    Ok(HttpResponseOk(ApiKeyResponse {
        id: token.id,
        permissions: into_permissions_response(token.permissions),
        created_at: token.created_at,
    }))
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct AddGroupBody {
    group_id: Uuid,
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
    let ctx = rqctx.v_ctx();
    let auth = ctx.authn_token(&rqctx).await?;
    let caller = ctx.get_caller(auth.as_ref()).await?;

    let user = ctx
        .add_api_user_to_group(&caller, &path.identifier, &body.group_id)
        .await?;

    Ok(HttpResponseOk(into_user_response(user)))
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApiUserRemoveGroupPath {
    identifier: Uuid,
    group_id: Uuid,
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
    let ctx = rqctx.v_ctx();
    let auth = ctx.authn_token(&rqctx).await?;
    let caller = ctx.get_caller(auth.as_ref()).await?;

    let user = ctx
        .remove_api_user_from_group(&caller, &path.identifier, &path.group_id)
        .await?;

    Ok(HttpResponseOk(into_user_response(user)))
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
    let ctx = rqctx.v_ctx();
    let auth = ctx.authn_token(&rqctx).await?;
    let caller = ctx.get_caller(auth.as_ref()).await?;

    // TODO: This permission check indicates that the permission modeling for this functionality
    // is not sufficient. Need to rethink it
    //
    // This endpoint can only be called by the user themselves, it can not be performed on behalf
    // of a user
    if path.identifier == caller.id {
        let secret = RawApiKey::try_from(body.token.as_str()).map_err(|err| {
            tracing::debug!(?err, "Invalid link request token");
            bad_request("Malformed link request token")
        })?;
        let link_request_id = Uuid::from_slice(secret.id()).map_err(|err| {
            tracing::debug!(?err, "Failed to parse link request id from token");
            bad_request("Invalid link request token")
        })?;

        // TODO: We need an actual permission for reading a LinkRequest
        let link_request = ctx
            .get_link_request(&link_request_id)
            .await
            .map_err(ApiError::Storage)?
            .ok_or_else(|| not_found("Failed to find identifier"))?;

        // TODO: How can this check be lowered to the context (including a proper permission check)

        // Verify that the found link request is assigned to the user calling the endpoint and that
        // the token provided matches the stored signature
        if link_request.target_api_user_id == caller.id
            && secret
                .verify(ctx.signer(), link_request.secret_signature.as_bytes())
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
    use std::{collections::BTreeSet, sync::Arc};

    use chrono::{Duration, Utc};
    use http::StatusCode;
    use mockall::predicate::eq;
    use uuid::Uuid;
    use v_api_permissions::{Caller, Permissions};
    use v_model::{
        storage::{ApiKeyFilter, ListPagination, MockApiKeyStore, MockApiUserStore, StoreError},
        ApiKey, ApiUser, NewApiUser,
    };

    use crate::{
        context::test_mocks::{mock_context, MockStorage},
        endpoints::api_user::{
            create_api_user_inner, create_api_user_token_inner, delete_api_user_token_inner,
            get_api_user_token_inner, list_api_user_tokens_inner, update_api_user_inner,
            ApiKeyCreateParams, ApiUserPath, ApiUserTokenPath,
        },
        permissions::{VPermission, VPermissionResponse},
        util::tests::get_status,
    };

    use super::ApiUserUpdateParams;

    fn mock_user() -> ApiUser<VPermission> {
        ApiUser {
            id: Uuid::new_v4(),
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
            groups: BTreeSet::new(),
        };

        let failure_update = ApiUserUpdateParams {
            permissions: vec![VPermission::GetApiUserAll].into(),
            groups: BTreeSet::new(),
        };

        let mut store = MockApiUserStore::new();
        store
            .expect_upsert()
            .withf(|x: &NewApiUser<VPermission>| {
                x.permissions.can(&VPermission::CreateApiUser.into())
            })
            .returning(|user| {
                Ok(ApiUser {
                    id: user.id,
                    permissions: user.permissions,
                    groups: BTreeSet::new(),
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    deleted_at: None,
                })
            });
        store
            .expect_upsert()
            .withf(|x: &NewApiUser<VPermission>| {
                x.permissions.can(&VPermission::GetApiUserAll.into())
            })
            .returning(|_| Err(StoreError::Unknown));

        let mut storage = MockStorage::new();
        storage.api_user_store = Some(Arc::new(store));

        let ctx = mock_context(storage).await;

        let user1 = mock_user();

        // 1. Fail to create due to lack of permissions
        let no_permissions = Caller {
            id: user1.id,
            permissions: Permissions::new(),
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
        let success_id = Uuid::new_v4();
        let successful_update = ApiUserUpdateParams {
            permissions: Permissions::new(),
            groups: BTreeSet::new(),
        };

        let failure_id = Uuid::new_v4();
        let failure_update = ApiUserUpdateParams {
            permissions: Permissions::new(),
            groups: BTreeSet::new(),
        };

        let mut store = MockApiUserStore::new();
        store
            .expect_upsert()
            .withf(move |x: &NewApiUser<VPermission>| &x.id == &success_id)
            .returning(|user| {
                Ok(ApiUser {
                    id: user.id,
                    permissions: user.permissions,
                    groups: BTreeSet::new(),
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    deleted_at: None,
                })
            });
        store
            .expect_upsert()
            .withf(move |x: &NewApiUser<VPermission>| &x.id == &failure_id)
            .returning(|_| Err(StoreError::Unknown));

        let mut storage = MockStorage::new();
        storage.api_user_store = Some(Arc::new(store));

        let ctx = mock_context(storage).await;

        let success_path = ApiUserPath {
            identifier: success_id,
        };
        let failure_path = ApiUserPath {
            identifier: failure_id,
        };

        let user1 = mock_user();

        // 1. Fail to create due to lack of permissions
        let no_permissions = Caller {
            id: user1.id,
            permissions: Permissions::new(),
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
            permissions: vec![VPermission::UpdateApiUser(success_path.identifier)].into(),
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
            permissions: vec![VPermission::UpdateApiUserAll].into(),
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
        let success_id = Uuid::new_v4();
        let failure_id = Uuid::new_v4();

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

        let ctx = mock_context(storage).await;

        let user1 = mock_user();

        // 1. Fail to list due to lack of permissions
        let no_permissions = Caller {
            id: user1.id,
            permissions: Permissions::new(),
        };

        let resp = list_api_user_tokens_inner::<VPermission, VPermissionResponse>(
            &ctx,
            no_permissions,
            ApiUserPath {
                identifier: success_id,
            },
        )
        .await;

        assert!(resp.is_ok());
        assert_eq!(resp.unwrap().0.len(), 0);

        let user2 = mock_user();

        // 2. Fail to list due to incorrect permissions
        let incorrect_permissions = Caller {
            id: user2.id,
            permissions: vec![VPermission::GetApiUserToken(Uuid::new_v4())].into(),
        };

        let resp = list_api_user_tokens_inner::<VPermission, VPermissionResponse>(
            &ctx,
            incorrect_permissions,
            ApiUserPath {
                identifier: success_id,
            },
        )
        .await;

        assert!(resp.is_ok());
        assert_eq!(resp.unwrap().0.len(), 0);

        let user3 = mock_user();

        // 3. Succeed in list tokens
        let success_permissions = Caller {
            id: user3.id,
            permissions: vec![VPermission::GetApiUserToken(success_id)].into(),
        };

        let resp = list_api_user_tokens_inner::<VPermission, VPermissionResponse>(
            &ctx,
            success_permissions,
            ApiUserPath {
                identifier: success_id,
            },
        )
        .await;

        assert!(resp.is_ok());
        assert_eq!(get_status(&resp), StatusCode::OK);

        let user4 = mock_user();

        // 4. Handle storage failure and return error
        let failure_permissions = Caller {
            id: user4.id,
            permissions: vec![VPermission::GetApiUserToken(failure_id)].into(),
        };

        let resp = list_api_user_tokens_inner::<VPermission, VPermissionResponse>(
            &ctx,
            failure_permissions,
            ApiUserPath {
                identifier: failure_id,
            },
        )
        .await;

        assert!(resp.is_err());
        assert_eq!(get_status(&resp), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_create_api_user_token_permissions() {
        let api_user_id = Uuid::new_v4();

        let api_user = ApiUser {
            id: api_user_id,
            permissions: vec![VPermission::GetApiUserToken(api_user_id)].into(),
            groups: BTreeSet::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };

        let api_user_path = ApiUserPath {
            identifier: api_user.id,
        };

        let failure_api_user_path = ApiUserPath {
            identifier: Uuid::new_v4(),
        };

        let unknown_api_user_path = ApiUserPath {
            identifier: Uuid::new_v4(),
        };

        let new_token = ApiKeyCreateParams {
            permissions: None,
            expires_at: Utc::now() + Duration::seconds(5 * 60),
        };

        let mut api_user_store = MockApiUserStore::new();
        api_user_store
            .expect_get()
            .with(eq(api_user_path.identifier), eq(false))
            .returning(move |_, _| Ok(Some(api_user.clone())));
        api_user_store
            .expect_get()
            .with(eq(failure_api_user_path.identifier), eq(false))
            .returning(|_, _| Err(StoreError::Unknown));
        api_user_store
            .expect_get()
            .with(eq(unknown_api_user_path.identifier), eq(false))
            .returning(move |_, _| Ok(None));

        let mut token_store = MockApiKeyStore::new();
        token_store
            .expect_upsert()
            // .withf(move |_, user| user.id == api_user_id)
            .returning(move |key| {
                Ok(ApiKey {
                    id: Uuid::new_v4(),
                    api_user_id: api_user_id,
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

        let ctx = mock_context(storage).await;

        let user1 = mock_user();

        // 1. Fail to create due to lack of permissions
        let no_permissions = Caller {
            id: user1.id,
            permissions: Permissions::new(),
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
            permissions: vec![VPermission::CreateApiUserToken(Uuid::new_v4())].into(),
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
                VPermission::GetApiUser(unknown_api_user_path.identifier),
                VPermission::CreateApiUserToken(unknown_api_user_path.identifier),
            ]
            .into(),
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
                VPermission::GetApiUser(api_user_path.identifier),
                VPermission::CreateApiUserToken(api_user_path.identifier),
            ]
            .into(),
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
                VPermission::GetApiUser(failure_api_user_path.identifier),
                VPermission::CreateApiUserToken(failure_api_user_path.identifier),
            ]
            .into(),
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
        let api_user_id = Uuid::new_v4();

        let token = ApiKey {
            id: Uuid::new_v4(),
            api_user_id: api_user_id,
            key_signature: "encrypted_key".to_string(),
            permissions: None,
            expires_at: Utc::now() + Duration::seconds(5 * 60),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };

        let api_user_token_path = ApiUserTokenPath {
            identifier: api_user_id,
            token_identifier: token.id,
        };

        let failure_api_user_token_path = ApiUserTokenPath {
            identifier: api_user_id,
            token_identifier: Uuid::new_v4(),
        };

        let unknown_api_user_token_path = ApiUserTokenPath {
            identifier: api_user_id,
            token_identifier: Uuid::new_v4(),
        };

        let mut token_store = MockApiKeyStore::new();
        token_store
            .expect_get()
            .with(eq(api_user_token_path.token_identifier.clone()), eq(false))
            .returning(move |_, _| Ok(Some(token.clone())));
        token_store
            .expect_get()
            .with(eq(failure_api_user_token_path.token_identifier), eq(false))
            .returning(move |_, _| Err(StoreError::Unknown));
        token_store
            .expect_get()
            .with(eq(unknown_api_user_token_path.token_identifier), eq(false))
            .returning(move |_, _| Ok(None));

        let mut storage = MockStorage::new();
        storage.api_user_token_store = Some(Arc::new(token_store));

        let ctx = mock_context(storage).await;

        let user1 = mock_user();

        // 1. Fail to get due to lack of permissions
        let no_permissions = Caller {
            id: user1.id,
            permissions: Permissions::new(),
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
            permissions: vec![VPermission::GetApiUserToken(Uuid::new_v4())].into(),
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
            permissions: vec![VPermission::GetApiUserToken(
                unknown_api_user_token_path.token_identifier,
            )]
            .into(),
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
            permissions: vec![VPermission::GetApiUserToken(
                api_user_token_path.token_identifier,
            )]
            .into(),
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
            permissions: vec![VPermission::GetApiUserToken(
                failure_api_user_token_path.token_identifier,
            )]
            .into(),
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
        let api_user_id = Uuid::new_v4();

        let token = ApiKey {
            id: Uuid::new_v4(),
            api_user_id: api_user_id,
            key_signature: "encrypted_key".to_string(),
            permissions: None,
            expires_at: Utc::now() + Duration::seconds(5 * 60),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };

        let api_user_token_path = ApiUserTokenPath {
            identifier: api_user_id,
            token_identifier: token.id,
        };

        let failure_api_user_token_path = ApiUserTokenPath {
            identifier: api_user_id,
            token_identifier: Uuid::new_v4(),
        };

        let unknown_api_user_token_path = ApiUserTokenPath {
            identifier: api_user_id,
            token_identifier: Uuid::new_v4(),
        };

        let mut token_store = MockApiKeyStore::new();
        token_store
            .expect_delete()
            .with(eq(api_user_token_path.token_identifier))
            .returning(move |_| Ok(Some(token.clone())));
        token_store
            .expect_delete()
            .with(eq(failure_api_user_token_path.token_identifier))
            .returning(move |_| Err(StoreError::Unknown));
        token_store
            .expect_delete()
            .with(eq(unknown_api_user_token_path.token_identifier))
            .returning(move |_| Ok(None));

        let mut storage = MockStorage::new();
        storage.api_user_token_store = Some(Arc::new(token_store));

        let ctx = mock_context(storage).await;

        let user1 = mock_user();

        // 1. Fail to get due to lack of permissions
        let no_permissions = Caller {
            id: user1.id,
            permissions: Permissions::new(),
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
            permissions: vec![VPermission::DeleteApiUserToken(Uuid::new_v4())].into(),
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
            permissions: vec![VPermission::DeleteApiUserToken(
                unknown_api_user_token_path.token_identifier,
            )]
            .into(),
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
            permissions: vec![VPermission::DeleteApiUserToken(
                api_user_token_path.token_identifier,
            )]
            .into(),
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
            permissions: vec![VPermission::DeleteApiUserToken(
                failure_api_user_token_path.token_identifier,
            )]
            .into(),
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
}
