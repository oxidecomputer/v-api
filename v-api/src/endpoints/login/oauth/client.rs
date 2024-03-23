// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{DateTime, Utc};
use dropshot::{HttpError, HttpResponseCreated, HttpResponseOk, Path, RequestContext, TypedBody};
use newtype_uuid::{GenericUuid, TypedUuid};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use v_model::{
    permissions::Caller, OAuthClient, OAuthClientId, OAuthClientRedirectUri, OAuthClientSecret,
    OAuthRedirectUriId, OAuthSecretId,
};

use crate::{
    authn::key::RawApiKey,
    context::{ApiContext, VContextWithCaller},
    permissions::{PermissionStorage, VAppPermission, VPermission},
    secrets::OpenApiSecretString,
    util::response::to_internal_error,
    VContext,
};

#[instrument(skip(rqctx), err(Debug))]
pub async fn list_oauth_clients_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
) -> Result<HttpResponseOk<Vec<OAuthClient>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    Ok(HttpResponseOk(ctx.list_oauth_clients(&caller).await?))
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn create_oauth_client_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
) -> Result<HttpResponseCreated<OAuthClient>, HttpError>
where
    T: VAppPermission + From<VPermission> + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    create_oauth_client_inner(ctx, caller).await
}

#[instrument(skip(ctx, caller), err(Debug))]
pub async fn create_oauth_client_inner<T>(
    ctx: &VContext<T>,
    caller: Caller<T>,
) -> Result<HttpResponseCreated<OAuthClient>, HttpError>
where
    T: VAppPermission + From<VPermission> + PermissionStorage,
{
    // Create the new client
    let client = ctx.create_oauth_client(&caller).await?;

    // Give the caller permission to perform actions on the client
    ctx.add_permissions_to_user(
        &caller,
        &caller.id,
        vec![
            VPermission::GetOAuthClient(client.id),
            VPermission::ManageOAuthClient(client.id),
        ]
        .into(),
    )
    .await?;

    Ok(HttpResponseCreated(client))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GetOAuthClientPath {
    pub client_id: TypedUuid<OAuthClientId>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn get_oauth_client_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<GetOAuthClientPath>,
) -> Result<HttpResponseOk<OAuthClient>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let path = path.into_inner();
    Ok(HttpResponseOk(
        ctx.get_oauth_client(&caller, &path.client_id).await?,
    ))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AddOAuthClientSecretPath {
    pub client_id: TypedUuid<OAuthClientId>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct InitialOAuthClientSecretResponse {
    pub id: TypedUuid<OAuthSecretId>,
    pub key: OpenApiSecretString,
    pub created_at: DateTime<Utc>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn create_oauth_client_secret_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<AddOAuthClientSecretPath>,
) -> Result<HttpResponseOk<InitialOAuthClientSecretResponse>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let client_id = path.into_inner().client_id;
    create_oauth_client_secret_inner(ctx, caller, &client_id).await
}

#[instrument(skip(ctx, caller), err(Debug))]
pub async fn create_oauth_client_secret_inner<T>(
    ctx: &VContext<T>,
    caller: Caller<T>,
    client_id: &TypedUuid<OAuthClientId>,
) -> Result<HttpResponseOk<InitialOAuthClientSecretResponse>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let id = TypedUuid::new_v4();
    let secret = RawApiKey::generate::<24>(id.as_untyped_uuid())
        .sign(ctx.signer())
        .await
        .map_err(to_internal_error)?;
    let client_secret = ctx
        .add_oauth_secret(&caller, &id, client_id, secret.signature())
        .await?;

    Ok(HttpResponseOk(InitialOAuthClientSecretResponse {
        id: client_secret.id,
        key: secret.key().into(),
        created_at: client_secret.created_at,
    }))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct DeleteOAuthClientSecretPath {
    pub client_id: TypedUuid<OAuthClientId>,
    pub secret_id: TypedUuid<OAuthSecretId>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn delete_oauth_client_secret_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<DeleteOAuthClientSecretPath>,
) -> Result<HttpResponseOk<OAuthClientSecret>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let path = path.into_inner();
    Ok(HttpResponseOk(
        ctx.delete_oauth_secret(&caller, &path.secret_id, &path.client_id)
            .await?,
    ))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AddOAuthClientRedirectPath {
    pub client_id: TypedUuid<OAuthClientId>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AddOAuthClientRedirectBody {
    pub redirect_uri: String,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn create_oauth_client_redirect_uri_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<AddOAuthClientRedirectPath>,
    body: TypedBody<AddOAuthClientRedirectBody>,
) -> Result<HttpResponseOk<OAuthClientRedirectUri>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let path = path.into_inner();
    let body = body.into_inner();
    Ok(HttpResponseOk(
        ctx.add_oauth_redirect_uri(&caller, &path.client_id, &body.redirect_uri)
            .await?,
    ))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct DeleteOAuthClientRedirectPath {
    pub client_id: TypedUuid<OAuthClientId>,
    pub redirect_uri_id: TypedUuid<OAuthRedirectUriId>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn delete_oauth_client_redirect_uri_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<DeleteOAuthClientRedirectPath>,
) -> Result<HttpResponseOk<OAuthClientRedirectUri>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let path = path.into_inner();
    Ok(HttpResponseOk(
        ctx.delete_oauth_redirect_uri(&caller, &path.redirect_uri_id, &path.client_id)
            .await?,
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{Arc, Mutex},
    };

    use chrono::Utc;
    use mockall::predicate::eq;
    use newtype_uuid::TypedUuid;
    use v_model::{
        permissions::Caller,
        storage::{MockApiUserStore, MockOAuthClientSecretStore, MockOAuthClientStore},
        ApiUser, OAuthClient, OAuthClientSecret,
    };

    use crate::{
        authn::key::RawApiKey,
        context::test_mocks::{mock_context, MockStorage},
        endpoints::login::oauth::{
            client::{create_oauth_client_inner, create_oauth_client_secret_inner},
            CheckOAuthClient,
        },
        permissions::VPermission,
    };

    fn mock_user() -> ApiUser<VPermission> {
        let user_id = TypedUuid::new_v4();
        ApiUser {
            id: user_id,
            permissions: vec![
                VPermission::CreateOAuthClient,
                VPermission::GetApiUser(user_id),
                VPermission::ManageApiUser(user_id),
            ]
            .into(),
            groups: BTreeSet::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        }
    }

    #[tokio::test]
    async fn test_create_client_with_secret() {
        let user = mock_user();
        let mut caller = Caller {
            id: user.id,
            permissions: user.permissions.clone(),
        };

        let mut user_store = MockApiUserStore::new();
        user_store
            .expect_get()
            .with(eq(user.id), eq(false))
            .returning(move |_, _| Ok(Some(user.clone())));
        user_store.expect_upsert().returning(|user| {
            Ok(ApiUser {
                id: user.id,
                permissions: user.permissions,
                groups: user.groups,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                deleted_at: None,
            })
        });

        let mut store = MockOAuthClientStore::new();
        store.expect_upsert().returning(|client| {
            Ok(OAuthClient {
                id: client.id,
                secrets: vec![],
                redirect_uris: vec![],
                created_at: Utc::now(),
                deleted_at: None,
            })
        });

        let last_stored_secret = Arc::new(Mutex::new(None));

        let mut secret_store = MockOAuthClientSecretStore::new();
        let extractor = last_stored_secret.clone();
        secret_store.expect_upsert().returning(move |secret| {
            let stored = OAuthClientSecret {
                id: secret.id,
                oauth_client_id: secret.oauth_client_id,
                secret_signature: secret.secret_signature,
                created_at: Utc::now(),
                deleted_at: None,
            };

            let mut extract = extractor.lock().unwrap();
            *extract = Some(stored.clone());
            drop(extract);

            Ok(stored)
        });

        let mut storage = MockStorage::new();
        storage.api_user_store = Some(Arc::new(user_store));
        storage.oauth_client_store = Some(Arc::new(store));
        storage.oauth_client_secret_store = Some(Arc::new(secret_store));

        let ctx = mock_context(storage).await;

        let mut client = create_oauth_client_inner(&ctx, caller.clone())
            .await
            .unwrap()
            .0;
        caller
            .permissions
            .insert(VPermission::ManageOAuthClient(client.id));

        let secret = create_oauth_client_secret_inner(&ctx, caller, &client.id)
            .await
            .unwrap()
            .0;
        client
            .secrets
            .push(last_stored_secret.lock().unwrap().clone().unwrap());

        let key = RawApiKey::try_from(&secret.key.0).unwrap();

        assert!(client.is_secret_valid(&key, ctx.signer()))
    }
}
