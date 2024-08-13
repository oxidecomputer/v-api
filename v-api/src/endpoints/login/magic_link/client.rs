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
    permissions::{Caller, PermissionStorage},
    MagicLink, MagicLinkId, MagicLinkRedirectUri, MagicLinkRedirectUriId, MagicLinkSecret,
    MagicLinkSecretId,
};

use crate::{
    authn::key::RawKey,
    context::{ApiContext, VContextWithCaller},
    permissions::{VAppPermission, VPermission},
    secrets::OpenApiSecretString,
    util::response::to_internal_error,
    VContext,
};

#[instrument(skip(rqctx), err(Debug))]
pub async fn list_magic_links_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
) -> Result<HttpResponseOk<Vec<MagicLink>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    Ok(HttpResponseOk(
        ctx.magic_link.list_magic_links(&caller).await?,
    ))
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn create_magic_link_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
) -> Result<HttpResponseCreated<MagicLink>, HttpError>
where
    T: VAppPermission + From<VPermission> + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    create_magic_link_inner(ctx, caller).await
}

#[instrument(skip(ctx, caller), err(Debug))]
pub async fn create_magic_link_inner<T>(
    ctx: &VContext<T>,
    caller: Caller<T>,
) -> Result<HttpResponseCreated<MagicLink>, HttpError>
where
    T: VAppPermission + From<VPermission> + PermissionStorage,
{
    // Create the new client
    let client = ctx.magic_link.create_magic_link(&caller).await?;

    // Give the caller permission to perform actions on the client
    ctx.user
        .add_permissions_to_user(
            &caller,
            &caller.id,
            vec![
                VPermission::GetMagicLinkClient(client.id),
                VPermission::ManageMagicLinkClient(client.id),
            ]
            .into(),
        )
        .await?;

    Ok(HttpResponseCreated(client))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GetMagicLinkPath {
    pub client_id: TypedUuid<MagicLinkId>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn get_magic_link_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<GetMagicLinkPath>,
) -> Result<HttpResponseOk<MagicLink>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let path = path.into_inner();
    Ok(HttpResponseOk(
        ctx.magic_link
            .get_magic_link(&caller, &path.client_id)
            .await?,
    ))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AddMagicLinkSecretPath {
    pub client_id: TypedUuid<MagicLinkId>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct InitialMagicLinkSecretResponse {
    pub id: TypedUuid<MagicLinkSecretId>,
    pub key: OpenApiSecretString,
    pub created_at: DateTime<Utc>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn create_magic_link_secret_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<AddMagicLinkSecretPath>,
) -> Result<HttpResponseOk<InitialMagicLinkSecretResponse>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let client_id = path.into_inner().client_id;
    create_magic_link_secret_inner(ctx, caller, &client_id).await
}

#[instrument(skip(ctx, caller), err(Debug))]
pub async fn create_magic_link_secret_inner<T>(
    ctx: &VContext<T>,
    caller: Caller<T>,
    client_id: &TypedUuid<MagicLinkId>,
) -> Result<HttpResponseOk<InitialMagicLinkSecretResponse>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let id = TypedUuid::new_v4();
    let secret = RawKey::generate::<24>(id.as_untyped_uuid())
        .sign(ctx.signer())
        .await
        .map_err(to_internal_error)?;
    let client_secret = ctx
        .magic_link
        .add_magic_link_secret(&caller, &id, client_id, secret.signature())
        .await?;

    Ok(HttpResponseOk(InitialMagicLinkSecretResponse {
        id: client_secret.id,
        key: secret.key().into(),
        created_at: client_secret.created_at,
    }))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct DeleteMagicLinkSecretPath {
    pub client_id: TypedUuid<MagicLinkId>,
    pub secret_id: TypedUuid<MagicLinkSecretId>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn delete_magic_link_secret_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<DeleteMagicLinkSecretPath>,
) -> Result<HttpResponseOk<MagicLinkSecret>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let path = path.into_inner();
    Ok(HttpResponseOk(
        ctx.magic_link
            .delete_magic_link_secret(&caller, &path.secret_id, &path.client_id)
            .await?,
    ))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AddMagicLinkRedirectPath {
    pub client_id: TypedUuid<MagicLinkId>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AddMagicLinkRedirectBody {
    pub redirect_uri: String,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn create_magic_link_redirect_uri_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<AddMagicLinkRedirectPath>,
    body: TypedBody<AddMagicLinkRedirectBody>,
) -> Result<HttpResponseOk<MagicLinkRedirectUri>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let path = path.into_inner();
    let body = body.into_inner();
    Ok(HttpResponseOk(
        ctx.magic_link
            .add_magic_link_redirect_uri(&caller, &path.client_id, &body.redirect_uri)
            .await?,
    ))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct DeleteMagicLinkRedirectPath {
    pub client_id: TypedUuid<MagicLinkId>,
    pub redirect_uri_id: TypedUuid<MagicLinkRedirectUriId>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn delete_magic_link_redirect_uri_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<DeleteMagicLinkRedirectPath>,
) -> Result<HttpResponseOk<MagicLinkRedirectUri>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let path = path.into_inner();
    Ok(HttpResponseOk(
        ctx.magic_link
            .delete_magic_link_redirect_uri(&caller, &path.redirect_uri_id, &path.client_id)
            .await?,
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, HashMap},
        sync::{Arc, Mutex},
    };

    use chrono::Utc;
    use mockall::predicate::eq;
    use newtype_uuid::TypedUuid;
    use v_model::{
        permissions::Caller,
        storage::{MockApiUserStore, MockMagicLinkSecretStore, MockMagicLinkStore},
        ApiUser, ApiUserInfo, MagicLink, MagicLinkSecret,
    };

    use crate::{
        authn::key::RawKey,
        context::test_mocks::{mock_context, MockStorage},
        endpoints::login::magic_link::{
            client::{create_magic_link_inner, create_magic_link_secret_inner},
            CheckMagicLinkClient,
        },
        permissions::VPermission,
    };

    fn mock_user() -> ApiUser<VPermission> {
        let user_id = TypedUuid::new_v4();
        ApiUser {
            id: user_id,
            permissions: vec![
                VPermission::CreateMagicLinkClient,
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
            extensions: HashMap::default(),
        };

        let mut user_store = MockApiUserStore::new();
        user_store
            .expect_get()
            .with(eq(user.id), eq(false))
            .returning(move |_, _| {
                Ok(Some(ApiUserInfo {
                    user: user.clone(),
                    providers: vec![],
                }))
            });
        user_store.expect_upsert().returning(|user| {
            Ok(ApiUserInfo {
                user: ApiUser {
                    id: user.id,
                    permissions: user.permissions,
                    groups: user.groups,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    deleted_at: None,
                },
                providers: vec![],
            })
        });

        let mut store = MockMagicLinkStore::new();
        store.expect_upsert().returning(|client| {
            Ok(MagicLink {
                id: client.id,
                secrets: vec![],
                redirect_uris: vec![],
                created_at: Utc::now(),
                deleted_at: None,
            })
        });

        let last_stored_secret = Arc::new(Mutex::new(None));

        let mut secret_store = MockMagicLinkSecretStore::new();
        let extractor = last_stored_secret.clone();
        secret_store.expect_upsert().returning(move |secret| {
            let stored = MagicLinkSecret {
                id: secret.id,
                magic_link_client_id: secret.magic_link_client_id,
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
        storage.magic_link_store = Some(Arc::new(store));
        storage.magic_link_secret_store = Some(Arc::new(secret_store));

        let ctx = mock_context(Arc::new(storage)).await;

        let mut client = create_magic_link_inner(&ctx, caller.clone())
            .await
            .unwrap()
            .0;
        caller
            .permissions
            .insert(VPermission::ManageMagicLinkClient(client.id));

        let secret = create_magic_link_secret_inner(&ctx, caller, &client.id)
            .await
            .unwrap()
            .0;
        client
            .secrets
            .push(last_stored_secret.lock().unwrap().clone().unwrap());

        let key = RawKey::try_from(&secret.key.0).unwrap();

        assert!(client.is_secret_valid(&key, ctx.signer()))
    }
}
