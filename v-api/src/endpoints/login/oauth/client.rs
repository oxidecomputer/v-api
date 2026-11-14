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
    OAuthClient, OAuthClientId, OAuthClientKey, OAuthClientKeyId, OAuthClientRedirectUri,
    OAuthClientSecret, OAuthRedirectUriId, OAuthSecretId, Permissions, ServiceAccountToken,
    ServiceAccountTokenId,
    permissions::{Caller, Permission, PermissionStorage},
};

use crate::{
    VContext,
    authn::{client_key::SubmittedJwk, key::RawKey},
    context::{ApiContext, VContextWithCaller, oauth::OAuthError},
    permissions::{VAppPermission, VPermission},
    response::{ResourceError, bad_request, forbidden},
    secrets::OpenApiSecretString,
    util::response::to_internal_error,
};

#[instrument(skip(rqctx), err(Debug))]
pub async fn list_oauth_clients_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
) -> Result<HttpResponseOk<Vec<OAuthClient>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    Ok(HttpResponseOk(ctx.oauth.list_oauth_clients(&caller).await?))
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
    // Only users are allowed to create clients.
    let creator = caller.user_id().ok_or_else(forbidden)?;

    // Create the new client
    let client = ctx
        .oauth
        .create_oauth_client(&caller, TypedUuid::new_v4())
        .await?;

    // Give the caller permission to perform actions on the client they just created.
    // This uses the registration caller which has sufficient privileges to grant these
    // permissions on behalf of the system.
    let registration_caller = ctx.builtin_registration_user();
    ctx.user
        .add_permissions_to_user(
            &registration_caller,
            &creator,
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
        ctx.oauth.get_oauth_client(&caller, &path.client_id).await?,
    ))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct OAuthClientPermissionPath {
    pub client_id: TypedUuid<OAuthClientId>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct OAuthClientPermissionParams<T> {
    pub permission: T,
}

fn into_permissions_response<T, U>(permissions: Permissions<T>) -> Permissions<U>
where
    T: Permission,
    U: Permission + From<T>,
{
    permissions.into_iter().map(|p| p.into()).collect()
}

/// Lists the permissions a client holds when it acts as a service account.
#[instrument(skip(rqctx), err(Debug))]
pub async fn get_oauth_client_permissions_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<OAuthClientPermissionPath>,
) -> Result<HttpResponseOk<Permissions<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: Permission + From<T> + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let client_id = path.into_inner().client_id;
    Ok(HttpResponseOk(into_permissions_response(
        ctx.oauth
            .get_service_account_permissions(&caller, &client_id)
            .await?,
    )))
}

/// Grants a single permission to a client's service account. The caller must be able to manage
/// the client and grant the permission.
#[instrument(skip(rqctx, body), err(Debug))]
pub async fn add_oauth_client_permission_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<OAuthClientPermissionPath>,
    body: OAuthClientPermissionParams<T>,
) -> Result<HttpResponseOk<Permissions<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: Permission + From<T> + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    add_oauth_client_permission_inner(ctx, caller, &path.into_inner().client_id, body).await
}

#[instrument(skip(ctx, caller, body), err(Debug))]
pub async fn add_oauth_client_permission_inner<T, U>(
    ctx: &VContext<T>,
    caller: Caller<T>,
    client_id: &TypedUuid<OAuthClientId>,
    body: OAuthClientPermissionParams<T>,
) -> Result<HttpResponseOk<Permissions<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: Permission + From<T> + JsonSchema,
{
    Ok(HttpResponseOk(into_permissions_response(
        ctx.oauth
            .add_permission_to_service_account(&caller, client_id, body.permission)
            .await?,
    )))
}

/// Removes a single permission from a client's service account. The caller must be able to
/// manage the client and grant the permission being removed.
#[instrument(skip(rqctx, body), err(Debug))]
pub async fn remove_oauth_client_permission_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<OAuthClientPermissionPath>,
    body: OAuthClientPermissionParams<T>,
) -> Result<HttpResponseOk<Permissions<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: Permission + From<T> + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    remove_oauth_client_permission_inner(ctx, caller, &path.into_inner().client_id, body).await
}

#[instrument(skip(ctx, caller, body), err(Debug))]
pub async fn remove_oauth_client_permission_inner<T, U>(
    ctx: &VContext<T>,
    caller: Caller<T>,
    client_id: &TypedUuid<OAuthClientId>,
    body: OAuthClientPermissionParams<T>,
) -> Result<HttpResponseOk<Permissions<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: Permission + From<T> + JsonSchema,
{
    Ok(HttpResponseOk(into_permissions_response(
        ctx.oauth
            .remove_permission_from_service_account(&caller, client_id, &body.permission)
            .await?,
    )))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct AddOAuthClientKeyPath {
    pub client_id: TypedUuid<OAuthClientId>,
}

// TODO: Only Ed25519 keys are accepted currently. We need to expand this.
/// Registers the public half of a key pair that a client signs its client credentials assertions
/// with. The client keeps the private key, and its assertions are verified against this public
/// key.
#[instrument(skip(rqctx, body), err(Debug))]
pub async fn add_oauth_client_key_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<AddOAuthClientKeyPath>,
    body: TypedBody<SubmittedJwk>,
) -> Result<HttpResponseOk<OAuthClientKey>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    add_oauth_client_key_inner(ctx, caller, &path.into_inner().client_id, body.into_inner()).await
}

#[instrument(skip(ctx, caller, jwk), err(Debug))]
pub async fn add_oauth_client_key_inner<T>(
    ctx: &VContext<T>,
    caller: Caller<T>,
    client_id: &TypedUuid<OAuthClientId>,
    jwk: SubmittedJwk,
) -> Result<HttpResponseOk<OAuthClientKey>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    Ok(HttpResponseOk(
        ctx.oauth
            .add_oauth_client_key(&caller, client_id, jwk.into_public_jwk())
            .await
            .map_err(|err| match err {
                ResourceError::InternalError(OAuthError::ClientKey(err)) => bad_request(err),
                err => err.into(),
            })?,
    ))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ListServiceAccountTokensPath {
    pub client_id: TypedUuid<OAuthClientId>,
}

/// Lists the service account tokens issued to a client that have neither expired nor been revoked
#[instrument(skip(rqctx), err(Debug))]
pub async fn list_service_account_tokens_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<ListServiceAccountTokensPath>,
) -> Result<HttpResponseOk<Vec<ServiceAccountToken>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    list_service_account_tokens_inner(ctx, caller, &path.into_inner().client_id).await
}

pub async fn list_service_account_tokens_inner<T>(
    ctx: &VContext<T>,
    caller: Caller<T>,
    client_id: &TypedUuid<OAuthClientId>,
) -> Result<HttpResponseOk<Vec<ServiceAccountToken>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    Ok(HttpResponseOk(
        ctx.oauth
            .list_service_account_tokens(&caller, client_id)
            .await?,
    ))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct RevokeServiceAccountTokenPath {
    pub client_id: TypedUuid<OAuthClientId>,
    pub token_id: TypedUuid<ServiceAccountTokenId>,
}

/// Revokes one of a client's service account tokens so that it is refused from then on
#[instrument(skip(rqctx), err(Debug))]
pub async fn revoke_service_account_token_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<RevokeServiceAccountTokenPath>,
) -> Result<HttpResponseOk<ServiceAccountToken>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let path = path.into_inner();
    revoke_service_account_token_inner(ctx, caller, &path.client_id, &path.token_id).await
}

pub async fn revoke_service_account_token_inner<T>(
    ctx: &VContext<T>,
    caller: Caller<T>,
    client_id: &TypedUuid<OAuthClientId>,
    token_id: &TypedUuid<ServiceAccountTokenId>,
) -> Result<HttpResponseOk<ServiceAccountToken>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    Ok(HttpResponseOk(
        ctx.oauth
            .revoke_service_account_token(&caller, client_id, token_id)
            .await?,
    ))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct DeleteOAuthClientKeyPath {
    pub client_id: TypedUuid<OAuthClientId>,
    pub key_id: TypedUuid<OAuthClientKeyId>,
}

/// Removes one of a client's public keys. Tokens already issued for assertions from this key pair
/// are not revoked.
#[instrument(skip(rqctx), err(Debug))]
pub async fn delete_oauth_client_key_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<DeleteOAuthClientKeyPath>,
) -> Result<HttpResponseOk<OAuthClientKey>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let path = path.into_inner();
    Ok(HttpResponseOk(
        ctx.oauth
            .delete_oauth_client_key(&caller, &path.client_id, &path.key_id)
            .await?,
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
    let secret = RawKey::generate::<24>(id.as_untyped_uuid())
        .sign(ctx.signer())
        .await
        .map_err(to_internal_error)?;
    let client_secret = ctx
        .oauth
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
        ctx.oauth
            .delete_oauth_secret(&caller, &path.secret_id, &path.client_id)
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
        ctx.oauth
            .add_oauth_redirect_uri(&caller, &path.client_id, &body.redirect_uri)
            .await
            .map_err(|err| match err {
                ResourceError::InternalError(OAuthError::RedirectUri(_)) => {
                    bad_request("Invalid redirect URI")
                }
                err => err.into(),
            })?,
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
        ctx.oauth
            .delete_oauth_redirect_uri(&caller, &path.redirect_uri_id, &path.client_id)
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
    use http::StatusCode;
    use mockall::predicate::eq;
    use newtype_uuid::TypedUuid;
    use serde_json::json;
    use v_model::{
        ApiUser, ApiUserInfo, NewOAuthClientKey, NewServiceAccount, OAuthClient, OAuthClientId,
        OAuthClientKey, OAuthClientSecret, Permissions, ServiceAccount, ServiceAccountToken,
        ServiceAccountTokenId,
        jwk::PublicJwk,
        permissions::{Caller, Principal},
        storage::{
            MockApiUserStore, MockOAuthClientAssertionStore, MockOAuthClientKeyStore,
            MockOAuthClientSecretStore, MockOAuthClientStore, MockServiceAccountStore,
            MockServiceAccountTokenStore, ServiceAccountTokenFilter, StoreError,
        },
    };

    use crate::{
        authn::key::RawKey,
        context::test_mocks::{MockStorage, mock_context},
        endpoints::login::oauth::{
            CheckOAuthClient,
            client::{
                OAuthClientPermissionParams, add_oauth_client_key_inner,
                add_oauth_client_permission_inner, create_oauth_client_inner,
                create_oauth_client_secret_inner, list_service_account_tokens_inner,
                remove_oauth_client_permission_inner, revoke_service_account_token_inner,
            },
        },
        permissions::VPermission,
        util::tests::get_status,
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
            generation: 0,
        }
    }

    #[tokio::test]
    async fn test_create_client_with_secret() {
        let user = mock_user();
        let mut caller = Caller {
            principal: Principal::User(user.id),
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
                    email: None,
                    providers: vec![],
                }))
            });
        user_store.expect_update().returning(|user, _| {
            Ok(Some(ApiUserInfo {
                user: ApiUser {
                    id: user.id,
                    permissions: user.permissions,
                    groups: user.groups,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    deleted_at: None,
                    generation: 0,
                },
                email: None,
                providers: vec![],
            }))
        });

        let mut store = MockOAuthClientStore::new();
        store.expect_upsert().returning(|client| {
            Ok(OAuthClient {
                id: client.id,
                keys: vec![],
                secrets: vec![],
                redirect_uris: vec![],
                created_at: Utc::now(),
                deleted_at: None,
            })
        });
        store
            .expect_get()
            .returning(|id, _| Ok(Some(oauth_client(*id, vec![]))));

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

        let ctx = mock_context(Arc::new(storage)).await;

        let mut client = create_oauth_client_inner(&ctx, caller.clone())
            .await
            .unwrap()
            .0;
        caller
            .permissions
            .insert(VPermission::GetOAuthClient(client.id));
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

        let key = RawKey::try_from(&secret.key.0).unwrap();

        assert!(client.is_secret_valid(&key, &ctx))
    }

    fn oauth_client(id: TypedUuid<OAuthClientId>, keys: Vec<OAuthClientKey>) -> OAuthClient {
        OAuthClient {
            id,
            secrets: vec![],
            redirect_uris: vec![],
            keys,
            created_at: Utc::now(),
            deleted_at: None,
        }
    }

    fn caller_with(permissions: Vec<VPermission>) -> Caller<VPermission> {
        Caller {
            principal: Principal::User(TypedUuid::new_v4()),
            permissions: permissions.into(),
            extensions: HashMap::default(),
        }
    }

    /// The example Ed25519 public key from RFC 8037 Appendix A.2
    const RFC_8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    fn submitted(jwk: serde_json::Value) -> crate::authn::client_key::SubmittedJwk {
        serde_json::from_value(jwk).unwrap()
    }

    fn valid_jwk() -> serde_json::Value {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": RFC_8037_X,
            "use": "sig",
            "key_ops": ["verify"],
            "alg": "EdDSA",
        })
    }

    fn stored_key(key: NewOAuthClientKey) -> OAuthClientKey {
        OAuthClientKey {
            id: key.id,
            oauth_client_id: key.oauth_client_id,
            thumbprint: key.thumbprint,
            jwk: key.jwk,
            created_at: Utc::now(),
            deleted_at: None,
        }
    }

    /// A context holding one client with `keys`. Inserting a key reports a conflict when
    /// `duplicate` is set, as storage does for a thumbprint registered anywhere before.
    async fn key_ctx(
        client_id: TypedUuid<OAuthClientId>,
        keys: Vec<OAuthClientKey>,
        duplicate: bool,
    ) -> (
        crate::VContext<VPermission>,
        Arc<Mutex<Vec<NewOAuthClientKey>>>,
    ) {
        let inserted = Arc::new(Mutex::new(vec![]));

        let mut client_store = MockOAuthClientStore::new();
        client_store
            .expect_get()
            .withf(move |id, _| id == &client_id)
            .returning(move |id, _| Ok(Some(oauth_client(*id, keys.clone()))));

        let mut key_store = MockOAuthClientKeyStore::new();
        let recorder = inserted.clone();
        key_store.expect_insert().returning(move |key| {
            recorder.lock().unwrap().push(key.clone());
            if duplicate {
                Err(StoreError::Conflict)
            } else {
                Ok(stored_key(key))
            }
        });
        key_store.expect_delete().returning(|id| {
            Ok(Some(stored_key(NewOAuthClientKey {
                id: *id,
                oauth_client_id: TypedUuid::new_v4(),
                thumbprint: "thumbprint".to_string(),
                jwk: PublicJwk::ed25519([7; 32]),
            })))
        });

        let mut storage = MockStorage::new();
        storage.oauth_client_store = Some(Arc::new(client_store));
        storage.oauth_client_key_store = Some(Arc::new(key_store));

        (mock_context(Arc::new(storage)).await, inserted)
    }

    fn key_manager(client_id: TypedUuid<OAuthClientId>) -> Caller<VPermission> {
        caller_with(vec![
            VPermission::GetOAuthClient(client_id),
            VPermission::ManageOAuthClient(client_id),
        ])
    }

    /// A registered key is stored against its client with its thumbprint as its id
    #[tokio::test]
    async fn adding_a_key_stores_it_under_its_thumbprint() {
        let client_id = TypedUuid::new_v4();
        let (ctx, inserted) = key_ctx(client_id, vec![], false).await;

        let resp = add_oauth_client_key_inner(
            &ctx,
            key_manager(client_id),
            &client_id,
            submitted(valid_jwk()),
        )
        .await;
        assert_eq!(get_status(&resp), StatusCode::OK);

        let inserted = inserted.lock().unwrap();
        assert_eq!(client_id, inserted[0].oauth_client_id);
        assert_eq!(
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
            inserted[0].thumbprint
        );
    }

    #[tokio::test]
    async fn adding_a_key_requires_managing_the_client() {
        let client_id = TypedUuid::new_v4();
        let (ctx, inserted) = key_ctx(client_id, vec![], false).await;

        let can_only_see = caller_with(vec![VPermission::GetOAuthClient(client_id)]);
        let resp =
            add_oauth_client_key_inner(&ctx, can_only_see, &client_id, submitted(valid_jwk()))
                .await;
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);
        assert!(inserted.lock().unwrap().is_empty());
    }

    /// A key registered anywhere before, by any client, can not be registered again
    #[tokio::test]
    async fn adding_a_registered_key_is_a_conflict() {
        let client_id = TypedUuid::new_v4();
        let (ctx, _) = key_ctx(client_id, vec![], true).await;

        let resp = add_oauth_client_key_inner(
            &ctx,
            key_manager(client_id),
            &client_id,
            submitted(valid_jwk()),
        )
        .await;
        assert_eq!(get_status(&resp), StatusCode::CONFLICT);
    }

    /// A key can only be removed through the client it belongs to, by a caller who manages it
    #[tokio::test]
    async fn removing_a_key_requires_it_to_belong_to_the_client() {
        let client_id = TypedUuid::new_v4();
        let key = stored_key(NewOAuthClientKey {
            id: TypedUuid::new_v4(),
            oauth_client_id: client_id,
            thumbprint: "thumbprint".to_string(),
            jwk: PublicJwk::ed25519([7; 32]),
        });
        let key_id = key.id;
        let (ctx, _) = key_ctx(client_id, vec![key], false).await;

        let removed = ctx
            .oauth
            .delete_oauth_client_key(&key_manager(client_id), &client_id, &key_id)
            .await;
        assert!(removed.is_ok());

        let not_on_client = ctx
            .oauth
            .delete_oauth_client_key(&key_manager(client_id), &client_id, &TypedUuid::new_v4())
            .await;
        assert!(matches!(
            not_on_client,
            Err(crate::response::ResourceError::DoesNotExist)
        ));

        let can_only_see = caller_with(vec![VPermission::GetOAuthClient(client_id)]);
        let refused = ctx
            .oauth
            .delete_oauth_client_key(&can_only_see, &client_id, &key_id)
            .await;
        assert!(matches!(
            refused,
            Err(crate::response::ResourceError::Restricted)
        ));
    }

    /// A service account can not create a client, and is refused before the client is created so
    /// that no client is left without anyone able to manage it
    #[tokio::test]
    async fn a_service_account_can_not_create_a_client() {
        let mut client_store = MockOAuthClientStore::new();
        client_store.expect_upsert().never();
        let mut storage = MockStorage::new();
        storage.oauth_client_store = Some(Arc::new(client_store));
        let ctx = mock_context(Arc::new(storage)).await;

        let service_account = Caller {
            principal: Principal::ServiceAccount(TypedUuid::new_v4()),
            permissions: vec![VPermission::CreateOAuthClient].into(),
            extensions: HashMap::default(),
        };

        let resp = create_oauth_client_inner(&ctx, service_account).await;
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);
    }

    /// How a service account write is answered
    #[derive(Clone, Copy)]
    enum WriteOutcome {
        Lands,
        Stale,
    }

    /// What service account changes wrote, as the record and the generation an update expected
    #[derive(Default)]
    struct AccountWrites {
        created: Vec<NewServiceAccount<VPermission>>,
        updated: Vec<(NewServiceAccount<VPermission>, i64)>,
    }

    fn service_account(
        id: TypedUuid<OAuthClientId>,
        permissions: Permissions<VPermission>,
        generation: i64,
    ) -> ServiceAccount<VPermission> {
        ServiceAccount {
            id,
            permissions,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            generation,
        }
    }

    /// A context holding one client, whose service account holds `existing` when it is set
    async fn account_ctx(
        client_id: TypedUuid<OAuthClientId>,
        existing: Option<ServiceAccount<VPermission>>,
        outcome: WriteOutcome,
    ) -> (crate::VContext<VPermission>, Arc<Mutex<AccountWrites>>) {
        let writes = Arc::new(Mutex::new(AccountWrites::default()));

        let mut client_store = MockOAuthClientStore::new();
        client_store
            .expect_get()
            .withf(move |id, _| id == &client_id)
            .returning(move |id, _| Ok(Some(oauth_client(*id, vec![]))));

        let mut account_store = MockServiceAccountStore::new();
        account_store
            .expect_get()
            .returning(move |_| Ok(existing.clone()));
        let recorder = writes.clone();
        account_store.expect_create().returning(move |account| {
            recorder.lock().unwrap().created.push(account.clone());
            match outcome {
                WriteOutcome::Lands => Ok(service_account(account.id, account.permissions, 0)),
                WriteOutcome::Stale => Err(StoreError::Conflict),
            }
        });
        let recorder = writes.clone();
        account_store
            .expect_update()
            .returning(move |account, generation| {
                recorder
                    .lock()
                    .unwrap()
                    .updated
                    .push((account.clone(), generation));
                match outcome {
                    WriteOutcome::Lands => Ok(Some(service_account(
                        account.id,
                        account.permissions,
                        generation + 1,
                    ))),
                    WriteOutcome::Stale => Ok(None),
                }
            });

        let mut storage = MockStorage::new();
        storage.oauth_client_store = Some(Arc::new(client_store));
        storage.service_account_store = Some(Arc::new(account_store));

        (mock_context(Arc::new(storage)).await, writes)
    }

    fn client_manager(
        client_id: TypedUuid<OAuthClientId>,
        holds: Vec<VPermission>,
    ) -> Caller<VPermission> {
        let mut permissions = vec![
            VPermission::GetOAuthClient(client_id),
            VPermission::ManageOAuthClient(client_id),
        ];
        permissions.extend(holds);
        caller_with(permissions)
    }

    fn grant(permission: VPermission) -> OAuthClientPermissionParams<VPermission> {
        OAuthClientPermissionParams { permission }
    }

    /// Granting needs management of the client and the ability to grant the permission
    #[tokio::test]
    async fn granting_to_a_service_account_requires_grant() {
        let client_id = TypedUuid::new_v4();
        let (ctx, writes) = account_ctx(client_id, None, WriteOutcome::Lands).await;

        let cannot_grant = client_manager(client_id, vec![]);
        let resp = add_oauth_client_permission_inner::<VPermission, VPermission>(
            &ctx,
            cannot_grant,
            &client_id,
            grant(VPermission::CreateGroup),
        )
        .await;
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);

        let cannot_manage = caller_with(vec![
            VPermission::GetOAuthClient(client_id),
            VPermission::CreateGroup,
        ]);
        let resp = add_oauth_client_permission_inner::<VPermission, VPermission>(
            &ctx,
            cannot_manage,
            &client_id,
            grant(VPermission::CreateGroup),
        )
        .await;
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);

        let writes = writes.lock().unwrap();
        assert!(writes.created.is_empty() && writes.updated.is_empty());
    }

    /// The first permission a client is granted creates its service account
    #[tokio::test]
    async fn the_first_grant_creates_the_service_account() {
        let client_id = TypedUuid::new_v4();
        let (ctx, writes) = account_ctx(client_id, None, WriteOutcome::Lands).await;

        let resp = add_oauth_client_permission_inner::<VPermission, VPermission>(
            &ctx,
            client_manager(client_id, vec![VPermission::CreateGroup]),
            &client_id,
            grant(VPermission::CreateGroup),
        )
        .await
        .unwrap();
        assert!(resp.0.can(&VPermission::CreateGroup));

        let writes = writes.lock().unwrap();
        assert_eq!(1, writes.created.len());
        assert!(writes.updated.is_empty());
        assert!(writes.created[0].permissions.can(&VPermission::CreateGroup));
    }

    /// Later grants write against the generation that was read, keeping what the account held
    #[tokio::test]
    async fn later_grants_update_from_the_generation_read() {
        let client_id = TypedUuid::new_v4();
        let existing = service_account(client_id, vec![VPermission::CreateMapper].into(), 4);
        let (ctx, writes) = account_ctx(client_id, Some(existing), WriteOutcome::Lands).await;

        add_oauth_client_permission_inner::<VPermission, VPermission>(
            &ctx,
            client_manager(client_id, vec![VPermission::CreateGroup]),
            &client_id,
            grant(VPermission::CreateGroup),
        )
        .await
        .unwrap();

        let writes = writes.lock().unwrap();
        assert!(writes.created.is_empty());
        let (written, generation) = &writes.updated[0];
        assert_eq!(4, *generation);
        assert!(written.permissions.can(&VPermission::CreateGroup));
        assert!(written.permissions.can(&VPermission::CreateMapper));
    }

    /// Removing needs the ability to grant the permission, and removing one value of a stored set
    /// keeps the rest of that set
    #[tokio::test]
    async fn removing_from_a_service_account_requires_grant() {
        let client_id = TypedUuid::new_v4();
        let (a, b) = (TypedUuid::new_v4(), TypedUuid::new_v4());
        let existing = service_account(
            client_id,
            vec![VPermission::ManageGroups([a, b].into())].into(),
            0,
        );
        let (ctx, writes) = account_ctx(client_id, Some(existing), WriteOutcome::Lands).await;

        let resp = remove_oauth_client_permission_inner::<VPermission, VPermission>(
            &ctx,
            client_manager(client_id, vec![]),
            &client_id,
            grant(VPermission::ManageGroup(a)),
        )
        .await;
        assert_eq!(get_status(&resp), StatusCode::FORBIDDEN);
        assert!(writes.lock().unwrap().updated.is_empty());

        let removed = remove_oauth_client_permission_inner::<VPermission, VPermission>(
            &ctx,
            client_manager(client_id, vec![VPermission::ManageGroup(a)]),
            &client_id,
            grant(VPermission::ManageGroup(a)),
        )
        .await
        .unwrap();
        assert!(!removed.0.can(&VPermission::ManageGroup(a)));
        assert!(removed.0.can(&VPermission::ManageGroup(b)));
    }

    /// Losing to a concurrent write is a conflict whether the service account was being created
    /// or updated, and is never retried
    #[tokio::test]
    async fn a_stale_service_account_write_is_a_conflict() {
        let client_id = TypedUuid::new_v4();
        let caller = || client_manager(client_id, vec![VPermission::CreateGroup]);

        let (creating, _) = account_ctx(client_id, None, WriteOutcome::Stale).await;
        let resp = add_oauth_client_permission_inner::<VPermission, VPermission>(
            &creating,
            caller(),
            &client_id,
            grant(VPermission::CreateGroup),
        )
        .await;
        assert_eq!(get_status(&resp), StatusCode::CONFLICT);

        let existing = service_account(client_id, Permissions::new(), 2);
        let (updating, _) = account_ctx(client_id, Some(existing), WriteOutcome::Stale).await;
        let resp = add_oauth_client_permission_inner::<VPermission, VPermission>(
            &updating,
            caller(),
            &client_id,
            grant(VPermission::CreateGroup),
        )
        .await;
        assert_eq!(get_status(&resp), StatusCode::CONFLICT);
    }

    /// Reading needs the client to be visible, and a client never granted anything holds nothing
    #[tokio::test]
    async fn reading_service_account_permissions() {
        let client_id = TypedUuid::new_v4();
        let (ctx, _) = account_ctx(client_id, None, WriteOutcome::Lands).await;

        let can_see = caller_with(vec![VPermission::GetOAuthClient(client_id)]);
        let permissions = ctx
            .oauth
            .get_service_account_permissions(&can_see, &client_id)
            .await
            .unwrap();
        assert!(permissions.is_empty());

        let cannot_see = caller_with(vec![VPermission::ManageOAuthClient(client_id)]);
        let refused = ctx
            .oauth
            .get_service_account_permissions(&cannot_see, &client_id)
            .await;
        assert!(matches!(
            refused,
            Err(crate::response::ResourceError::Restricted)
        ));
    }

    fn token_ctx_storage(
        client_id: TypedUuid<OAuthClientId>,
    ) -> (MockStorage, Arc<Mutex<Vec<ServiceAccountTokenFilter>>>) {
        let mut client_store = MockOAuthClientStore::new();
        client_store.expect_get().returning(move |id, deleted| {
            Ok((id == &client_id && !deleted).then(|| oauth_client(*id, vec![])))
        });

        let filters = Arc::new(Mutex::new(vec![]));
        let seen = filters.clone();
        let mut token_store = MockServiceAccountTokenStore::new();
        token_store.expect_list().returning(move |filter, _| {
            let oauth_client_id = filter.oauth_client_id.clone().unwrap_or_default()[0];
            seen.lock().unwrap().push(filter);
            Ok(vec![ServiceAccountToken {
                id: TypedUuid::new_v4(),
                oauth_client_id,
                expires_at: Utc::now(),
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }])
        });

        let mut storage = MockStorage::new();
        storage.oauth_client_store = Some(Arc::new(client_store));
        storage.service_account_token_store = Some(Arc::new(token_store));
        (storage, filters)
    }

    /// Listing tokens needs the client to be visible, and only asks for the client's live tokens
    #[tokio::test]
    async fn listing_service_account_tokens() {
        let client_id = TypedUuid::new_v4();
        let (storage, filters) = token_ctx_storage(client_id);
        let ctx = mock_context(Arc::new(storage)).await;

        let tokens = list_service_account_tokens_inner(
            &ctx,
            caller_with(vec![VPermission::GetOAuthClient(client_id)]),
            &client_id,
        )
        .await
        .unwrap()
        .0;
        assert_eq!(1, tokens.len());
        assert_eq!(
            vec![ServiceAccountTokenFilter {
                oauth_client_id: Some(vec![client_id]),
                revoked: false,
                expired: false,
            }],
            *filters.lock().unwrap()
        );

        let refused = list_service_account_tokens_inner(
            &ctx,
            caller_with(vec![VPermission::ManageOAuthClient(client_id)]),
            &client_id,
        )
        .await;
        assert_eq!(StatusCode::FORBIDDEN, get_status(&refused));

        let missing = TypedUuid::new_v4();
        let not_found = list_service_account_tokens_inner(
            &ctx,
            caller_with(vec![VPermission::GetOAuthClient(missing)]),
            &missing,
        )
        .await;
        assert_eq!(StatusCode::NOT_FOUND, get_status(&not_found));
        assert_eq!(1, filters.lock().unwrap().len());
    }

    /// Removing expired assertions spans every client, so it needs management of all of them
    #[tokio::test]
    async fn deleting_expired_client_assertions_requires_managing_every_client() {
        let mut assertion_store = MockOAuthClientAssertionStore::new();
        assertion_store
            .expect_delete_expired()
            .times(1)
            .returning(|_| Ok(3));

        let mut storage = MockStorage::new();
        storage.oauth_client_assertion_store = Some(Arc::new(assertion_store));
        let ctx = mock_context(Arc::new(storage)).await;

        let refused = ctx
            .oauth
            .delete_expired_client_assertions(&caller_with(vec![VPermission::ManageOAuthClient(
                TypedUuid::new_v4(),
            )]))
            .await;
        assert!(matches!(
            refused,
            Err(crate::response::ResourceError::Restricted)
        ));

        let removed = ctx
            .oauth
            .delete_expired_client_assertions(&caller_with(vec![
                VPermission::ManageOAuthClientsAll,
            ]))
            .await
            .unwrap();
        assert_eq!(3, removed);
    }

    /// Revoking needs management of the client, and only revokes live tokens the client holds
    #[tokio::test]
    async fn revoking_a_service_account_token() {
        let client_id = TypedUuid::new_v4();
        let live = TypedUuid::new_v4();
        let foreign = TypedUuid::new_v4();
        let revoked = Arc::new(Mutex::new(vec![]));

        let mut client_store = MockOAuthClientStore::new();
        client_store.expect_get().returning(move |id, deleted| {
            Ok((id == &client_id && !deleted).then(|| oauth_client(*id, vec![])))
        });

        let token =
            move |id: TypedUuid<ServiceAccountTokenId>, oauth_client_id| ServiceAccountToken {
                id,
                oauth_client_id,
                expires_at: Utc::now(),
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
        let mut token_store = MockServiceAccountTokenStore::new();
        token_store.expect_get().returning(move |id, revoked| {
            assert!(!revoked, "revoked tokens should never be looked up");
            Ok(if id == &live {
                Some(token(live, client_id))
            } else if id == &foreign {
                Some(token(foreign, TypedUuid::new_v4()))
            } else {
                None
            })
        });
        let recorder = revoked.clone();
        token_store.expect_revoke().returning(move |id| {
            recorder.lock().unwrap().push(*id);
            Ok(Some(token(*id, client_id)))
        });

        let mut storage = MockStorage::new();
        storage.oauth_client_store = Some(Arc::new(client_store));
        storage.service_account_token_store = Some(Arc::new(token_store));
        let ctx = mock_context(Arc::new(storage)).await;

        let manager = || {
            caller_with(vec![
                VPermission::GetOAuthClient(client_id),
                VPermission::ManageOAuthClient(client_id),
            ])
        };

        let refused = revoke_service_account_token_inner(
            &ctx,
            caller_with(vec![VPermission::GetOAuthClient(client_id)]),
            &client_id,
            &live,
        )
        .await;
        assert_eq!(StatusCode::FORBIDDEN, get_status(&refused));

        for missing in [foreign, TypedUuid::new_v4()] {
            let resp =
                revoke_service_account_token_inner(&ctx, manager(), &client_id, &missing).await;
            assert_eq!(StatusCode::NOT_FOUND, get_status(&resp));
        }
        assert!(revoked.lock().unwrap().is_empty());

        let resp = revoke_service_account_token_inner(&ctx, manager(), &client_id, &live)
            .await
            .unwrap();
        assert_eq!(live, resp.0.id);
        assert_eq!(vec![live], *revoked.lock().unwrap());
    }

    /// A client that is deleted or does not exist is not found for every service account
    /// permission operation, even for a caller who could otherwise make the change. Its service
    /// account is never read or written.
    #[tokio::test]
    async fn service_account_permissions_of_a_missing_client_are_not_found() {
        let client_id = TypedUuid::new_v4();

        // A deleted client is filtered out by the lookup in the same way as one that never
        // existed, so both are represented by the store finding nothing
        let mut client_store = MockOAuthClientStore::new();
        client_store
            .expect_get()
            .withf(move |id, deleted| id == &client_id && !deleted)
            .returning(|_, _| Ok(None));

        let mut storage = MockStorage::new();
        storage.oauth_client_store = Some(Arc::new(client_store));
        storage.service_account_store = Some(Arc::new(MockServiceAccountStore::new()));
        let ctx = mock_context(Arc::new(storage)).await;

        let caller = || client_manager(client_id, vec![VPermission::CreateGroup]);

        let read = ctx
            .oauth
            .get_service_account_permissions(&caller(), &client_id)
            .await;
        assert!(matches!(
            read,
            Err(crate::response::ResourceError::DoesNotExist)
        ));

        let added = add_oauth_client_permission_inner::<VPermission, VPermission>(
            &ctx,
            caller(),
            &client_id,
            grant(VPermission::CreateGroup),
        )
        .await;
        assert_eq!(StatusCode::NOT_FOUND, get_status(&added));

        let removed = remove_oauth_client_permission_inner::<VPermission, VPermission>(
            &ctx,
            caller(),
            &client_id,
            grant(VPermission::CreateGroup),
        )
        .await;
        assert_eq!(StatusCode::NOT_FOUND, get_status(&removed));
    }
}
