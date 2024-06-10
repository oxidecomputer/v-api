// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_bb8_diesel::{AsyncRunQueryDsl, ConnectionError, ConnectionManager};
use async_trait::async_trait;
use bb8::Pool;
use chrono::Utc;
use diesel::{
    insert_into, pg::PgConnection, query_dsl::QueryDsl, update, upsert::excluded,
    ExpressionMethods, OptionalExtension as OptionalExtension2, PgArrayExpressionMethods,
};
use newtype_uuid::{GenericUuid, TypedUuid};
use std::{collections::BTreeMap, time::Duration};
use thiserror::Error;
use tracing::instrument;

use crate::{
    db::{
        AccessGroupModel, ApiKeyModel, ApiUserAccessTokenModel, ApiUserModel, ApiUserProviderModel,
        LinkRequestModel, LoginAttemptModel, MapperModel, OAuthClientModel,
        OAuthClientRedirectUriModel, OAuthClientSecretModel,
    },
    permissions::Permission,
    schema::{
        access_groups, api_key, api_user, api_user_access_token, api_user_provider, link_request,
        login_attempt, mapper, oauth_client, oauth_client_redirect_uri, oauth_client_secret,
    },
    storage::{LinkRequestFilter, LinkRequestStore, StoreError},
    AccessGroup, AccessGroupId, AccessToken, AccessTokenId, ApiKey, ApiKeyId, ApiUser, ApiUserInfo,
    ApiUserProvider, LinkRequest, LinkRequestId, LoginAttempt, LoginAttemptId, Mapper, MapperId,
    NewAccessGroup, NewAccessToken, NewApiKey, NewApiUser, NewApiUserProvider, NewLinkRequest,
    NewLoginAttempt, NewMapper, NewOAuthClient, NewOAuthClientRedirectUri, NewOAuthClientSecret,
    OAuthClient, OAuthClientId, OAuthClientRedirectUri, OAuthClientSecret, OAuthRedirectUriId,
    OAuthSecretId, UserId, UserProviderId,
};

use super::{
    AccessGroupFilter, AccessGroupStore, AccessTokenFilter, AccessTokenStore, ApiKeyFilter,
    ApiKeyStore, ApiUserFilter, ApiUserProviderFilter, ApiUserProviderStore, ApiUserStore,
    ListPagination, LoginAttemptFilter, LoginAttemptStore, MapperFilter, MapperStore,
    OAuthClientFilter, OAuthClientRedirectUriStore, OAuthClientSecretStore, OAuthClientStore,
};

pub type DbPool = Pool<ConnectionManager<PgConnection>>;

pub struct PostgresStore {
    pub pool: DbPool,
}

#[derive(Debug, Error)]
pub enum PostgresError {
    #[error("Database connection failed")]
    Connection(ConnectionError),
}

impl From<ConnectionError> for PostgresError {
    fn from(error: ConnectionError) -> Self {
        PostgresError::Connection(error)
    }
}

impl PostgresStore {
    pub async fn new(url: &str) -> Result<Self, PostgresError> {
        let manager = ConnectionManager::<PgConnection>::new(url);

        Ok(Self {
            pool: Pool::builder()
                .connection_timeout(Duration::from_secs(5))
                .build(manager)
                .await?,
        })
    }
}

#[async_trait]
impl<T> ApiUserStore<T> for PostgresStore
where
    T: Permission,
{
    async fn get(
        &self,
        id: &TypedUuid<UserId>,
        deleted: bool,
    ) -> Result<Option<ApiUserInfo<T>>, StoreError> {
        let user = ApiUserStore::list(
            self,
            ApiUserFilter {
                id: Some(vec![*id]),
                email: None,
                groups: None,
                deleted,
            },
            &ListPagination::default().limit(1),
        )
        .await?;
        Ok(user.into_iter().nth(0))
    }

    async fn list(
        &self,
        filter: ApiUserFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<ApiUserInfo<T>>, StoreError> {
        let mut query = api_user::dsl::api_user
            .left_join(api_user_provider::dsl::api_user_provider)
            .into_boxed();

        let ApiUserFilter {
            id,
            email,
            groups,
            deleted,
        } = filter;

        if let Some(id) = id {
            query =
                query.filter(api_user::id.eq_any(id.into_iter().map(|id| id.into_untyped_uuid())));
        }

        if let Some(email) = email {
            query = query.filter(api_user_provider::emails.contains(email));
        }

        if let Some(groups) = groups {
            query = query.filter(
                api_user::groups.overlaps_with(
                    groups
                        .into_iter()
                        .map(|id| id.into_untyped_uuid())
                        .collect::<Vec<_>>(),
                ),
            );
        }

        if !deleted {
            query = query.filter(api_user::deleted_at.is_null());
        }

        let results = query
            .offset(pagination.offset)
            .limit(pagination.limit)
            .order(api_user::created_at.asc())
            .get_results_async::<(ApiUserModel<T>, Option<ApiUserProviderModel>)>(
                &*self.pool.get().await?,
            )
            .await?;

        let users = results
            .into_iter()
            .fold(BTreeMap::new(), |mut acc, (user, provider)| {
                let (_, providers): &mut (ApiUser<T>, Vec<ApiUserProvider>) =
                    acc.entry(user.id).or_insert_with(|| (user.into(), vec![]));
                if let Some(provider) = provider {
                    providers.push(provider.into());
                }

                acc
            })
            .into_values()
            .map(|(user, providers)| ApiUserInfo { user, providers })
            .collect::<Vec<_>>();

        Ok(users)
    }

    #[instrument(skip(self), fields(id = ?user.id, permissions = ?user.permissions, groups = ?user.groups))]
    async fn upsert(&self, user: NewApiUser<T>) -> Result<ApiUserInfo<T>, StoreError> {
        tracing::trace!("Upserting user");

        insert_into(api_user::dsl::api_user)
            .values((
                api_user::id.eq(user.id.into_untyped_uuid()),
                api_user::permissions.eq(user.permissions.clone()),
                api_user::groups.eq(user
                    .groups
                    .into_iter()
                    .map(|g| g.into_untyped_uuid())
                    .collect::<Vec<_>>()),
            ))
            .on_conflict(api_user::id)
            .do_update()
            .set((
                api_user::permissions.eq(excluded(api_user::permissions)),
                api_user::groups.eq(excluded(api_user::groups)),
                api_user::updated_at.eq(Utc::now()),
            ))
            .execute_async(&*self.pool.get().await?)
            .await?;

        Ok(ApiUserStore::get(self, &user.id, false).await?.unwrap())
    }

    async fn delete(&self, id: &TypedUuid<UserId>) -> Result<Option<ApiUserInfo<T>>, StoreError> {
        let _ = update(api_user::dsl::api_user)
            .filter(api_user::id.eq(id.into_untyped_uuid()))
            .set(api_user::deleted_at.eq(Utc::now()))
            .execute_async(&*self.pool.get().await?)
            .await?;

        ApiUserStore::get(self, id, true).await
    }
}

#[async_trait]
impl<T> ApiKeyStore<T> for PostgresStore
where
    T: Permission,
{
    async fn get(
        &self,
        id: &TypedUuid<ApiKeyId>,
        deleted: bool,
    ) -> Result<Option<ApiKey<T>>, StoreError> {
        let mut query = api_key::dsl::api_key
            .into_boxed()
            .filter(api_key::id.eq(id.into_untyped_uuid()));

        if !deleted {
            query = query.filter(api_key::deleted_at.is_null());
        }

        let result = query
            .get_result_async::<ApiKeyModel<T>>(&*self.pool.get().await?)
            .await
            .optional()?;

        Ok(result.map(|key| key.into()))
    }

    async fn list(
        &self,
        filter: ApiKeyFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<ApiKey<T>>, StoreError> {
        let mut query = api_key::dsl::api_key.into_boxed();

        let ApiKeyFilter {
            id,
            api_user_id,
            key_signature,
            expired,
            deleted,
        } = filter;

        if let Some(id) = id {
            query =
                query.filter(api_key::id.eq_any(id.into_iter().map(|key| key.into_untyped_uuid())));
        }

        if let Some(api_user_id) = api_user_id {
            query = query.filter(
                api_key::api_user_id
                    .eq_any(api_user_id.into_iter().map(|user| user.into_untyped_uuid())),
            );
        }

        if let Some(key_signature) = key_signature {
            query = query.filter(api_key::key_signature.eq_any(key_signature));
        }

        if !expired {
            query = query.filter(api_key::expires_at.gt(Utc::now()));
        }

        if !deleted {
            query = query.filter(api_key::deleted_at.is_null());
        }

        let results = query
            .offset(pagination.offset)
            .limit(pagination.limit)
            .order(api_key::created_at.desc())
            .get_results_async::<ApiKeyModel<T>>(&*self.pool.get().await?)
            .await?;

        Ok(results.into_iter().map(|token| token.into()).collect())
    }

    async fn upsert(&self, key: NewApiKey<T>) -> Result<ApiKey<T>, StoreError> {
        let key_m: ApiKeyModel<T> = insert_into(api_key::dsl::api_key)
            .values((
                api_key::id.eq(key.id.into_untyped_uuid()),
                api_key::api_user_id.eq(key.user_id.into_untyped_uuid()),
                api_key::key_signature.eq(key.key_signature.clone()),
                api_key::expires_at.eq(key.expires_at),
                api_key::permissions.eq(key.permissions),
            ))
            .get_result_async(&*self.pool.get().await?)
            .await?;

        Ok(key_m.into())
    }

    async fn delete(&self, id: &TypedUuid<ApiKeyId>) -> Result<Option<ApiKey<T>>, StoreError> {
        let _ = update(api_key::dsl::api_key)
            .filter(api_key::id.eq(id.into_untyped_uuid()))
            .set(api_key::deleted_at.eq(Utc::now()))
            .execute_async(&*self.pool.get().await?)
            .await?;

        ApiKeyStore::get(self, id, true).await
    }
}

#[async_trait]
impl ApiUserProviderStore for PostgresStore {
    async fn get(
        &self,
        id: &TypedUuid<UserProviderId>,
        deleted: bool,
    ) -> Result<Option<ApiUserProvider>, StoreError> {
        let user = ApiUserProviderStore::list(
            self,
            ApiUserProviderFilter {
                id: Some(vec![*id]),
                api_user_id: None,
                provider: None,
                provider_id: None,
                email: None,
                deleted,
            },
            &ListPagination::default().limit(1),
        )
        .await?;
        Ok(user.into_iter().nth(0))
    }

    async fn list(
        &self,
        filter: ApiUserProviderFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<ApiUserProvider>, StoreError> {
        let mut query = api_user_provider::dsl::api_user_provider.into_boxed();

        let ApiUserProviderFilter {
            id,
            api_user_id,
            provider,
            provider_id,
            email,
            deleted,
        } = filter;

        if let Some(id) = id {
            query = query.filter(
                api_user_provider::id
                    .eq_any(id.into_iter().map(|provider| provider.into_untyped_uuid())),
            );
        }

        if let Some(api_user_id) = api_user_id {
            query = query.filter(
                api_user_provider::api_user_id
                    .eq_any(api_user_id.into_iter().map(|user| user.into_untyped_uuid())),
            );
        }

        if let Some(provider) = provider {
            query = query.filter(api_user_provider::provider.eq_any(provider));
        }

        if let Some(provider_id) = provider_id {
            query = query.filter(api_user_provider::provider_id.eq_any(provider_id));
        }

        if let Some(email) = email {
            query = query.filter(api_user_provider::emails.contains(email));
        }

        if !deleted {
            query = query.filter(api_user_provider::deleted_at.is_null());
        }

        let results = query
            .offset(pagination.offset)
            .limit(pagination.limit)
            .order(api_user_provider::created_at.desc())
            .get_results_async::<ApiUserProviderModel>(&*self.pool.get().await?)
            .await?;

        Ok(results
            .into_iter()
            .map(|provider| provider.into())
            .collect())
    }

    async fn upsert(&self, provider: NewApiUserProvider) -> Result<ApiUserProvider, StoreError> {
        tracing::trace!(id = ?provider.id, api_user_id = ?provider.user_id, provider = ?provider, "Inserting user provider");

        let provider_m: ApiUserProviderModel =
            insert_into(api_user_provider::dsl::api_user_provider)
                .values((
                    api_user_provider::id.eq(provider.id.into_untyped_uuid()),
                    api_user_provider::api_user_id.eq(provider.user_id.into_untyped_uuid()),
                    api_user_provider::provider.eq(provider.provider),
                    api_user_provider::provider_id.eq(provider.provider_id),
                    api_user_provider::emails.eq(provider.emails),
                    api_user_provider::display_names.eq(provider.display_names),
                ))
                .on_conflict(api_user_provider::id)
                .do_update()
                .set((
                    api_user_provider::emails.eq(excluded(api_user_provider::emails)),
                    api_user_provider::display_names.eq(excluded(api_user_provider::display_names)),
                    api_user_provider::updated_at.eq(Utc::now()),
                ))
                .get_result_async(&*self.pool.get().await?)
                .await?;

        Ok(provider_m.into())
    }

    async fn transfer(
        &self,
        provider: NewApiUserProvider,
        current_api_user_id: TypedUuid<UserId>,
    ) -> Result<ApiUserProvider, StoreError> {
        tracing::trace!(id = ?provider.id, api_user_id = ?provider.user_id, provider = ?provider, "Updating user provider");

        let provider_m: ApiUserProviderModel = update(api_user_provider::dsl::api_user_provider)
            .set((
                api_user_provider::api_user_id.eq(provider.user_id.into_untyped_uuid()),
                api_user_provider::updated_at.eq(Utc::now()),
            ))
            .filter(api_user_provider::id.eq(provider.id.into_untyped_uuid()))
            .filter(api_user_provider::api_user_id.eq(current_api_user_id.into_untyped_uuid()))
            .get_result_async(&*self.pool.get().await?)
            .await?;

        Ok(provider_m.into())
    }

    async fn delete(
        &self,
        id: &TypedUuid<UserProviderId>,
    ) -> Result<Option<ApiUserProvider>, StoreError> {
        let _ = update(api_user::dsl::api_user)
            .filter(api_user::id.eq(id.into_untyped_uuid()))
            .set(api_user::deleted_at.eq(Utc::now()))
            .execute_async(&*self.pool.get().await?)
            .await?;

        ApiUserProviderStore::get(self, id, true).await
    }
}

#[async_trait]
impl AccessTokenStore for PostgresStore {
    async fn get(
        &self,
        id: &TypedUuid<AccessTokenId>,
        revoked: bool,
    ) -> Result<Option<AccessToken>, StoreError> {
        let mut query = api_user_access_token::dsl::api_user_access_token
            .into_boxed()
            .filter(api_user_access_token::id.eq(id.into_untyped_uuid()));

        if !revoked {
            query = query.filter(api_user_access_token::revoked_at.is_null());
        }

        let result = query
            .get_result_async::<ApiUserAccessTokenModel>(&*self.pool.get().await?)
            .await
            .optional()?;

        Ok(result.map(|token| token.into()))
    }

    async fn list(
        &self,
        filter: AccessTokenFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<AccessToken>, StoreError> {
        let mut query = api_user_access_token::dsl::api_user_access_token.into_boxed();

        let AccessTokenFilter {
            id,
            api_user_id,
            revoked,
        } = filter;

        if let Some(id) = id {
            query = query.filter(
                api_user_access_token::id
                    .eq_any(id.into_iter().map(|token| token.into_untyped_uuid())),
            );
        }

        if let Some(api_user_id) = api_user_id {
            query = query.filter(
                api_user_access_token::api_user_id
                    .eq_any(api_user_id.into_iter().map(|user| user.into_untyped_uuid())),
            );
        }

        if !revoked {
            query = query.filter(api_user_access_token::revoked_at.gt(Utc::now()));
        }

        let results = query
            .offset(pagination.offset)
            .limit(pagination.limit)
            .order(api_user_access_token::created_at.desc())
            .get_results_async::<ApiUserAccessTokenModel>(&*self.pool.get().await?)
            .await?;

        Ok(results.into_iter().map(|token| token.into()).collect())
    }

    async fn upsert(&self, token: NewAccessToken) -> Result<AccessToken, StoreError> {
        let token_m: ApiUserAccessTokenModel =
            insert_into(api_user_access_token::dsl::api_user_access_token)
                .values((
                    api_user_access_token::id.eq(token.id.into_untyped_uuid()),
                    api_user_access_token::api_user_id.eq(token.user_id.into_untyped_uuid()),
                    api_user_access_token::revoked_at.eq(token.revoked_at),
                ))
                .on_conflict(api_user_access_token::id)
                .do_update()
                .set((api_user_access_token::revoked_at
                    .eq(excluded(api_user_access_token::revoked_at)),))
                .get_result_async(&*self.pool.get().await?)
                .await?;

        Ok(token_m.into())
    }
}

#[async_trait]
impl LoginAttemptStore for PostgresStore {
    async fn get(
        &self,
        id: &TypedUuid<LoginAttemptId>,
    ) -> Result<Option<LoginAttempt>, StoreError> {
        let query = login_attempt::dsl::login_attempt
            .into_boxed()
            .filter(login_attempt::id.eq(id.into_untyped_uuid()));

        let result = query
            .get_result_async::<LoginAttemptModel>(&*self.pool.get().await?)
            .await
            .optional()?;

        Ok(result.map(|attempt| attempt.into()))
    }

    async fn list(
        &self,
        filter: LoginAttemptFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<LoginAttempt>, StoreError> {
        let mut query = login_attempt::dsl::login_attempt.into_boxed();

        let LoginAttemptFilter {
            id,
            client_id,
            attempt_state,
            authz_code,
        } = filter;

        if let Some(id) = id {
            query = query.filter(
                login_attempt::id.eq_any(id.into_iter().map(|attempt| attempt.into_untyped_uuid())),
            );
        }

        if let Some(client_id) = client_id {
            query = query.filter(
                login_attempt::client_id.eq_any(
                    client_id
                        .into_iter()
                        .map(|client| client.into_untyped_uuid()),
                ),
            );
        }

        if let Some(attempt_state) = attempt_state {
            query = query.filter(login_attempt::attempt_state.eq_any(attempt_state));
        }

        if let Some(authz_code) = authz_code {
            query = query.filter(login_attempt::authz_code.eq_any(authz_code));
        }

        let results = query
            .offset(pagination.offset)
            .limit(pagination.limit)
            .order(login_attempt::created_at.desc())
            .get_results_async::<LoginAttemptModel>(&*self.pool.get().await?)
            .await?;

        Ok(results.into_iter().map(|model| model.into()).collect())
    }

    async fn upsert(&self, attempt: NewLoginAttempt) -> Result<LoginAttempt, StoreError> {
        let attempt_m: LoginAttemptModel = insert_into(login_attempt::dsl::login_attempt)
            .values((
                login_attempt::id.eq(attempt.id.into_untyped_uuid()),
                login_attempt::attempt_state.eq(attempt.attempt_state),
                login_attempt::client_id.eq(attempt.client_id.into_untyped_uuid()),
                login_attempt::redirect_uri.eq(attempt.redirect_uri),
                login_attempt::state.eq(attempt.state),
                login_attempt::pkce_challenge.eq(attempt.pkce_challenge),
                login_attempt::pkce_challenge_method.eq(attempt.pkce_challenge_method),
                login_attempt::authz_code.eq(attempt.authz_code),
                login_attempt::expires_at.eq(attempt.expires_at),
                login_attempt::error.eq(attempt.error),
                login_attempt::provider.eq(attempt.provider),
                login_attempt::provider_pkce_verifier.eq(attempt.provider_pkce_verifier),
                login_attempt::provider_authz_code.eq(attempt.provider_authz_code),
                login_attempt::provider_error.eq(attempt.provider_error),
                login_attempt::scope.eq(attempt.scope),
            ))
            .on_conflict(login_attempt::id)
            .do_update()
            .set((
                login_attempt::attempt_state.eq(excluded(login_attempt::attempt_state)),
                login_attempt::authz_code.eq(excluded(login_attempt::authz_code)),
                login_attempt::expires_at.eq(excluded(login_attempt::expires_at)),
                login_attempt::error.eq(excluded(login_attempt::error)),
                login_attempt::provider_authz_code.eq(excluded(login_attempt::provider_authz_code)),
                login_attempt::provider_error.eq(excluded(login_attempt::provider_error)),
                login_attempt::updated_at.eq(Utc::now()),
            ))
            .get_result_async(&*self.pool.get().await?)
            .await?;

        Ok(attempt_m.into())
    }
}

#[async_trait]
impl OAuthClientStore for PostgresStore {
    async fn get(
        &self,
        id: &TypedUuid<OAuthClientId>,
        deleted: bool,
    ) -> Result<Option<OAuthClient>, StoreError> {
        let client = OAuthClientStore::list(
            self,
            OAuthClientFilter {
                id: Some(vec![*id]),
                deleted,
            },
            &ListPagination::default().limit(1),
        )
        .await?;

        Ok(client.into_iter().nth(0))
    }

    async fn list(
        &self,
        filter: OAuthClientFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<OAuthClient>, StoreError> {
        let mut query = oauth_client::dsl::oauth_client
            .left_join(oauth_client_secret::table)
            .left_join(oauth_client_redirect_uri::table)
            .into_boxed();

        let OAuthClientFilter { id, deleted } = filter;

        if let Some(id) = id {
            query = query.filter(
                oauth_client::id.eq_any(id.into_iter().map(|client| client.into_untyped_uuid())),
            );
        }

        if !deleted {
            query = query.filter(oauth_client::deleted_at.is_null());
        }

        let clients = query
            .order(oauth_client::created_at.desc())
            .load_async::<(
                OAuthClientModel,
                Option<OAuthClientSecretModel>,
                Option<OAuthClientRedirectUriModel>,
            )>(&*self.pool.get().await?)
            .await?
            .into_iter()
            .fold(
                BTreeMap::new(),
                |mut clients, (client, secret, redirect)| {
                    let value = clients.entry(client.id).or_insert((
                        client,
                        Vec::<OAuthClientSecret>::new(),
                        Vec::<OAuthClientRedirectUri>::new(),
                    ));

                    if let Some(secret) = secret {
                        value.1.push(secret.into());
                    }

                    if let Some(redirect) = redirect {
                        value.2.push(redirect.into());
                    }

                    clients
                },
            )
            .into_iter()
            .map(|(_, (client, secrets, redirect_uris))| {
                OAuthClient::new(client, secrets, redirect_uris)
            })
            .skip(pagination.offset as usize)
            .take(pagination.limit as usize)
            .collect::<Vec<_>>();

        Ok(clients)
    }

    async fn upsert(&self, client: NewOAuthClient) -> Result<OAuthClient, StoreError> {
        let client_m: OAuthClientModel = insert_into(oauth_client::dsl::oauth_client)
            .values(oauth_client::id.eq(client.id.into_untyped_uuid()))
            .get_result_async(&*self.pool.get().await?)
            .await?;

        Ok(client_m.into())
    }

    async fn delete(
        &self,
        id: &TypedUuid<OAuthClientId>,
    ) -> Result<Option<OAuthClient>, StoreError> {
        let _ = update(oauth_client::dsl::oauth_client)
            .filter(oauth_client::id.eq(id.into_untyped_uuid()))
            .set(oauth_client::deleted_at.eq(Utc::now()))
            .execute_async(&*self.pool.get().await?)
            .await?;

        OAuthClientStore::get(self, id, true).await
    }
}

#[async_trait]
impl OAuthClientSecretStore for PostgresStore {
    async fn upsert(&self, secret: NewOAuthClientSecret) -> Result<OAuthClientSecret, StoreError> {
        let secret_m: OAuthClientSecretModel =
            insert_into(oauth_client_secret::dsl::oauth_client_secret)
                .values((
                    oauth_client_secret::id.eq(secret.id.into_untyped_uuid()),
                    oauth_client_secret::oauth_client_id
                        .eq(secret.oauth_client_id.into_untyped_uuid()),
                    oauth_client_secret::secret_signature.eq(secret.secret_signature),
                ))
                .get_result_async(&*self.pool.get().await?)
                .await?;

        Ok(secret_m.into())
    }

    async fn delete(
        &self,
        id: &TypedUuid<OAuthSecretId>,
    ) -> Result<Option<OAuthClientSecret>, StoreError> {
        let _ = update(oauth_client_secret::dsl::oauth_client_secret)
            .filter(oauth_client_secret::id.eq(id.into_untyped_uuid()))
            .set(oauth_client_secret::deleted_at.eq(Utc::now()))
            .execute_async(&*self.pool.get().await?)
            .await?;

        let query = oauth_client_secret::dsl::oauth_client_secret
            .into_boxed()
            .filter(oauth_client_secret::id.eq(id.into_untyped_uuid()));

        let result = query
            .get_result_async::<OAuthClientSecretModel>(&*self.pool.get().await?)
            .await
            .optional()?;

        Ok(result.map(|secret| secret.into()))
    }
}

#[async_trait]
impl OAuthClientRedirectUriStore for PostgresStore {
    async fn upsert(
        &self,
        redirect_uri: NewOAuthClientRedirectUri,
    ) -> Result<OAuthClientRedirectUri, StoreError> {
        let redirect_uri_m: OAuthClientRedirectUriModel =
            insert_into(oauth_client_redirect_uri::dsl::oauth_client_redirect_uri)
                .values((
                    oauth_client_redirect_uri::id.eq(redirect_uri.id.into_untyped_uuid()),
                    oauth_client_redirect_uri::oauth_client_id
                        .eq(redirect_uri.oauth_client_id.into_untyped_uuid()),
                    oauth_client_redirect_uri::redirect_uri.eq(redirect_uri.redirect_uri),
                ))
                .get_result_async(&*self.pool.get().await?)
                .await?;

        Ok(redirect_uri_m.into())
    }

    async fn delete(
        &self,
        id: &TypedUuid<OAuthRedirectUriId>,
    ) -> Result<Option<OAuthClientRedirectUri>, StoreError> {
        let _ = update(oauth_client_redirect_uri::dsl::oauth_client_redirect_uri)
            .filter(oauth_client_redirect_uri::id.eq(id.into_untyped_uuid()))
            .set(oauth_client_redirect_uri::deleted_at.eq(Utc::now()))
            .execute_async(&*self.pool.get().await?)
            .await?;

        let query = oauth_client_redirect_uri::dsl::oauth_client_redirect_uri
            .into_boxed()
            .filter(oauth_client_redirect_uri::id.eq(id.into_untyped_uuid()));

        let result = query
            .get_result_async::<OAuthClientRedirectUriModel>(&*self.pool.get().await?)
            .await
            .optional()?;

        Ok(result.map(|redirect| redirect.into()))
    }
}

#[async_trait]
impl<T> AccessGroupStore<T> for PostgresStore
where
    T: Permission,
{
    async fn get(
        &self,
        id: &TypedUuid<AccessGroupId>,
        deleted: bool,
    ) -> Result<Option<AccessGroup<T>>, StoreError> {
        let client = AccessGroupStore::list(
            self,
            AccessGroupFilter {
                id: Some(vec![*id]),
                name: None,
                deleted,
            },
            &ListPagination::default().limit(1),
        )
        .await?;

        Ok(client.into_iter().nth(0))
    }

    async fn list(
        &self,
        filter: AccessGroupFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<AccessGroup<T>>, StoreError> {
        let mut query = access_groups::dsl::access_groups.into_boxed();

        let AccessGroupFilter { id, name, deleted } = filter;

        if let Some(id) = id {
            query = query.filter(
                access_groups::id.eq_any(id.into_iter().map(|group| group.into_untyped_uuid())),
            );
        }

        if let Some(name) = name {
            query = query.filter(access_groups::name.eq_any(name));
        }

        if !deleted {
            query = query.filter(access_groups::deleted_at.is_null());
        }

        let results = query
            .offset(pagination.offset)
            .limit(pagination.limit)
            .order(access_groups::created_at.desc())
            .get_results_async::<AccessGroupModel<T>>(&*self.pool.get().await?)
            .await?;

        Ok(results.into_iter().map(|model| model.into()).collect())
    }

    async fn upsert(&self, group: &NewAccessGroup<T>) -> Result<AccessGroup<T>, StoreError> {
        let group_m: AccessGroupModel<T> = insert_into(access_groups::dsl::access_groups)
            .values((
                access_groups::id.eq(group.id.into_untyped_uuid()),
                access_groups::name.eq(group.name.clone()),
                access_groups::permissions.eq(group.permissions.clone()),
            ))
            .on_conflict(access_groups::id)
            .do_update()
            .set((
                access_groups::name.eq(excluded(access_groups::name)),
                access_groups::permissions.eq(excluded(access_groups::permissions)),
                access_groups::updated_at.eq(Utc::now()),
            ))
            .get_result_async(&*self.pool.get().await?)
            .await?;

        Ok(group_m.into())
    }

    async fn delete(
        &self,
        id: &TypedUuid<AccessGroupId>,
    ) -> Result<Option<AccessGroup<T>>, StoreError> {
        let _ = update(access_groups::dsl::access_groups)
            .filter(access_groups::id.eq(id.into_untyped_uuid()))
            .set(access_groups::deleted_at.eq(Utc::now()))
            .execute_async(&*self.pool.get().await?)
            .await?;

        AccessGroupStore::get(self, id, true).await
    }
}

#[async_trait]
impl MapperStore for PostgresStore {
    #[instrument(skip(self), err(Debug))]
    async fn get(
        &self,
        id: &TypedUuid<MapperId>,
        depleted: bool,
        deleted: bool,
    ) -> Result<Option<Mapper>, StoreError> {
        tracing::trace!("Get mapper");

        let client = MapperStore::list(
            self,
            MapperFilter {
                id: Some(vec![*id]),
                name: None,
                depleted,
                deleted,
            },
            &ListPagination::default().limit(1),
        )
        .await?;

        Ok(client.into_iter().nth(0))
    }

    #[instrument(skip(self), err(Debug))]
    async fn list(
        &self,
        filter: MapperFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<Mapper>, StoreError> {
        tracing::trace!("Listing mappers");

        let mut query = mapper::dsl::mapper.into_boxed();

        let MapperFilter {
            id,
            name,
            depleted,
            deleted,
        } = filter;

        if let Some(id) = id {
            query = query
                .filter(mapper::id.eq_any(id.into_iter().map(|mapper| mapper.into_untyped_uuid())));
        }

        if let Some(name) = name {
            query = query.filter(mapper::name.eq_any(name));
        }

        if !depleted {
            query = query.filter(mapper::depleted_at.is_null());
        }

        if !deleted {
            query = query.filter(mapper::deleted_at.is_null());
        }

        let results = query
            .offset(pagination.offset)
            .limit(pagination.limit)
            .order(mapper::created_at.desc())
            .get_results_async::<MapperModel>(&*self.pool.get().await?)
            .await?;

        Ok(results.into_iter().map(|model| model.into()).collect())
    }

    #[instrument(skip(self), err(Debug))]
    async fn upsert(&self, new_mapper: &NewMapper) -> Result<Mapper, StoreError> {
        tracing::trace!("Upserting mapper");

        let depleted = new_mapper
            .max_activations
            .map(|max| new_mapper.activations.unwrap_or(0) == max)
            .unwrap_or(false);

        let mapper_m: MapperModel = insert_into(mapper::dsl::mapper)
            .values((
                mapper::id.eq(new_mapper.id.into_untyped_uuid()),
                mapper::name.eq(new_mapper.name.clone()),
                mapper::rule.eq(new_mapper.rule.clone()),
                mapper::activations.eq(new_mapper.activations),
                mapper::max_activations.eq(new_mapper.max_activations),
                mapper::depleted_at.eq(if depleted { Some(Utc::now()) } else { None }),
            ))
            .on_conflict(mapper::id)
            .do_update()
            .set((
                mapper::activations.eq(excluded(mapper::activations)),
                mapper::depleted_at.eq(excluded(mapper::depleted_at)),
            ))
            .get_result_async(&*self.pool.get().await?)
            .await?;

        Ok(mapper_m.into())
    }

    #[instrument(skip(self), err(Debug))]
    async fn delete(&self, id: &TypedUuid<MapperId>) -> Result<Option<Mapper>, StoreError> {
        tracing::trace!("Deleting mapper");

        let _ = update(mapper::dsl::mapper)
            .filter(mapper::id.eq(id.into_untyped_uuid()))
            .set(mapper::deleted_at.eq(Utc::now()))
            .execute_async(&*self.pool.get().await?)
            .await?;

        MapperStore::get(self, id, false, true).await
    }
}

#[async_trait]
impl LinkRequestStore for PostgresStore {
    #[instrument(skip(self), err(Debug))]
    async fn get(
        &self,
        id: &TypedUuid<LinkRequestId>,
        expired: bool,
        completed: bool,
    ) -> Result<Option<LinkRequest>, StoreError> {
        tracing::trace!("Get link request");

        let client = LinkRequestStore::list(
            self,
            LinkRequestFilter {
                id: Some(vec![*id]),
                provider_id: None,
                user_id: None,
                expired,
                completed,
            },
            &ListPagination::default().limit(1),
        )
        .await?;

        Ok(client.into_iter().nth(0))
    }

    #[instrument(skip(self), err(Debug))]
    async fn list(
        &self,
        filter: LinkRequestFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<LinkRequest>, StoreError> {
        tracing::trace!("Listing link requests");

        let mut query = link_request::dsl::link_request.into_boxed();

        let LinkRequestFilter {
            id,
            provider_id,
            user_id,
            expired,
            completed,
        } = filter;

        if let Some(id) = id {
            query = query.filter(
                link_request::id.eq_any(id.into_iter().map(|link| link.into_untyped_uuid())),
            );
        }

        if let Some(provider_id) = provider_id {
            query = query.filter(
                link_request::source_provider_id.eq_any(
                    provider_id
                        .into_iter()
                        .map(|provider| provider.into_untyped_uuid()),
                ),
            );
        }

        if let Some(user_id) = user_id {
            query = query.filter(link_request::target_api_user_id.eq_any(user_id));
        }

        if !expired {
            query = query.filter(link_request::expires_at.gt(Utc::now()));
        }

        if !completed {
            query = query.filter(link_request::completed_at.is_null());
        }

        let results = query
            .offset(pagination.offset)
            .limit(pagination.limit)
            .order(link_request::created_at.desc())
            .get_results_async::<LinkRequestModel>(&*self.pool.get().await?)
            .await?;

        Ok(results.into_iter().map(|model| model.into()).collect())
    }

    #[instrument(skip(self), err(Debug))]
    async fn upsert(&self, request: &NewLinkRequest) -> Result<LinkRequest, StoreError> {
        tracing::trace!("Upserting link request");

        let link_request_m: LinkRequestModel = insert_into(link_request::dsl::link_request)
            .values((
                link_request::id.eq(request.id.into_untyped_uuid()),
                link_request::source_provider_id.eq(request.source_provider_id.into_untyped_uuid()),
                link_request::source_api_user_id.eq(request.source_user_id.into_untyped_uuid()),
                link_request::target_api_user_id.eq(request.target_user_id.into_untyped_uuid()),
                link_request::secret_signature.eq(request.secret_signature.clone()),
                link_request::created_at.eq(Utc::now()),
                link_request::expires_at.eq(request.expires_at),
                link_request::completed_at.eq(request.completed_at),
            ))
            .on_conflict(link_request::id)
            .do_update()
            .set((link_request::completed_at.eq(excluded(link_request::completed_at)),))
            .get_result_async(&*self.pool.get().await?)
            .await?;

        Ok(link_request_m.into())
    }
}
