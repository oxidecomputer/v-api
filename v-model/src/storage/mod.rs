// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::fmt::Debug;

pub use async_bb8_diesel::{ConnectionError, PoolError};
use async_trait::async_trait;
use bb8::RunError;
pub use diesel::result::Error as DbError;
#[cfg(feature = "mock")]
use mockall::automock;
use thiserror::Error;
use uuid::Uuid;
use v_api_permissions::Permission;

use crate::{
    schema_ext::LoginAttemptState, AccessGroup, AccessToken, ApiKey, ApiUser, ApiUserProvider,
    LinkRequest, LoginAttempt, Mapper, NewAccessGroup, NewAccessToken, NewApiKey, NewApiUser,
    NewApiUserProvider, NewLinkRequest, NewLoginAttempt, NewMapper, NewOAuthClient,
    NewOAuthClientRedirectUri, NewOAuthClientSecret, OAuthClient, OAuthClientRedirectUri,
    OAuthClientSecret,
};

pub mod postgres;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("Connection failure: {0}")]
    Conn(#[from] RunError<ConnectionError>),
    #[error("Database failure: {0}")]
    Db(#[from] DbError),
    #[error("Connection pool failure: {0}")]
    Pool(#[from] PoolError),
    #[error("Database invariant failed to hold")]
    InvariantFailed(String),
    #[error("Unknown error")]
    Unknown,
}

#[derive(Debug, PartialEq)]
pub struct ListPagination {
    pub offset: i64,
    pub limit: i64,
}

impl Default for ListPagination {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 10,
        }
    }
}

impl ListPagination {
    pub fn latest() -> Self {
        Self::default().limit(1)
    }

    pub fn offset(mut self, offset: i64) -> Self {
        self.offset = offset;
        self
    }

    pub fn limit(mut self, limit: i64) -> Self {
        self.limit = limit;
        self
    }
}

#[derive(Debug, Default)]
pub struct ApiUserFilter {
    pub id: Option<Vec<Uuid>>,
    pub email: Option<Vec<String>>,
    pub groups: Option<Vec<Uuid>>,
    pub deleted: bool,
}

#[cfg_attr(feature = "mock", automock)]
#[async_trait]
pub trait ApiUserStore<T: Permission + Ord> {
    async fn get(&self, id: &Uuid, deleted: bool) -> Result<Option<ApiUser<T>>, StoreError>;
    async fn list(
        &self,
        filter: ApiUserFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<ApiUser<T>>, StoreError>;
    async fn upsert(&self, api_user: NewApiUser<T>) -> Result<ApiUser<T>, StoreError>;
    async fn delete(&self, id: &Uuid) -> Result<Option<ApiUser<T>>, StoreError>;
}

#[derive(Debug, Default)]
pub struct ApiKeyFilter {
    pub id: Option<Vec<Uuid>>,
    pub api_user_id: Option<Vec<Uuid>>,
    pub key_signature: Option<Vec<String>>,
    pub expired: bool,
    pub deleted: bool,
}

#[cfg_attr(feature = "mock", automock)]
#[async_trait]
pub trait ApiKeyStore<T: Permission + Ord> {
    async fn get(&self, id: &Uuid, deleted: bool) -> Result<Option<ApiKey<T>>, StoreError>;
    async fn list(
        &self,
        filter: ApiKeyFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<ApiKey<T>>, StoreError>;
    async fn upsert(&self, token: NewApiKey<T>) -> Result<ApiKey<T>, StoreError>;
    async fn delete(&self, id: &Uuid) -> Result<Option<ApiKey<T>>, StoreError>;
}

#[derive(Debug, Default)]
pub struct ApiUserProviderFilter {
    pub id: Option<Vec<Uuid>>,
    pub api_user_id: Option<Vec<Uuid>>,
    pub provider: Option<Vec<String>>,
    pub provider_id: Option<Vec<String>>,
    pub email: Option<Vec<String>>,
    pub deleted: bool,
}

#[cfg_attr(feature = "mock", automock)]
#[async_trait]
pub trait ApiUserProviderStore {
    async fn get(&self, id: &Uuid, deleted: bool) -> Result<Option<ApiUserProvider>, StoreError>;
    async fn list(
        &self,
        filter: ApiUserProviderFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<ApiUserProvider>, StoreError>;
    async fn upsert(&self, api_user: NewApiUserProvider) -> Result<ApiUserProvider, StoreError>;
    async fn transfer(
        &self,
        api_user: NewApiUserProvider,
        current_api_user_id: Uuid,
    ) -> Result<ApiUserProvider, StoreError>;
    async fn delete(&self, id: &Uuid) -> Result<Option<ApiUserProvider>, StoreError>;
}

#[derive(Debug, Default)]
pub struct AccessTokenFilter {
    pub id: Option<Vec<Uuid>>,
    pub api_user_id: Option<Vec<Uuid>>,
    pub revoked: bool,
}

#[cfg_attr(feature = "mock", automock)]
#[async_trait]
pub trait AccessTokenStore {
    async fn get(&self, id: &Uuid, revoked: bool) -> Result<Option<AccessToken>, StoreError>;
    async fn list(
        &self,
        filter: AccessTokenFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<AccessToken>, StoreError>;
    async fn upsert(&self, token: NewAccessToken) -> Result<AccessToken, StoreError>;
}

#[derive(Debug, Default)]
pub struct LoginAttemptFilter {
    pub id: Option<Vec<Uuid>>,
    pub client_id: Option<Vec<Uuid>>,
    pub attempt_state: Option<Vec<LoginAttemptState>>,
    pub authz_code: Option<Vec<String>>,
}

#[cfg_attr(feature = "mock", automock)]
#[async_trait]
pub trait LoginAttemptStore {
    async fn get(&self, id: &Uuid) -> Result<Option<LoginAttempt>, StoreError>;
    async fn list(
        &self,
        filter: LoginAttemptFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<LoginAttempt>, StoreError>;
    async fn upsert(&self, attempt: NewLoginAttempt) -> Result<LoginAttempt, StoreError>;
}

#[derive(Debug, Default)]
pub struct OAuthClientFilter {
    pub id: Option<Vec<Uuid>>,
    pub deleted: bool,
}

#[cfg_attr(feature = "mock", automock)]
#[async_trait]
pub trait OAuthClientStore {
    async fn get(&self, id: &Uuid, deleted: bool) -> Result<Option<OAuthClient>, StoreError>;
    async fn list(
        &self,
        filter: OAuthClientFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<OAuthClient>, StoreError>;
    async fn upsert(&self, client: NewOAuthClient) -> Result<OAuthClient, StoreError>;
    async fn delete(&self, id: &Uuid) -> Result<Option<OAuthClient>, StoreError>;
}

#[cfg_attr(feature = "mock", automock)]
#[async_trait]
pub trait OAuthClientSecretStore {
    async fn upsert(&self, secret: NewOAuthClientSecret) -> Result<OAuthClientSecret, StoreError>;
    async fn delete(&self, id: &Uuid) -> Result<Option<OAuthClientSecret>, StoreError>;
}

#[cfg_attr(feature = "mock", automock)]
#[async_trait]
pub trait OAuthClientRedirectUriStore {
    async fn upsert(
        &self,
        redirect_uri: NewOAuthClientRedirectUri,
    ) -> Result<OAuthClientRedirectUri, StoreError>;
    async fn delete(&self, id: &Uuid) -> Result<Option<OAuthClientRedirectUri>, StoreError>;
}

#[derive(Debug, Default, PartialEq)]
pub struct AccessGroupFilter {
    pub id: Option<Vec<Uuid>>,
    pub name: Option<Vec<String>>,
    pub deleted: bool,
}

#[cfg_attr(feature = "mock", automock)]
#[async_trait]
pub trait AccessGroupStore<T: Permission + Ord> {
    async fn get(&self, id: &Uuid, deleted: bool) -> Result<Option<AccessGroup<T>>, StoreError>;
    async fn list(
        &self,
        filter: AccessGroupFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<AccessGroup<T>>, StoreError>;
    async fn upsert(&self, group: &NewAccessGroup<T>) -> Result<AccessGroup<T>, StoreError>;
    async fn delete(&self, id: &Uuid) -> Result<Option<AccessGroup<T>>, StoreError>;
}

#[derive(Debug, Default, PartialEq)]
pub struct MapperFilter {
    pub id: Option<Vec<Uuid>>,
    pub name: Option<Vec<String>>,
    pub depleted: bool,
    pub deleted: bool,
}

impl MapperFilter {
    pub fn id(mut self, id: Option<Vec<Uuid>>) -> Self {
        self.id = id;
        self
    }

    pub fn name(mut self, name: Option<Vec<String>>) -> Self {
        self.name = name;
        self
    }

    pub fn depleted(mut self, depleted: bool) -> Self {
        self.depleted = depleted;
        self
    }

    pub fn deleted(mut self, deleted: bool) -> Self {
        self.deleted = deleted;
        self
    }
}

#[cfg_attr(feature = "mock", automock)]
#[async_trait]
pub trait MapperStore {
    async fn get(
        &self,
        id: &Uuid,
        depleted: bool,
        deleted: bool,
    ) -> Result<Option<Mapper>, StoreError>;
    async fn list(
        &self,
        filter: MapperFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<Mapper>, StoreError>;
    async fn upsert(&self, new_mapper: &NewMapper) -> Result<Mapper, StoreError>;
    async fn delete(&self, id: &Uuid) -> Result<Option<Mapper>, StoreError>;
}

#[derive(Debug, Default, PartialEq)]
pub struct LinkRequestFilter {
    pub id: Option<Vec<Uuid>>,
    pub provider_id: Option<Vec<Uuid>>,
    pub user_id: Option<Vec<Uuid>>,
    pub expired: bool,
    pub completed: bool,
}

#[cfg_attr(feature = "mock", automock)]
#[async_trait]
pub trait LinkRequestStore {
    async fn get(
        &self,
        id: &Uuid,
        expired: bool,
        completed: bool,
    ) -> Result<Option<LinkRequest>, StoreError>;
    async fn list(
        &self,
        filter: LinkRequestFilter,
        pagination: &ListPagination,
    ) -> Result<Vec<LinkRequest>, StoreError>;
    async fn upsert(&self, request: &NewLinkRequest) -> Result<LinkRequest, StoreError>;
}
