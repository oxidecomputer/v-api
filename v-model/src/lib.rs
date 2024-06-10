// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{DateTime, Utc};
use db::{
    AccessGroupModel, ApiKeyModel, ApiUserAccessTokenModel, ApiUserModel, ApiUserProviderModel,
    LinkRequestModel, LoginAttemptModel, MapperModel, OAuthClientModel,
    OAuthClientRedirectUriModel, OAuthClientSecretModel,
};
use newtype_uuid::{GenericUuid, TypedUuid, TypedUuidKind, TypedUuidTag};
use partial_struct::partial;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};
use thiserror::Error;

pub mod db;
pub mod permissions;
pub mod schema;
pub mod schema_ext;
pub mod storage;

pub use {permissions::Permissions, schema_ext::LoginAttemptState};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ApiUserInfo<T> {
    pub user: ApiUser<T>,
    pub providers: Vec<ApiUserProvider>,
}

#[derive(JsonSchema)]
pub enum UserId {}
impl TypedUuidKind for UserId {
    fn tag() -> TypedUuidTag {
        const TAG: TypedUuidTag = TypedUuidTag::new("user");
        TAG
    }
}

#[partial(NewApiUser)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ApiUser<T> {
    pub id: TypedUuid<UserId>,
    pub permissions: Permissions<T>,
    pub groups: BTreeSet<TypedUuid<AccessGroupId>>,
    #[partial(NewApiUser(skip))]
    pub created_at: DateTime<Utc>,
    #[partial(NewApiUser(skip))]
    pub updated_at: DateTime<Utc>,
    #[partial(NewApiUser(skip))]
    pub deleted_at: Option<DateTime<Utc>>,
}

impl<T> From<ApiUserModel<T>> for ApiUser<T> {
    fn from(value: ApiUserModel<T>) -> Self {
        ApiUser {
            id: TypedUuid::from_untyped_uuid(value.id),
            permissions: value.permissions,
            groups: value
                .groups
                .into_iter()
                .filter_map(|g| g.map(TypedUuid::from_untyped_uuid))
                .collect(),
            created_at: value.created_at,
            updated_at: value.updated_at,
            deleted_at: value.deleted_at,
        }
    }
}

#[derive(JsonSchema)]
pub enum UserProviderId {}
impl TypedUuidKind for UserProviderId {
    fn tag() -> TypedUuidTag {
        const TAG: TypedUuidTag = TypedUuidTag::new("user-provider");
        TAG
    }
}

#[partial(NewApiUserProvider)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ApiUserProvider {
    pub id: TypedUuid<UserProviderId>,
    pub user_id: TypedUuid<UserId>,
    pub provider: String,
    pub provider_id: String,
    pub emails: Vec<String>,
    pub display_names: Vec<String>,
    #[partial(NewApiUserProvider(skip))]
    pub created_at: DateTime<Utc>,
    #[partial(NewApiUserProvider(skip))]
    pub updated_at: DateTime<Utc>,
    #[partial(NewApiUserProvider(skip))]
    pub deleted_at: Option<DateTime<Utc>>,
}

impl From<ApiUserProviderModel> for ApiUserProvider {
    fn from(value: ApiUserProviderModel) -> Self {
        ApiUserProvider {
            id: TypedUuid::from_untyped_uuid(value.id),
            user_id: TypedUuid::from_untyped_uuid(value.api_user_id),
            provider: value.provider,
            provider_id: value.provider_id,
            emails: value.emails.into_iter().filter_map(|e| e).collect(),
            display_names: value.display_names.into_iter().filter_map(|d| d).collect(),
            created_at: value.created_at,
            updated_at: value.updated_at,
            deleted_at: value.deleted_at,
        }
    }
}

#[derive(JsonSchema)]
pub enum ApiKeyId {}
impl TypedUuidKind for ApiKeyId {
    fn tag() -> TypedUuidTag {
        const TAG: TypedUuidTag = TypedUuidTag::new("api-key");
        TAG
    }
}

#[partial(NewApiKey)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ApiKey<T> {
    pub id: TypedUuid<ApiKeyId>,
    pub user_id: TypedUuid<UserId>,
    pub key_signature: String,
    pub permissions: Option<Permissions<T>>,
    pub expires_at: DateTime<Utc>,
    #[partial(NewApiKey(skip))]
    pub created_at: DateTime<Utc>,
    #[partial(NewApiKey(skip))]
    pub updated_at: DateTime<Utc>,
    #[partial(NewApiKey(skip))]
    pub deleted_at: Option<DateTime<Utc>>,
}

impl<T> From<ApiKeyModel<T>> for ApiKey<T> {
    fn from(value: ApiKeyModel<T>) -> Self {
        ApiKey {
            id: TypedUuid::from_untyped_uuid(value.id),
            user_id: TypedUuid::from_untyped_uuid(value.api_user_id),
            key_signature: value.key_signature,
            permissions: value.permissions,
            expires_at: value.expires_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
            deleted_at: value.deleted_at,
        }
    }
}

#[derive(JsonSchema)]
pub enum AccessTokenId {}
impl TypedUuidKind for AccessTokenId {
    fn tag() -> TypedUuidTag {
        const TAG: TypedUuidTag = TypedUuidTag::new("access-token");
        TAG
    }
}

#[partial(NewAccessToken)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessToken {
    pub id: TypedUuid<AccessTokenId>,
    pub user_id: TypedUuid<UserId>,
    pub revoked_at: Option<DateTime<Utc>>,
    #[partial(NewAccessToken(skip))]
    pub created_at: DateTime<Utc>,
    #[partial(NewAccessToken(skip))]
    pub updated_at: DateTime<Utc>,
}

impl From<ApiUserAccessTokenModel> for AccessToken {
    fn from(value: ApiUserAccessTokenModel) -> Self {
        AccessToken {
            id: TypedUuid::from_untyped_uuid(value.id),
            user_id: TypedUuid::from_untyped_uuid(value.api_user_id),
            revoked_at: value.revoked_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

#[derive(JsonSchema)]
pub enum LoginAttemptId {}
impl TypedUuidKind for LoginAttemptId {
    fn tag() -> TypedUuidTag {
        const TAG: TypedUuidTag = TypedUuidTag::new("login-attempt");
        TAG
    }
}

#[partial(NewLoginAttempt)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LoginAttempt {
    pub id: TypedUuid<LoginAttemptId>,
    pub attempt_state: LoginAttemptState,
    pub client_id: TypedUuid<OAuthClientId>,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub pkce_challenge: Option<String>,
    pub pkce_challenge_method: Option<String>,
    pub authz_code: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub provider: String,
    pub provider_pkce_verifier: Option<String>,
    pub provider_authz_code: Option<String>,
    pub provider_error: Option<String>,
    #[partial(NewLoginAttempt(skip))]
    pub created_at: DateTime<Utc>,
    #[partial(NewLoginAttempt(skip))]
    pub updated_at: DateTime<Utc>,
    pub scope: String,
}

impl LoginAttempt {
    pub fn callback_url(&self) -> String {
        let mut params = BTreeMap::new();

        if let Some(state) = &self.state {
            params.insert("state", state);
        }

        if let Some(error) = &self.error {
            params.insert("error", error);
        } else {
            if let Some(authz_code) = &self.authz_code {
                params.insert("code", authz_code);
            }
        }

        let query_string = params
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        [self.redirect_uri.as_str(), query_string.as_str()].join("?")
    }
}

#[derive(Debug, Error)]
pub struct InvalidValueError {
    pub field: String,
    pub error: String,
}

impl Display for InvalidValueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} has an invalid value: {}", self.field, self.error)
    }
}

impl NewLoginAttempt {
    pub fn new(
        provider: String,
        client_id: TypedUuid<OAuthClientId>,
        redirect_uri: String,
        scope: String,
    ) -> Result<Self, InvalidValueError> {
        Ok(Self {
            id: TypedUuid::new_v4(),
            attempt_state: LoginAttemptState::New,
            client_id,
            redirect_uri,
            state: None,
            pkce_challenge: None,
            pkce_challenge_method: None,
            authz_code: None,
            expires_at: None,
            error: None,
            provider,
            provider_pkce_verifier: None,
            provider_authz_code: None,
            provider_error: None,
            scope,
        })
    }
}

impl From<LoginAttemptModel> for LoginAttempt {
    fn from(value: LoginAttemptModel) -> Self {
        Self {
            id: TypedUuid::from_untyped_uuid(value.id),
            attempt_state: value.attempt_state,
            client_id: TypedUuid::from_untyped_uuid(value.client_id),
            redirect_uri: value.redirect_uri,
            state: value.state,
            pkce_challenge: value.pkce_challenge,
            pkce_challenge_method: value.pkce_challenge_method,
            authz_code: value.authz_code,
            expires_at: value.expires_at,
            error: None,
            provider: value.provider,
            provider_pkce_verifier: value.provider_pkce_verifier,
            provider_authz_code: value.provider_authz_code,
            provider_error: value.provider_error,
            created_at: value.created_at,
            updated_at: value.updated_at,
            scope: value.scope,
        }
    }
}

#[derive(JsonSchema)]
pub enum OAuthClientId {}
impl TypedUuidKind for OAuthClientId {
    fn tag() -> TypedUuidTag {
        const TAG: TypedUuidTag = TypedUuidTag::new("oauth-client");
        TAG
    }
}

#[partial(NewOAuthClient)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OAuthClient {
    pub id: TypedUuid<OAuthClientId>,
    #[partial(NewOAuthClient(skip))]
    pub secrets: Vec<OAuthClientSecret>,
    #[partial(NewOAuthClient(skip))]
    pub redirect_uris: Vec<OAuthClientRedirectUri>,
    #[partial(NewOAuthClient(skip))]
    pub created_at: DateTime<Utc>,
    #[partial(NewOAuthClient(skip))]
    pub deleted_at: Option<DateTime<Utc>>,
}

impl OAuthClient {
    pub fn new(
        client: OAuthClientModel,
        secrets: Vec<OAuthClientSecret>,
        redirect_uris: Vec<OAuthClientRedirectUri>,
    ) -> Self {
        OAuthClient {
            id: TypedUuid::from_untyped_uuid(client.id),
            secrets,
            redirect_uris,
            created_at: client.created_at,
            deleted_at: client.deleted_at,
        }
    }
}

impl From<OAuthClientModel> for OAuthClient {
    fn from(value: OAuthClientModel) -> Self {
        OAuthClient {
            id: TypedUuid::from_untyped_uuid(value.id),
            secrets: vec![],
            redirect_uris: vec![],
            created_at: value.created_at,
            deleted_at: value.deleted_at,
        }
    }
}

#[derive(JsonSchema)]
pub enum OAuthSecretId {}
impl TypedUuidKind for OAuthSecretId {
    fn tag() -> TypedUuidTag {
        const TAG: TypedUuidTag = TypedUuidTag::new("oauth-secret");
        TAG
    }
}

#[partial(NewOAuthClientSecret)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OAuthClientSecret {
    pub id: TypedUuid<OAuthSecretId>,
    pub oauth_client_id: TypedUuid<OAuthClientId>,
    pub secret_signature: String,
    #[partial(NewOAuthClientSecret(skip))]
    pub created_at: DateTime<Utc>,
    #[partial(NewOAuthClientSecret(skip))]
    pub deleted_at: Option<DateTime<Utc>>,
}

impl From<OAuthClientSecretModel> for OAuthClientSecret {
    fn from(value: OAuthClientSecretModel) -> Self {
        OAuthClientSecret {
            id: TypedUuid::from_untyped_uuid(value.id),
            oauth_client_id: TypedUuid::from_untyped_uuid(value.oauth_client_id),
            secret_signature: value.secret_signature,
            created_at: value.created_at,
            deleted_at: value.deleted_at,
        }
    }
}

#[derive(JsonSchema)]
pub enum OAuthRedirectUriId {}
impl TypedUuidKind for OAuthRedirectUriId {
    fn tag() -> TypedUuidTag {
        const TAG: TypedUuidTag = TypedUuidTag::new("oauth-redirect-uri");
        TAG
    }
}

#[partial(NewOAuthClientRedirectUri)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OAuthClientRedirectUri {
    pub id: TypedUuid<OAuthRedirectUriId>,
    pub oauth_client_id: TypedUuid<OAuthClientId>,
    pub redirect_uri: String,
    #[partial(NewOAuthClientRedirectUri(skip))]
    pub created_at: DateTime<Utc>,
    #[partial(NewOAuthClientRedirectUri(skip))]
    pub deleted_at: Option<DateTime<Utc>>,
}

impl From<OAuthClientRedirectUriModel> for OAuthClientRedirectUri {
    fn from(value: OAuthClientRedirectUriModel) -> Self {
        OAuthClientRedirectUri {
            id: TypedUuid::from_untyped_uuid(value.id),
            oauth_client_id: TypedUuid::from_untyped_uuid(value.oauth_client_id),
            redirect_uri: value.redirect_uri,
            created_at: value.created_at,
            deleted_at: value.deleted_at,
        }
    }
}

#[derive(JsonSchema)]
pub enum AccessGroupId {}
impl TypedUuidKind for AccessGroupId {
    fn tag() -> TypedUuidTag {
        const TAG: TypedUuidTag = TypedUuidTag::new("access-group");
        TAG
    }
}

#[partial(NewAccessGroup)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AccessGroup<T> {
    pub id: TypedUuid<AccessGroupId>,
    pub name: String,
    pub permissions: Permissions<T>,
    #[partial(NewAccessGroup(skip))]
    pub created_at: DateTime<Utc>,
    #[partial(NewAccessGroup(skip))]
    pub updated_at: DateTime<Utc>,
    #[partial(NewAccessGroup(skip))]
    pub deleted_at: Option<DateTime<Utc>>,
}

impl<T> From<AccessGroupModel<T>> for AccessGroup<T> {
    fn from(value: AccessGroupModel<T>) -> Self {
        AccessGroup {
            id: TypedUuid::from_untyped_uuid(value.id),
            name: value.name,
            permissions: value.permissions,
            created_at: value.created_at,
            updated_at: value.updated_at,
            deleted_at: value.deleted_at,
        }
    }
}

#[derive(JsonSchema)]
pub enum MapperId {}
impl TypedUuidKind for MapperId {
    fn tag() -> TypedUuidTag {
        const TAG: TypedUuidTag = TypedUuidTag::new("mapper");
        TAG
    }
}

#[partial(NewMapper)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Mapper {
    pub id: TypedUuid<MapperId>,
    pub name: String,
    pub rule: Value,
    pub activations: Option<i32>,
    pub max_activations: Option<i32>,
    #[partial(NewMapper(skip))]
    pub depleted_at: Option<DateTime<Utc>>,
    #[partial(NewMapper(skip))]
    pub created_at: DateTime<Utc>,
    #[partial(NewMapper(skip))]
    pub deleted_at: Option<DateTime<Utc>>,
}

impl From<MapperModel> for Mapper {
    fn from(value: MapperModel) -> Self {
        Mapper {
            id: TypedUuid::from_untyped_uuid(value.id),
            name: value.name,
            rule: value.rule,
            activations: value.activations,
            max_activations: value.max_activations,
            depleted_at: value.depleted_at,
            created_at: value.created_at,
            deleted_at: value.deleted_at,
        }
    }
}

#[derive(JsonSchema)]
pub enum LinkRequestId {}
impl TypedUuidKind for LinkRequestId {
    fn tag() -> TypedUuidTag {
        const TAG: TypedUuidTag = TypedUuidTag::new("link-request");
        TAG
    }
}

#[partial(NewLinkRequest)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LinkRequest {
    pub id: TypedUuid<LinkRequestId>,
    pub source_provider_id: TypedUuid<UserProviderId>,
    pub source_user_id: TypedUuid<UserId>,
    pub target_user_id: TypedUuid<UserId>,
    pub secret_signature: String,
    #[partial(NewLinkRequest(skip))]
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl From<LinkRequestModel> for LinkRequest {
    fn from(value: LinkRequestModel) -> Self {
        LinkRequest {
            id: TypedUuid::from_untyped_uuid(value.id),
            source_provider_id: TypedUuid::from_untyped_uuid(value.source_provider_id),
            source_user_id: TypedUuid::from_untyped_uuid(value.source_api_user_id),
            target_user_id: TypedUuid::from_untyped_uuid(value.target_api_user_id),
            secret_signature: value.secret_signature,
            created_at: value.created_at,
            expires_at: value.expires_at,
            completed_at: value.completed_at,
        }
    }
}
