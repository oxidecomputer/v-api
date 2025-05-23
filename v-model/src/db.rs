// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{DateTime, Utc};
use diesel::{Insertable, Queryable};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    permissions::Permissions,
    schema::{
        access_groups, api_key, api_user, api_user_access_token, api_user_contact_email,
        api_user_provider, link_request, login_attempt, magic_link_attempt, magic_link_client,
        magic_link_client_redirect_uri, magic_link_client_secret, mapper, oauth_client,
        oauth_client_redirect_uri, oauth_client_secret,
    },
    schema_ext::{LoginAttemptState, MagicLinkAttemptState},
};

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = api_key)]
pub struct ApiKeyModel<T> {
    pub id: Uuid,
    pub api_user_id: Uuid,
    pub key_signature: String,
    pub permissions: Option<Permissions<T>>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = api_user)]
pub struct ApiUserModel<T> {
    pub id: Uuid,
    pub permissions: Permissions<T>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub groups: Vec<Option<Uuid>>,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = api_user_access_token)]
pub struct ApiUserAccessTokenModel {
    pub id: Uuid,
    pub api_user_id: Uuid,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = api_user_contact_email)]
pub struct ApiUserContactEmailModel {
    pub id: Uuid,
    pub api_user_id: Uuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = api_user_provider)]
pub struct ApiUserProviderModel {
    pub id: Uuid,
    pub api_user_id: Uuid,
    pub provider: String,
    pub provider_id: String,
    pub emails: Vec<Option<String>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub display_names: Vec<Option<String>>,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = login_attempt)]
pub struct LoginAttemptModel {
    pub id: Uuid,
    pub attempt_state: LoginAttemptState,
    pub client_id: Uuid,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub pkce_challenge: Option<String>,
    pub pkce_challenge_method: Option<String>,
    pub authz_code: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
    pub scope: String,
    pub provider: String,
    pub provider_pkce_verifier: Option<String>,
    pub provider_authz_code: Option<String>,
    pub provider_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = oauth_client)]
pub struct OAuthClientModel {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = oauth_client_secret)]
pub struct OAuthClientSecretModel {
    pub id: Uuid,
    pub oauth_client_id: Uuid,
    pub secret_signature: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = oauth_client_redirect_uri)]
pub struct OAuthClientRedirectUriModel {
    pub id: Uuid,
    pub oauth_client_id: Uuid,
    pub redirect_uri: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = magic_link_client)]
pub struct MagicLinkModel {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = magic_link_client_secret)]
pub struct MagicLinkSecretModel {
    pub id: Uuid,
    pub magic_link_client_id: Uuid,
    pub secret_signature: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = magic_link_client_redirect_uri)]
pub struct MagicLinkRedirectUriModel {
    pub id: Uuid,
    pub magic_link_client_id: Uuid,
    pub redirect_uri: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = magic_link_attempt)]
pub struct MagicLinkAttemptModel {
    pub id: Uuid,
    pub attempt_state: MagicLinkAttemptState,
    pub magic_link_client_id: Uuid,
    // TODO: This needs to be the MagicLinkMedium enum
    pub medium: String,
    pub channel: String,
    pub recipient: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub nonce_signature: String,
    pub expiration: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = access_groups)]
pub struct AccessGroupModel<T> {
    pub id: Uuid,
    pub name: String,
    pub permissions: Permissions<T>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = mapper)]
pub struct MapperModel {
    pub id: Uuid,
    pub name: String,
    pub rule: Value,
    pub activations: Option<i32>,
    pub max_activations: Option<i32>,
    pub depleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Queryable, Insertable)]
#[diesel(table_name = link_request)]
pub struct LinkRequestModel {
    pub id: Uuid,
    pub source_provider_id: Uuid,
    pub source_api_user_id: Uuid,
    pub target_api_user_id: Uuid,
    pub secret_signature: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}
