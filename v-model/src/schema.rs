// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "attempt_state"))]
    pub struct AttemptState;
}

diesel::table! {
    access_groups (id) {
        id -> Uuid,
        name -> Varchar,
        permissions -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    api_key (id) {
        id -> Uuid,
        api_user_id -> Uuid,
        key_signature -> Text,
        permissions -> Nullable<Jsonb>,
        expires_at -> Timestamptz,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    api_user (id) {
        id -> Uuid,
        permissions -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
        groups -> Array<Nullable<Uuid>>,
    }
}

diesel::table! {
    api_user_access_token (id) {
        id -> Uuid,
        api_user_id -> Uuid,
        revoked_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    api_user_provider (id) {
        id -> Uuid,
        api_user_id -> Uuid,
        provider -> Varchar,
        provider_id -> Varchar,
        emails -> Array<Nullable<Text>>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    chat (id) {
        id -> Uuid,
        owner_id -> Uuid,
        external_id -> Varchar,
        external_name -> Varchar,
        external_created -> Timestamptz,
        external_modified -> Timestamptz,
        shared -> Bool,
        downloadable -> Bool,
        indexed -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    link_request (id) {
        id -> Uuid,
        source_provider_id -> Uuid,
        source_api_user_id -> Uuid,
        target_api_user_id -> Uuid,
        secret_signature -> Varchar,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
        completed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::AttemptState;

    login_attempt (id) {
        id -> Uuid,
        attempt_state -> AttemptState,
        client_id -> Uuid,
        redirect_uri -> Varchar,
        state -> Nullable<Varchar>,
        pkce_challenge -> Nullable<Varchar>,
        pkce_challenge_method -> Nullable<Varchar>,
        authz_code -> Nullable<Varchar>,
        expires_at -> Nullable<Timestamptz>,
        error -> Nullable<Varchar>,
        scope -> Varchar,
        provider -> Varchar,
        provider_pkce_verifier -> Nullable<Varchar>,
        provider_authz_code -> Nullable<Varchar>,
        provider_error -> Nullable<Varchar>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    mapper (id) {
        id -> Uuid,
        name -> Varchar,
        rule -> Jsonb,
        activations -> Nullable<Int4>,
        max_activations -> Nullable<Int4>,
        depleted_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    oauth_client (id) {
        id -> Uuid,
        created_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    oauth_client_redirect_uri (id) {
        id -> Uuid,
        oauth_client_id -> Uuid,
        redirect_uri -> Varchar,
        created_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    oauth_client_secret (id) {
        id -> Uuid,
        oauth_client_id -> Uuid,
        secret_signature -> Varchar,
        created_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    owner (id) {
        id -> Uuid,
        subject -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    recording (id) {
        id -> Uuid,
        owner_id -> Uuid,
        external_id -> Varchar,
        external_name -> Varchar,
        external_created -> Timestamptz,
        external_modified -> Timestamptz,
        shared -> Bool,
        downloadable -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    transcript (id) {
        id -> Uuid,
        owner_id -> Uuid,
        external_id -> Varchar,
        external_name -> Varchar,
        external_created -> Timestamptz,
        external_modified -> Timestamptz,
        shared -> Bool,
        downloadable -> Bool,
        indexed -> Bool,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::joinable!(api_key -> api_user (api_user_id));
diesel::joinable!(api_user_access_token -> api_user (api_user_id));
diesel::joinable!(api_user_provider -> api_user (api_user_id));
diesel::joinable!(chat -> owner (owner_id));
diesel::joinable!(oauth_client_redirect_uri -> oauth_client (oauth_client_id));
diesel::joinable!(oauth_client_secret -> oauth_client (oauth_client_id));
diesel::joinable!(recording -> owner (owner_id));
diesel::joinable!(transcript -> owner (owner_id));

diesel::allow_tables_to_appear_in_same_query!(
    access_groups,
    api_key,
    api_user,
    api_user_access_token,
    api_user_provider,
    chat,
    link_request,
    login_attempt,
    mapper,
    oauth_client,
    oauth_client_redirect_uri,
    oauth_client_secret,
    owner,
    recording,
    transcript,
);
