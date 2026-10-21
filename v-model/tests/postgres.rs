// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeSet;

use chrono::{Duration, TimeDelta, Utc};
use diesel::{
    PgConnection, RunQueryDsl,
    r2d2::{ConnectionManager, ManageConnection},
    sql_query,
};
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::ops::{Add, Sub};
use uuid::Uuid;
use v_model::{
    NewAccessGroup, NewApiKey, NewApiUser, NewMagicLink, NewMagicLinkAttempt, NewMapper,
    NewOAuthClient, NewOAuthClientAssertion, NewOAuthClientKey, OAuthClientId, UserId,
    jwk::PublicJwk,
    migrations::run_migrations_quiet,
    schema_ext::MagicLinkAttemptState,
    storage::{
        AccessGroupStore, ApiKeyFilter, ApiKeyStore, ApiUserFilter, ApiUserStore, ListPagination,
        MagicLinkAttemptStore, MagicLinkStore, MapperStore, OAuthClientAssertionStore,
        OAuthClientKeyFilter, OAuthClientKeyStore, OAuthClientStore, StoreError,
        postgres::PostgresStore,
    },
};

fn leakable_dbs() -> Vec<String> {
    let leaks = std::env::var("LEAK_TEST_DB").unwrap_or_else(|_| String::new());
    leaks.split(',').map(|s| s.to_string()).collect()
}

#[derive(
    Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema, PartialOrd, Ord,
)]
enum TestPermission {
    CreateApiUser,
    CreateApiKey(TypedUuid<UserId>),
    GetApiKey(TypedUuid<UserId>),
    DeleteApiKey(TypedUuid<UserId>),
}

impl v_model::permissions::PermissionStorage for TestPermission {
    fn contract(collection: &v_model::Permissions<Self>) -> v_model::Permissions<Self> {
        collection.clone()
    }
    fn expand(
        collection: &v_model::Permissions<Self>,
        _actor: &v_model::ApiUser<Self>,
        _actor_permissions: Option<&v_model::Permissions<Self>>,
        _extensions: &v_model::permissions::ArcMap,
    ) -> v_model::Permissions<Self> {
        collection.clone()
    }
    fn implies(held: &Self, target: &Self) -> bool {
        held == target
    }
}

// A fresh test database that will be created and migrated for use in a test. At the end of the
// the test (or when the database is dropped) the database will be deleted
#[derive(Debug)]
struct TestDb {
    pub db_base: String,
    pub db_name: String,
    pub should_drop: bool,
}

impl TestDb {
    pub fn new(test_name: &str) -> Self {
        // TEST_DATABASE should be a connection string that does not
        // define the initial database.
        //
        // `postgres://<user>:<pass>@localhost`
        let db_base = std::env::var("TEST_DATABASE").unwrap();
        let db_name = format!(
            "v_api_{}_{}",
            test_name,
            Uuid::new_v4().to_string().replace("-", "_")
        );

        let should_drop = !leakable_dbs().iter().any(|s| s == test_name);

        let db = Self {
            db_base,
            db_name,
            should_drop,
        };

        println!("Creating database {}", db.db_name);
        let create_result = sql_query(format!("CREATE DATABASE {}", db.db_name))
            .execute(&mut db.conn())
            .unwrap();
        println!("Created database {:?}", create_result);

        println!("Running migrations on {}", db.url());
        run_migrations_quiet(&db.url());
        println!("Ran migrtations on {}", db.url());

        db
    }

    pub fn url(&self) -> String {
        format!("{}/{}", self.db_base, self.db_name)
    }

    fn conn(&self) -> PgConnection {
        // Connect to the builtin postgres database since we know it exists.
        // This makes it easier to deal with postgres instances stood up as
        // part of a dev environment manager such as flox.dev
        let url = format!("{}/postgres", self.db_base);
        let conn: ConnectionManager<PgConnection> = ConnectionManager::new(&url);
        conn.connect().unwrap()
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        if self.should_drop {
            sql_query(format!("DROP DATABASE {}", self.db_name))
                .execute(&mut self.conn())
                .unwrap();
        }
    }
}

// Steps through the process of:
//   1. Creating an API user
//   2. Retrieve the user
//   3. Update the user's email
//   4. Update the user's permissions
//   5. Create an API token for the user
//   6. Create an API token with excess permissions for the user
//   7. Create an expired API token for the user
//   8. List the active API tokens for the user
//   9. List all API tokens for the user
//   10. Delete the API tokens for the user
//   11. List the deleted API tokens for the user
//   12. Delete the user
//   13. List the deleted user
#[tokio::test]
async fn test_api_user() {
    let db = TestDb::new("test_api_user");
    let store = PostgresStore::new(&db.url()).await.unwrap();

    let api_user_id = TypedUuid::new_v4();

    // 1. Create an API user
    let api_user = ApiUserStore::<TestPermission>::upsert(
        &store,
        NewApiUser {
            id: api_user_id,
            permissions: vec![TestPermission::CreateApiKey(api_user_id)].into(),
            groups: BTreeSet::new(),
        },
    )
    .await
    .unwrap();

    // 2. Retrieve the user
    let api_user_lookup = ApiUserStore::get(&store, &api_user.user.id, false)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(api_user, api_user_lookup);

    // 3. Update the user's email
    let api_user = ApiUserStore::<TestPermission>::upsert(
        &store,
        NewApiUser {
            id: api_user_id,
            permissions: vec![TestPermission::CreateApiKey(api_user_id)].into(),
            groups: BTreeSet::new(),
        },
    )
    .await
    .unwrap();

    assert_eq!(api_user_id, api_user.user.id);

    // 4. Update the user's permissions
    let api_user = ApiUserStore::<TestPermission>::upsert(
        &store,
        NewApiUser {
            id: api_user_id,
            permissions: vec![
                TestPermission::CreateApiKey(api_user_id),
                TestPermission::GetApiKey(api_user_id),
                TestPermission::DeleteApiKey(api_user_id),
            ]
            .into(),
            groups: BTreeSet::new(),
        },
    )
    .await
    .unwrap();

    assert!(
        api_user
            .user
            .permissions
            .can(&TestPermission::GetApiKey(api_user_id))
    );
    assert!(
        api_user
            .user
            .permissions
            .can(&TestPermission::DeleteApiKey(api_user_id))
    );

    // 5. Create an API token for the user
    let token = ApiKeyStore::<TestPermission>::upsert(
        &store,
        NewApiKey {
            id: TypedUuid::new_v4(),
            user_id: api_user.user.id,
            key_signature: format!("key-{}", Uuid::new_v4()),
            permission_boundary: Some(vec![TestPermission::GetApiKey(api_user_id)].into()),
            expires_at: Utc::now() + TimeDelta::try_seconds(5 * 60).unwrap(),
        },
    )
    .await
    .unwrap();

    // 6. Create an API token with excess permissions for the user
    let excess_token = ApiKeyStore::upsert(
        &store,
        NewApiKey {
            id: TypedUuid::new_v4(),
            user_id: api_user.user.id,
            key_signature: format!("key-{}", Uuid::new_v4()),
            permission_boundary: Some(
                vec![
                    TestPermission::CreateApiUser,
                    TestPermission::GetApiKey(api_user_id),
                ]
                .into(),
            ),
            expires_at: Utc::now() + TimeDelta::try_seconds(5 * 60).unwrap(),
        },
    )
    .await
    .unwrap();

    assert!(
        excess_token
            .permission_boundary
            .as_ref()
            .unwrap()
            .can(&TestPermission::CreateApiUser)
    );

    // 7. Create an API token with excess permissions for the user
    let expired_token = ApiKeyStore::<TestPermission>::upsert(
        &store,
        NewApiKey {
            id: TypedUuid::new_v4(),
            user_id: api_user.user.id,
            key_signature: format!("key-{}", Uuid::new_v4()),
            permission_boundary: Some(
                vec![
                    TestPermission::CreateApiUser,
                    TestPermission::GetApiKey(api_user_id),
                ]
                .into(),
            ),
            expires_at: Utc::now() - TimeDelta::try_seconds(5 * 60).unwrap(),
        },
    )
    .await
    .unwrap();

    assert!(expired_token.expires_at < Utc::now());

    // 8. List the active API tokens for the user
    let tokens = ApiKeyStore::list(
        &store,
        ApiKeyFilter {
            id: None,
            api_user_id: Some(vec![api_user.user.id]),
            key_signature: None,
            expired: false,
            deleted: false,
        },
        &ListPagination::default(),
    )
    .await
    .unwrap();

    assert_eq!(tokens.len(), 2);
    assert!(tokens.contains(&token));
    assert!(tokens.contains(&excess_token));

    // 9. List all API tokens for the user
    let all_tokens = ApiKeyStore::list(
        &store,
        ApiKeyFilter {
            id: None,
            api_user_id: Some(vec![api_user.user.id]),
            key_signature: None,
            expired: true,
            deleted: false,
        },
        &ListPagination::default(),
    )
    .await
    .unwrap();

    assert!(all_tokens.len() == 3);
    assert!(all_tokens.contains(&expired_token));

    // 10. Lookup an API token for the user
    let token_lookup = ApiKeyStore::<TestPermission>::get(&store, &token.id, false)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(token.id, token_lookup.id);

    // 11. Delete the API tokens for the user
    for token in all_tokens {
        let _ = ApiKeyStore::<TestPermission>::delete(&store, &token.id)
            .await
            .unwrap();
    }

    // 12. List the deleted API tokens for the user
    let deleted_tokens = ApiKeyStore::<TestPermission>::list(
        &store,
        ApiKeyFilter {
            id: None,
            api_user_id: Some(vec![api_user.user.id]),
            key_signature: None,
            expired: true,
            deleted: true,
        },
        &ListPagination::default(),
    )
    .await
    .unwrap();

    assert!(deleted_tokens.len() == 3);

    for token in deleted_tokens {
        assert!(token.deleted_at.is_some());
        assert!(token.deleted_at.unwrap() < Utc::now());
    }

    // 13. Delete the user
    let api_user = ApiUserStore::<TestPermission>::delete(&store, &api_user.user.id)
        .await
        .unwrap()
        .unwrap();

    assert!(api_user.user.deleted_at.is_some());
    assert!(api_user.user.deleted_at.unwrap() < Utc::now());
    println!("Created api user {:#?}", api_user);

    // 14. List the deleted user
    let all_api_users = ApiUserStore::<TestPermission>::list(
        &store,
        ApiUserFilter {
            id: None,
            email: None,
            groups: None,
            deleted: true,
        },
        &ListPagination::default(),
    )
    .await
    .unwrap();

    assert!(all_api_users.len() == 1);

    for user in all_api_users {
        assert!(user.user.deleted_at.is_some());
        assert!(user.user.deleted_at.unwrap() < Utc::now());
    }
}

// Steps through the process of:
//   1. Upsert a magic link attempt
//   2. Retrieve the magic link attempt
//   3. Try to transition with an invalid id
//   4. Try to transition with an invalid secret
//   5. Transition with valid arguments
//   6. Try to transition same attempt a second time
//   7. Upsert an expired magic link attempt
//   8. Try to transition an expired attempt
#[tokio::test]
async fn test_magic_link_attempt() {
    let db = TestDb::new("test_api_user");
    let store = PostgresStore::new(&db.url()).await.unwrap();

    // Create a client to reference
    let client_id = TypedUuid::new_v4();
    MagicLinkStore::upsert(&store, NewMagicLink { id: client_id })
        .await
        .unwrap();

    // 1. Create a magic link attempt
    let attempt = MagicLinkAttemptStore::upsert(
        &store,
        NewMagicLinkAttempt {
            id: TypedUuid::new_v4(),
            attempt_state: MagicLinkAttemptState::Sent,
            magic_link_client_id: client_id,
            recipient: String::new(),
            medium: String::new(),
            channel: String::new(),
            redirect_uri: String::new(),
            scope: String::new(),
            nonce_signature: "xxxxx".to_string(),
            expiration: Utc::now().add(Duration::seconds(60)),
        },
    )
    .await
    .unwrap();

    // 2. Retrieve the attempt
    let attempt_lookup = MagicLinkAttemptStore::get(&store, &attempt.id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(attempt, attempt_lookup);

    // 3. Try to transition with an invalid id
    let attempt_lookup = MagicLinkAttemptStore::transition(
        &store,
        &TypedUuid::new_v4(),
        &attempt.nonce_signature,
        MagicLinkAttemptState::Sent,
        MagicLinkAttemptState::Complete,
    )
    .await
    .unwrap();

    assert_eq!(None, attempt_lookup);

    // 4. Try to transition with an invalid secret
    let attempt_lookup = MagicLinkAttemptStore::transition(
        &store,
        &attempt.id,
        "",
        MagicLinkAttemptState::Sent,
        MagicLinkAttemptState::Complete,
    )
    .await
    .unwrap();

    assert_eq!(None, attempt_lookup);

    // 5. Transition with valid arguments
    let attempt_lookup = MagicLinkAttemptStore::transition(
        &store,
        &attempt.id,
        &attempt.nonce_signature,
        MagicLinkAttemptState::Sent,
        MagicLinkAttemptState::Complete,
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        MagicLinkAttemptState::Complete,
        attempt_lookup.attempt_state
    );

    // 6. Try to transition same attempt a second time
    let attempt_lookup = MagicLinkAttemptStore::transition(
        &store,
        &attempt.id,
        &attempt.nonce_signature,
        MagicLinkAttemptState::Sent,
        MagicLinkAttemptState::Complete,
    )
    .await
    .unwrap();

    assert_eq!(None, attempt_lookup);

    // 7. Upsert an expired magic link attempt
    let expired_attempt = MagicLinkAttemptStore::upsert(
        &store,
        NewMagicLinkAttempt {
            id: TypedUuid::new_v4(),
            attempt_state: MagicLinkAttemptState::Sent,
            magic_link_client_id: client_id,
            recipient: String::new(),
            medium: String::new(),
            channel: String::new(),
            redirect_uri: String::new(),
            scope: String::new(),
            nonce_signature: "xxxxx".to_string(),
            expiration: Utc::now().sub(Duration::seconds(60)),
        },
    )
    .await
    .unwrap();

    // 8. Try to transition an expired attempt
    let expired_attempt_lookup = MagicLinkAttemptStore::transition(
        &store,
        &expired_attempt.id,
        &expired_attempt.nonce_signature,
        MagicLinkAttemptState::Sent,
        MagicLinkAttemptState::Complete,
    )
    .await
    .unwrap();

    assert_eq!(None, expired_attempt_lookup);
}

// Verifies that a mapper's activation limit is enforced atomically by the
// store's upsert. A mapper with `max_activations = 1` must be redeemable at
// most once, even when two redemptions race. This guards against the
// read-modify-write race where two concurrent logins could both redeem a
// single-use mapper.
//
// Steps:
//   1. Create a single-use mapper (activations = 0, max_activations = 1)
//   2. Redeem it once (activations -> 1, depleted_at set)
//   3. A second sequential redemption is rejected
//   4. Two concurrent redemptions of a fresh single-use mapper yield exactly
//      one success, and the persisted counter records a single activation
#[tokio::test]
async fn test_mapper_activation_limit() {
    let db = TestDb::new("test_mapper_activation_limit");
    let store = PostgresStore::new(&db.url()).await.unwrap();

    // 1. Create a single-use mapper. The insert path stores the provided
    //    activation count as-is.
    let mapper_id = TypedUuid::new_v4();
    let seed = NewMapper {
        id: mapper_id,
        name: format!("seq-{}", Uuid::new_v4()),
        rule: serde_json::json!({ "rule": "default" }),
        activations: Some(0),
        max_activations: Some(1),
    };

    let created = MapperStore::upsert(&store, &seed).await.unwrap();
    assert_eq!(created.activations, Some(0));
    assert!(created.depleted_at.is_none());

    // 2. The first redemption increments the counter and depletes the mapper.
    let consumed = MapperStore::upsert(&store, &seed).await.unwrap();
    assert_eq!(consumed.activations, Some(1));
    assert!(consumed.depleted_at.is_some());

    // 3. A second redemption is rejected: the guarded update affects no rows,
    //    which surfaces as an error.
    let depleted = MapperStore::upsert(&store, &seed).await;
    assert!(
        depleted.is_err(),
        "a depleted single-use mapper must not be redeemable again, got {:?}",
        depleted.map(|m| m.activations),
    );

    // 4. Race two redemptions of a fresh single-use mapper. Regardless of
    //    interleaving, `INSERT ... ON CONFLICT DO UPDATE` locks the row and the
    //    `WHERE activations < max_activations` guard ensures exactly one wins.
    let race_id = TypedUuid::new_v4();
    let race_seed = NewMapper {
        id: race_id,
        name: format!("race-{}", Uuid::new_v4()),
        rule: serde_json::json!({ "rule": "default" }),
        activations: Some(0),
        max_activations: Some(1),
    };
    MapperStore::upsert(&store, &race_seed).await.unwrap();

    let (first, second) = tokio::join!(
        MapperStore::upsert(&store, &race_seed),
        MapperStore::upsert(&store, &race_seed),
    );

    let successes = [&first, &second].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        successes,
        1,
        "exactly one of two concurrent redemptions of a max_activations=1 mapper should succeed, \
         got first={:?} second={:?}",
        first.as_ref().map(|m| m.activations),
        second.as_ref().map(|m| m.activations),
    );

    // The persisted counter reflects exactly one activation, and the mapper is
    // marked depleted.
    let final_mapper = MapperStore::get(&store, &race_id, true, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(final_mapper.activations, Some(1));
    assert!(final_mapper.depleted_at.is_some());
}

async fn create_user(store: &PostgresStore) -> TypedUuid<UserId> {
    let id = TypedUuid::new_v4();
    ApiUserStore::<TestPermission>::upsert(
        store,
        NewApiUser {
            id,
            permissions: Default::default(),
            groups: BTreeSet::new(),
        },
    )
    .await
    .unwrap();
    id
}

async fn create_client(store: &PostgresStore) -> TypedUuid<OAuthClientId> {
    let id = TypedUuid::new_v4();
    OAuthClientStore::upsert(store, NewOAuthClient { id })
        .await
        .unwrap();
    id
}

fn new_key(client_id: TypedUuid<OAuthClientId>, thumbprint: &str) -> NewOAuthClientKey {
    NewOAuthClientKey {
        id: TypedUuid::new_v4(),
        oauth_client_id: client_id,
        thumbprint: thumbprint.to_string(),
        // A distinct key per thumbprint, which is all these tests need
        jwk: PublicJwk::ed25519([*thumbprint.as_bytes().last().unwrap(); 32]),
    }
}

// A client's service user can be assigned once and is never rebound afterwards
#[tokio::test]
async fn test_oauth_client_service_user() {
    let db = TestDb::new("test_oauth_client_service_user");
    let store = PostgresStore::new(&db.url()).await.unwrap();

    let client_id = create_client(&store).await;
    let client = OAuthClientStore::get(&store, &client_id, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(None, client.api_user_id);

    let first = create_user(&store).await;
    let client = OAuthClientStore::assign_api_user(&store, &client_id, &first)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(Some(first), client.api_user_id);

    // A second assignment leaves the original service user in place
    let second = create_user(&store).await;
    let client = OAuthClientStore::assign_api_user(&store, &client_id, &second)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(Some(first), client.api_user_id);

    // A service user backs at most one client
    let other_client = create_client(&store).await;
    let result = OAuthClientStore::assign_api_user(&store, &other_client, &first).await;
    assert!(
        matches!(result, Err(StoreError::Conflict)),
        "a service user was assigned to two clients, got {result:?}"
    );

    // A deleted client is never assigned a service user
    let deleted_client = create_client(&store).await;
    OAuthClientStore::delete(&store, &deleted_client)
        .await
        .unwrap();
    let assigned = OAuthClientStore::assign_api_user(&store, &deleted_client, &second)
        .await
        .unwrap();
    assert!(assigned.is_none());
    let deleted = OAuthClientStore::get(&store, &deleted_client, true)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(None, deleted.api_user_id);
}

// Keys are listed on their client, deleted keys drop out of listings, and a thumbprint can
// never be registered twice
#[tokio::test]
async fn test_oauth_client_keys() {
    let db = TestDb::new("test_oauth_client_keys");
    let store = PostgresStore::new(&db.url()).await.unwrap();

    let client_id = create_client(&store).await;
    let first = OAuthClientKeyStore::insert(&store, new_key(client_id, "thumbprint-a"))
        .await
        .unwrap();

    // The key reads back from its JSONB column exactly as it was written
    assert_eq!(new_key(client_id, "thumbprint-a").jwk, first.jwk);
    let second = OAuthClientKeyStore::insert(&store, new_key(client_id, "thumbprint-b"))
        .await
        .unwrap();

    // The client carries its keys
    let client = OAuthClientStore::get(&store, &client_id, false)
        .await
        .unwrap()
        .unwrap();
    let thumbprints = client
        .keys
        .iter()
        .map(|key| key.thumbprint.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        BTreeSet::from(["thumbprint-a", "thumbprint-b"]),
        thumbprints
    );

    // Keys can be found by thumbprint, which is how an assertion's kid is resolved
    let found = OAuthClientKeyStore::list(
        &store,
        OAuthClientKeyFilter {
            thumbprint: Some(vec!["thumbprint-b".to_string()]),
            ..Default::default()
        },
        &ListPagination::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        vec![second.id],
        found.iter().map(|key| key.id).collect::<Vec<_>>()
    );

    // A deleted key leaves listings and its client, but is still retrievable when asked for
    let deleted = OAuthClientKeyStore::delete(&store, &first.id)
        .await
        .unwrap()
        .unwrap();
    assert!(deleted.deleted_at.is_some());
    assert!(
        OAuthClientKeyStore::get(&store, &first.id, false)
            .await
            .unwrap()
            .is_none()
    );
    let client = OAuthClientStore::get(&store, &client_id, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        vec![second.id],
        client.keys.iter().map(|key| key.id).collect::<Vec<_>>()
    );

    // Deleting again keeps the original deletion time
    let deleted_again = OAuthClientKeyStore::delete(&store, &first.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(deleted.deleted_at, deleted_again.deleted_at);

    // A thumbprint is unique across every client, including keys that have been deleted
    let other_client = create_client(&store).await;
    for thumbprint in ["thumbprint-a", "thumbprint-b"] {
        let result = OAuthClientKeyStore::insert(&store, new_key(other_client, thumbprint)).await;
        assert!(
            matches!(result, Err(StoreError::Conflict)),
            "{thumbprint} was registered twice, got {result:?}"
        );
    }
}

// An assertion is accepted once per client, and expired assertions can be pruned
#[tokio::test]
async fn test_oauth_client_assertions() {
    let db = TestDb::new("test_oauth_client_assertions");
    let store = PostgresStore::new(&db.url()).await.unwrap();

    let client_id = create_client(&store).await;
    let other_client = create_client(&store).await;
    let expires_at = Utc::now() + TimeDelta::minutes(5);

    let assertion =
        |client: TypedUuid<OAuthClientId>, jti: &str, expires_at| NewOAuthClientAssertion {
            oauth_client_id: client,
            jti: jti.to_string(),
            expires_at,
        };

    OAuthClientAssertionStore::record(&store, assertion(client_id, "jti-1", expires_at))
        .await
        .unwrap();

    // Presenting the same jti again is a replay
    let replay =
        OAuthClientAssertionStore::record(&store, assertion(client_id, "jti-1", expires_at)).await;
    assert!(
        matches!(replay, Err(StoreError::Conflict)),
        "a replayed assertion was accepted, got {replay:?}"
    );

    // The jti is chosen by the client, so another client may use the same value
    OAuthClientAssertionStore::record(&store, assertion(other_client, "jti-1", expires_at))
        .await
        .unwrap();

    // Only assertions that expired before the cutoff are pruned
    let expired = Utc::now() - TimeDelta::minutes(10);
    OAuthClientAssertionStore::record(&store, assertion(client_id, "jti-2", expired))
        .await
        .unwrap();
    let pruned = OAuthClientAssertionStore::delete_expired(&store, Utc::now())
        .await
        .unwrap();
    assert_eq!(1, pruned);

    // A pruned assertion's jti no longer conflicts, while live ones still do
    OAuthClientAssertionStore::record(&store, assertion(client_id, "jti-2", expires_at))
        .await
        .unwrap();
    let replay =
        OAuthClientAssertionStore::record(&store, assertion(client_id, "jti-1", expires_at)).await;
    assert!(matches!(replay, Err(StoreError::Conflict)));
}

// A conditional write lands only when the record is unchanged since it was read, which is what
// keeps concurrent permission changes from overwriting each other
#[tokio::test]
async fn test_conditional_updates() {
    let db = TestDb::new("test_conditional_updates");
    let store = PostgresStore::new(&db.url()).await.unwrap();

    let user_id = create_user(&store).await;
    let read = ApiUserStore::<TestPermission>::get(&store, &user_id, false)
        .await
        .unwrap()
        .unwrap();

    let change = |permissions: Vec<TestPermission>| NewApiUser {
        id: user_id,
        permissions: permissions.into(),
        groups: BTreeSet::new(),
    };

    // The first write from this read lands
    let written = ApiUserStore::update(
        &store,
        change(vec![TestPermission::CreateApiUser]),
        read.user.generation,
    )
    .await
    .unwrap()
    .expect("a write from a current read should land");
    assert_eq!(read.user.generation + 1, written.user.generation);

    // A second write from the same, now stale, read is rejected and changes nothing
    let stale = ApiUserStore::update(
        &store,
        change(vec![TestPermission::GetApiKey(user_id)]),
        read.user.generation,
    )
    .await
    .unwrap();
    assert!(stale.is_none());
    let current = ApiUserStore::<TestPermission>::get(&store, &user_id, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(written.user.permissions, current.user.permissions);

    // A deleted user is never written
    ApiUserStore::<TestPermission>::delete(&store, &user_id)
        .await
        .unwrap();
    let deleted = ApiUserStore::update(&store, change(vec![]), current.user.generation)
        .await
        .unwrap();
    assert!(deleted.is_none());

    // Groups follow the same rule
    let group_id = TypedUuid::new_v4();
    let group = AccessGroupStore::<TestPermission>::upsert(
        &store,
        &NewAccessGroup {
            id: group_id,
            name: "engineering".to_string(),
            permissions: Default::default(),
        },
    )
    .await
    .unwrap();
    let change = |name: &str, permissions: Vec<TestPermission>| NewAccessGroup::<TestPermission> {
        id: group_id,
        name: name.to_string(),
        permissions: permissions.into(),
    };

    // A write from the current read lands, and changes the permissions but never the name, even
    // when a different name is supplied. Mappers resolve groups by name.
    let written = AccessGroupStore::update(
        &store,
        &change("platform", vec![TestPermission::CreateApiUser]),
        group.generation,
    )
    .await
    .unwrap()
    .expect("a write from a current read should land");
    assert_eq!("engineering", written.name);
    assert_eq!(
        v_model::Permissions::from(vec![TestPermission::CreateApiUser]),
        written.permissions
    );
    assert_eq!(group.generation + 1, written.generation);

    // Upserting an existing group keeps its name too
    let upserted = AccessGroupStore::upsert(
        &store,
        &change("other", vec![TestPermission::CreateApiUser]),
    )
    .await
    .unwrap();
    assert_eq!("engineering", upserted.name);

    let stale = AccessGroupStore::update(&store, &change("engineering", vec![]), group.generation)
        .await
        .unwrap();
    assert!(stale.is_none());
}
