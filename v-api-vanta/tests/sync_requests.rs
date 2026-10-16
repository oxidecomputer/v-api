// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Checks the requests the client puts on the wire against a stub standing in for Vanta.
//!
//! What Vanta does with a request cannot be tested here, so what is worth pinning down is the
//! shape of what is sent: the full state envelope, the resource ids, and the token handling that
//! Vanta's single active token rule constrains.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use v_api_vanta::{
    AccountStatus, CustomResource, GroupProperties, UserAccount, VantaClient, VantaConfig,
    VantaError,
};

struct Recorded {
    path: String,
    authorization: Option<String>,
    body: serde_json::Value,
}

/// A stand in for Vanta that records what it was sent.
struct StubVanta {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl StubVanta {
    /// Start a stub that answers resource syncs with `sync_status`.
    async fn start(sync_status: StatusCode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let requests = Arc::new(Mutex::new(Vec::new()));

        let recorder = requests.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let recorder = recorder.clone();

                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let recorder = recorder.clone();
                        async move { handle(request, recorder, sync_status).await }
                    });

                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });

        Self { address, requests }
    }

    fn config(&self) -> VantaConfig {
        VantaConfig {
            client_id: "client-id".to_string(),
            client_secret: "client-secret".to_string().into(),
            base_url: format!("http://{}", self.address),
            user_account_resource_id: "user-account-resource".to_string(),
            group_resource_id: Some("group-resource".to_string()),
            api_key_resource_id: None,
        }
    }

    fn client(&self) -> VantaClient {
        VantaClient::new(&self.config(), None).expect("build client")
    }

    fn requests(&self) -> std::sync::MutexGuard<'_, Vec<Recorded>> {
        self.requests.lock().expect("lock")
    }

    fn token_requests(&self) -> usize {
        self.requests()
            .iter()
            .filter(|request| request.path == "/oauth/token")
            .count()
    }
}

async fn handle(
    request: Request<Incoming>,
    recorder: Arc<Mutex<Vec<Recorded>>>,
    sync_status: StatusCode,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    let path = request.uri().path().to_string();
    let method = request.method().clone();
    let authorization = request
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    let bytes = request.collect().await.expect("read body").to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);

    recorder.lock().expect("lock").push(Recorded {
        path: path.clone(),
        authorization,
        body,
    });

    let response = match (&method, path.as_str()) {
        (&Method::POST, "/oauth/token") => Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from(
                r#"{"access_token":"issued-token","expires_in":3600,"token_type":"Bearer"}"#,
            )))
            .expect("token response"),
        (&Method::PUT, _) => Response::builder()
            .status(sync_status)
            .body(Full::new(Bytes::from(r#"{"error":"rejected"}"#)))
            .expect("sync response"),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .expect("not found response"),
    };

    Ok(response)
}

fn account(unique_id: &str) -> UserAccount {
    let now = Utc::now();
    UserAccount {
        unique_id: unique_id.to_string(),
        display_name: "Ada Lovelace".to_string(),
        full_name: None,
        email: Some("ada@example.com".to_string()),
        status: AccountStatus::Active,
        auth_method: Some("google".to_string()),
        external_url: None,
        created_timestamp: now,
        updated_timestamp: now,
    }
}

/// The sync carries the resource id and the complete set of accounts, and is authorized with a
/// token fetched from the token endpoint
#[tokio::test]
async fn a_user_sync_sends_the_full_state_envelope() {
    let vanta = StubVanta::start(StatusCode::OK).await;

    vanta
        .client()
        .sync_user_accounts(vec![account("user-a"), account("user-b")])
        .await
        .expect("sync");

    let requests = vanta.requests();
    assert_eq!(2, requests.len(), "expected a token and a sync request");

    let token = &requests[0];
    assert_eq!("/oauth/token", token.path);
    assert_eq!("client_credentials", token.body["grant_type"]);
    assert_eq!(
        "connectors.self:write-resource", token.body["scope"],
        "the write scope is what lets the integration report resources"
    );

    let sync = &requests[1];
    assert_eq!("/v1/resources/user_account", sync.path);
    assert_eq!(Some("Bearer issued-token".to_string()), sync.authorization);
    assert_eq!("user-account-resource", sync.body["resourceId"]);

    let resources = sync.body["resources"].as_array().expect("resources array");
    assert_eq!(2, resources.len());
    assert_eq!("user-a", resources[0]["uniqueId"]);
    assert_eq!("Ada Lovelace", resources[0]["displayName"]);
    assert_eq!("ACTIVE", resources[0]["status"]);

    // Fields v-api cannot answer for are left off rather than guessed at
    assert!(resources[0].get("mfaEnabled").is_none());
    assert!(resources[0].get("permissionLevel").is_none());
    // As are the optional fields that had no value
    assert!(resources[0].get("fullName").is_none());
}

/// Vanta revokes the previous token whenever a new one is issued, so the client has to hold on to
/// the one it has rather than fetching per request
#[tokio::test]
async fn the_access_token_is_reused_across_syncs() {
    let vanta = StubVanta::start(StatusCode::OK).await;
    let client = vanta.client();

    client
        .sync_user_accounts(vec![account("user-a")])
        .await
        .expect("first sync");
    client
        .sync_user_accounts(vec![account("user-a")])
        .await
        .expect("second sync");
    client
        .sync_custom_resources(
            "group-resource",
            vec![CustomResource {
                unique_id: "group-a".to_string(),
                display_name: "engineering".to_string(),
                external_url: None,
                custom_properties: GroupProperties {
                    name: "engineering".to_string(),
                    source: "dynamic".to_string(),
                    active: true,
                    member_count: 1,
                    member_unique_ids: vec!["user-a".to_string()],
                    created_at: Utc::now(),
                },
            }],
        )
        .await
        .expect("group sync");

    assert_eq!(
        1,
        vanta.token_requests(),
        "each sync fetched its own token, which would revoke the one before it"
    );
}

/// Custom properties sit under their own key, since the dashboard schema only describes them
#[tokio::test]
async fn a_custom_resource_sync_nests_its_properties() {
    let vanta = StubVanta::start(StatusCode::OK).await;

    vanta
        .client()
        .sync_custom_resources(
            "group-resource",
            vec![CustomResource {
                unique_id: "group-a".to_string(),
                display_name: "engineering".to_string(),
                external_url: None,
                custom_properties: GroupProperties {
                    name: "engineering".to_string(),
                    source: "dynamic".to_string(),
                    active: true,
                    member_count: 2,
                    member_unique_ids: vec!["user-a".to_string(), "user-b".to_string()],
                    created_at: Utc::now(),
                },
            }],
        )
        .await
        .expect("sync");

    let requests = vanta.requests();
    let sync = requests.last().expect("sync request");

    assert_eq!("/v1/resources/custom_resource", sync.path);
    assert_eq!("group-resource", sync.body["resourceId"]);

    let resource = &sync.body["resources"][0];
    assert_eq!("group-a", resource["uniqueId"]);
    assert_eq!("engineering", resource["displayName"]);
    assert_eq!("engineering", resource["customProperties"]["name"]);
    assert_eq!(2, resource["customProperties"]["memberCount"]);
    assert_eq!("user-b", resource["customProperties"]["memberUniqueIds"][1]);
}

/// A full state sync of nothing would deprecate every account Vanta holds for the service, so it
/// is refused before a request is made
#[tokio::test]
async fn an_empty_user_sync_is_refused_without_calling_vanta() {
    let vanta = StubVanta::start(StatusCode::OK).await;

    let error = vanta
        .client()
        .sync_user_accounts(vec![])
        .await
        .expect_err("empty sync should be refused");

    assert!(matches!(error, VantaError::NoUserAccounts), "{error:?}");
    assert!(
        vanta.requests().is_empty(),
        "nothing should have been sent to Vanta"
    );
}

/// An empty custom resource sync is allowed, because a service really can have no groups and
/// Vanta has to be told when the last one goes away
#[tokio::test]
async fn an_empty_custom_resource_sync_is_sent() {
    let vanta = StubVanta::start(StatusCode::OK).await;

    vanta
        .client()
        .sync_custom_resources::<GroupProperties>("group-resource", vec![])
        .await
        .expect("sync");

    let requests = vanta.requests();
    let sync = requests.last().expect("sync request");

    assert_eq!("/v1/resources/custom_resource", sync.path);
    assert_eq!(
        0,
        sync.body["resources"].as_array().expect("resources").len()
    );
}

/// Vanta reports schema and resource id problems in the response body, so a rejection has to
/// carry it through or a failed sync says nothing useful
#[tokio::test]
async fn a_rejected_sync_reports_the_status_and_body() {
    let vanta = StubVanta::start(StatusCode::BAD_REQUEST).await;

    let error = vanta
        .client()
        .sync_user_accounts(vec![account("user-a")])
        .await
        .expect_err("sync should fail");

    match error {
        VantaError::Response { status, path, body } => {
            assert_eq!(StatusCode::BAD_REQUEST, status);
            assert_eq!("/v1/resources/user_account", path);
            assert!(body.contains("rejected"), "body was dropped: {body}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
