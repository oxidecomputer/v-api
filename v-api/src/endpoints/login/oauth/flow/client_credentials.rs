// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::{
    ErrorStatusCode, HttpError, HttpResponseHeaders, HttpResponseOk, RequestContext, TypedBody,
};
use http::header::AUTHORIZATION;
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use v_model::{OAuthClientId, permissions::PermissionStorage};

use super::{
    error::{OAuthErrorCode, OAuthErrorResponse},
    requested_scope, token_response,
};
use crate::{
    authn::client_assertion::JWT_BEARER_ASSERTION_TYPE,
    context::{ApiContext, ClientAuthenticationError, VContext},
    permissions::VAppPermission,
    secrets::OpenApiSecretString,
};

/// A client credentials token request (RFC 6749 §4.4.2) where the client authenticates with a
/// JWT assertion (RFC 7523 §2.2)
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClientCredentialsTokenBody {
    pub grant_type: String,
    /// Space delimited scopes that narrow what the token may do. An absent scope means no
    /// permissions. Use "full" for every permission the service account holds.
    pub scope: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
    /// Optional. When present it must name the client that issued the assertion.
    pub client_id: Option<TypedUuid<OAuthClientId>>,
    /// Never accepted. It is only read so that a request carrying it can be refused.
    pub client_secret: Option<OpenApiSecretString>,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct ClientCredentialsTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    /// The scope granted to the access token per RFC 6749 §5.1
    pub scope: String,
}

fn invalid_request(description: &str) -> OAuthErrorResponse {
    OAuthErrorResponse::new(OAuthErrorCode::InvalidRequest, Some(description))
}

fn invalid_client(description: &str) -> OAuthErrorResponse {
    OAuthErrorResponse::new(OAuthErrorCode::InvalidClient, Some(description))
        .with_status(ErrorStatusCode::UNAUTHORIZED)
}

/// The client assertion a token request authenticates with.
///
/// The request must ask for the client credentials grant with a JWT assertion. A client
/// authenticates in exactly one way, so a request that also carries basic credentials, a bearer
/// token, or a client secret is refused rather than authenticated by whichever of them happens to
/// be checked. A caller supplying any of those has misunderstood how assertions work against this
/// API.
fn client_assertion<'a>(
    headers: &http::HeaderMap,
    body: &'a ClientCredentialsTokenBody,
) -> Result<&'a str, OAuthErrorResponse> {
    if body.grant_type != "client_credentials" {
        Err(OAuthErrorResponse::new(
            OAuthErrorCode::UnsupportedGrantType,
            None,
        ))
    } else if body.client_assertion_type.as_deref() != Some(JWT_BEARER_ASSERTION_TYPE) {
        Err(invalid_request(
            "client_assertion_type must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ))
    } else if headers.contains_key(AUTHORIZATION) || body.client_secret.is_some() {
        Err(invalid_request(
            "Clients must authenticate only with a client assertion",
        ))
    } else {
        body.client_assertion
            .as_deref()
            .ok_or_else(|| invalid_request("Missing client_assertion"))
    }
}

#[instrument(skip(rqctx, body), err(Debug))]
pub async fn client_credentials_token_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    body: TypedBody<ClientCredentialsTokenBody>,
) -> Result<HttpResponseHeaders<HttpResponseOk<ClientCredentialsTokenResponse>>, OAuthErrorResponse>
where
    T: VAppPermission + PermissionStorage,
{
    Ok(token_response(
        client_credentials_token_inner(rqctx.v_ctx(), rqctx.request.headers(), body.into_inner())
            .await?,
    ))
}

/// Issues a service account token to a client that authenticates with a signed assertion.
pub async fn client_credentials_token_inner<T>(
    ctx: &VContext<T>,
    headers: &http::HeaderMap,
    body: ClientCredentialsTokenBody,
) -> Result<HttpResponseOk<ClientCredentialsTokenResponse>, OAuthErrorResponse>
where
    T: VAppPermission + PermissionStorage,
{
    let assertion = client_assertion(headers, &body)?;
    let scope = requested_scope::<T>(body.scope.as_deref())?;

    let registration_user = ctx.builtin_registration_user();
    let client = ctx
        .oauth
        .authenticate_client(
            &registration_user,
            assertion,
            body.client_id.as_ref(),
            &ctx.client_assertion_policy(),
        )
        .await
        .map_err(|err| match err {
            ClientAuthenticationError::Storage(err) => {
                tracing::error!(?err, "Failed to authenticate client");
                OAuthErrorResponse::new(OAuthErrorCode::ServerError, None)
            }
            ClientAuthenticationError::Restricted => {
                tracing::error!("Registration user is not allowed to authenticate clients");
                OAuthErrorResponse::new(OAuthErrorCode::ServerError, None)
            }
            ClientAuthenticationError::ClientMismatch => {
                tracing::info!("Refused client assertion for a different client");
                invalid_client("client_id does not match the client that issued the assertion")
            }
            err => {
                tracing::info!(?err, "Refused client assertion");
                invalid_client("Client authentication failed")
            }
        })?;

    let token = ctx
        .generate_service_account_token(
            &registration_user,
            &client.id,
            scope
                .split(' ')
                .filter(|scope| !scope.is_empty())
                .map(|scope| scope.to_string())
                .collect(),
        )
        .await
        .map_err(HttpError::from)?;

    Ok(HttpResponseOk(ClientCredentialsTokenResponse {
        access_token: token.signed_token,
        token_type: "Bearer".to_string(),
        expires_in: token.expires_in,
        scope,
    }))
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use dropshot::HttpResponseError;
    use http::{HeaderMap, HeaderValue, StatusCode, header::AUTHORIZATION};
    use newtype_uuid::TypedUuid;
    use serde_json::json;
    use std::{
        collections::HashSet,
        sync::{Arc, Mutex},
    };
    use v_model::{
        OAuthClient, OAuthClientAssertion, OAuthClientId, OAuthClientKey, ServiceAccount,
        ServiceAccountToken,
        permissions::Principal,
        storage::{
            MockOAuthClientAssertionStore, MockOAuthClientKeyStore, MockOAuthClientStore,
            MockServiceAccountStore, MockServiceAccountTokenStore, StoreError,
        },
    };

    use super::{
        ClientCredentialsTokenBody, JWT_BEARER_ASSERTION_TYPE, OAuthErrorResponse,
        client_credentials_token_inner,
    };
    use crate::{
        VContext,
        authn::{
            AuthToken,
            client_assertion::tests::{TestKey, claims, header},
            client_key::JwkThumbprint,
            jwt::{Jwt, TokenClaims},
        },
        context::test_mocks::{MockStorage, mock_context},
        permissions::VPermission,
        secrets::OpenApiSecretString,
    };

    /// What the token endpoint wrote to storage
    #[derive(Default)]
    struct Recorded {
        assertions: HashSet<String>,
        tokens: Vec<ServiceAccountToken>,
    }

    /// A key pair registered to a client
    struct RegisteredKey {
        client_id: TypedUuid<OAuthClientId>,
        key: TestKey,
        kid: String,
    }

    impl RegisteredKey {
        fn new(client_id: TypedUuid<OAuthClientId>) -> Self {
            let key = TestKey::new();
            let kid = key.public_jwk().thumbprint().unwrap();
            Self {
                client_id,
                key,
                kid,
            }
        }

        fn stored(&self) -> OAuthClientKey {
            OAuthClientKey {
                id: TypedUuid::new_v4(),
                oauth_client_id: self.client_id,
                thumbprint: self.kid.clone(),
                jwk: self.key.public_jwk(),
                created_at: Utc::now(),
                deleted_at: None,
            }
        }

        /// A valid assertion signed with this key that names `issuer` as the client
        fn assertion_for(&self, issuer: TypedUuid<OAuthClientId>) -> String {
            self.key.assertion(issuer, &self.kid)
        }
    }

    struct Fixture {
        ctx: VContext<VPermission>,
        client_id: TypedUuid<OAuthClientId>,
        key: RegisteredKey,
        /// A key registered to a different client that also exists
        other: RegisteredKey,
        /// A key registered to a client that has been deleted
        orphan: RegisteredKey,
        recorded: Arc<Mutex<Recorded>>,
    }

    /// A context holding the client under test and a second live client, each with one
    /// registered key, along with a key left behind by a deleted client. The service account of
    /// every live client holds `CreateGroup` and `GetMappersAll`.
    async fn fixture() -> Fixture {
        let client_id = TypedUuid::new_v4();
        let other_client_id = TypedUuid::new_v4();
        let key = RegisteredKey::new(client_id);
        let other = RegisteredKey::new(other_client_id);
        let orphan = RegisteredKey::new(TypedUuid::new_v4());
        let recorded = Arc::new(Mutex::new(Recorded::default()));

        let stored_keys = vec![key.stored(), other.stored(), orphan.stored()];
        let mut key_store = MockOAuthClientKeyStore::new();
        let listed = stored_keys.clone();
        key_store.expect_list().returning(move |filter, _| {
            let thumbprints = filter.thumbprint.unwrap_or_default();
            Ok(listed
                .iter()
                .filter(|key| thumbprints.contains(&key.thumbprint))
                .cloned()
                .collect())
        });

        // Deleted clients are filtered out by the lookup, so only the live clients are found
        let mut client_store = MockOAuthClientStore::new();
        client_store.expect_get().returning(move |id, deleted| {
            Ok(
                ([client_id, other_client_id].contains(id) && !deleted).then(|| OAuthClient {
                    id: *id,
                    secrets: vec![],
                    redirect_uris: vec![],
                    keys: stored_keys
                        .iter()
                        .filter(|key| &key.oauth_client_id == id)
                        .cloned()
                        .collect(),
                    created_at: Utc::now(),
                    deleted_at: None,
                }),
            )
        });

        let mut assertion_store = MockOAuthClientAssertionStore::new();
        let assertions = recorded.clone();
        assertion_store.expect_record().returning(move |assertion| {
            if assertions
                .lock()
                .unwrap()
                .assertions
                .insert(assertion.jti.clone())
            {
                Ok(OAuthClientAssertion {
                    oauth_client_id: assertion.oauth_client_id,
                    jti: assertion.jti,
                    expires_at: assertion.expires_at,
                    created_at: Utc::now(),
                })
            } else {
                Err(StoreError::Conflict)
            }
        });

        let mut token_store = MockServiceAccountTokenStore::new();
        let created = recorded.clone();
        token_store.expect_create().returning(move |token| {
            let token = ServiceAccountToken {
                id: token.id,
                oauth_client_id: token.oauth_client_id,
                expires_at: token.expires_at,
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            created.lock().unwrap().tokens.push(token.clone());
            Ok(token)
        });
        let known = recorded.clone();
        token_store.expect_get().returning(move |id, _| {
            Ok(known
                .lock()
                .unwrap()
                .tokens
                .iter()
                .find(|token| &token.id == id)
                .cloned())
        });

        let mut account_store = MockServiceAccountStore::new();
        account_store.expect_get().returning(|id| {
            Ok(Some(ServiceAccount {
                id: *id,
                permissions: vec![VPermission::CreateGroup, VPermission::GetMappersAll].into(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                generation: 0,
            }))
        });

        let mut storage = MockStorage::new();
        storage.oauth_client_store = Some(Arc::new(client_store));
        storage.oauth_client_key_store = Some(Arc::new(key_store));
        storage.oauth_client_assertion_store = Some(Arc::new(assertion_store));
        storage.service_account_token_store = Some(Arc::new(token_store));
        storage.service_account_store = Some(Arc::new(account_store));

        Fixture {
            ctx: mock_context(Arc::new(storage)).await,
            client_id,
            key,
            other,
            orphan,
            recorded,
        }
    }

    /// A well formed request from `client_id` carrying `assertion`
    fn request_from(
        client_id: TypedUuid<OAuthClientId>,
        assertion: String,
        scope: Option<&str>,
    ) -> ClientCredentialsTokenBody {
        ClientCredentialsTokenBody {
            grant_type: "client_credentials".to_string(),
            scope: scope.map(|scope| scope.to_string()),
            client_assertion_type: Some(JWT_BEARER_ASSERTION_TYPE.to_string()),
            client_assertion: Some(assertion),
            client_id: Some(client_id),
            client_secret: None,
        }
    }

    fn no_headers() -> HeaderMap {
        HeaderMap::new()
    }

    fn basic_auth() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic Y2xpZW50OnNlY3JldA=="),
        );
        headers
    }

    /// The `error` member of the response body a failed request is answered with
    fn error_code<T>(result: &Result<T, OAuthErrorResponse>) -> String {
        let err = result.as_ref().err().expect("expected the request to fail");
        serde_json::to_value(err).unwrap()["error"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn get_status<T>(result: &Result<T, OAuthErrorResponse>) -> StatusCode {
        match result {
            Ok(_) => StatusCode::OK,
            Err(err) => err.status_code().as_status(),
        }
    }

    impl Fixture {
        fn assertion(&self) -> String {
            self.key.assertion_for(self.client_id)
        }

        /// A well formed request from the client under test carrying `assertion`
        fn request(&self, assertion: String, scope: Option<&str>) -> ClientCredentialsTokenBody {
            request_from(self.client_id, assertion, scope)
        }

        fn recorded_assertions(&self) -> usize {
            self.recorded.lock().unwrap().assertions.len()
        }
    }

    /// A valid assertion is exchanged for a service account token, which then resolves to the
    /// client's service account narrowed by the requested scope
    #[tokio::test]
    async fn issues_a_service_account_token() {
        let fixture = fixture().await;

        let response = client_credentials_token_inner(
            &fixture.ctx,
            &no_headers(),
            fixture.request(fixture.assertion(), Some("group:info:w")),
        )
        .await
        .unwrap()
        .0;
        assert_eq!("Bearer", response.token_type);
        assert_eq!("group:info:w", response.scope);
        assert!(response.expires_in > 0);

        let token: AuthToken = Jwt::<TokenClaims>::new(&fixture.ctx, &response.access_token)
            .await
            .unwrap()
            .into();
        let caller = fixture
            .ctx
            .get_caller_from_token(Some(&token))
            .await
            .unwrap();

        assert_eq!(
            Principal::ServiceAccount(fixture.client_id),
            caller.principal
        );
        assert_eq!(
            v_model::Permissions::from(vec![VPermission::CreateGroup]),
            caller.permissions
        );
        assert_eq!(1, fixture.recorded.lock().unwrap().tokens.len());
    }

    /// An assertion is accepted once
    #[tokio::test]
    async fn refuses_a_replayed_assertion() {
        let fixture = fixture().await;
        let assertion = fixture.assertion();

        let first = client_credentials_token_inner(
            &fixture.ctx,
            &no_headers(),
            fixture.request(assertion.clone(), None),
        )
        .await;
        assert_eq!(StatusCode::OK, get_status(&first));

        let replay = client_credentials_token_inner(
            &fixture.ctx,
            &no_headers(),
            fixture.request(assertion, None),
        )
        .await;
        assert_eq!(StatusCode::UNAUTHORIZED, get_status(&replay));
        assert_eq!("invalid_client", error_code(&replay));
        assert_eq!(1, fixture.recorded.lock().unwrap().tokens.len());
    }

    /// Requests that are malformed are refused before the assertion is verified, so they never
    /// take up its jti
    #[tokio::test]
    async fn refuses_malformed_requests_without_using_the_assertion() {
        let fixture = fixture().await;

        let cases: Vec<(&str, HeaderMap, ClientCredentialsTokenBody)> = vec![
            (
                "unsupported_grant_type",
                no_headers(),
                ClientCredentialsTokenBody {
                    grant_type: "authorization_code".to_string(),
                    ..fixture.request(fixture.assertion(), None)
                },
            ),
            (
                "invalid_request",
                no_headers(),
                ClientCredentialsTokenBody {
                    client_assertion_type: None,
                    ..fixture.request(fixture.assertion(), None)
                },
            ),
            (
                "invalid_request",
                no_headers(),
                ClientCredentialsTokenBody {
                    client_assertion_type: Some(
                        "urn:ietf:params:oauth:client-assertion-type:saml2-bearer".to_string(),
                    ),
                    ..fixture.request(fixture.assertion(), None)
                },
            ),
            (
                "invalid_request",
                no_headers(),
                ClientCredentialsTokenBody {
                    client_assertion: None,
                    ..fixture.request(fixture.assertion(), None)
                },
            ),
            (
                "invalid_request",
                basic_auth(),
                fixture.request(fixture.assertion(), None),
            ),
            (
                "invalid_request",
                no_headers(),
                ClientCredentialsTokenBody {
                    client_secret: Some(OpenApiSecretString("secret".to_string().into())),
                    ..fixture.request(fixture.assertion(), None)
                },
            ),
            (
                "invalid_scope",
                no_headers(),
                fixture.request(fixture.assertion(), Some("not-a-scope")),
            ),
        ];

        for (expected, headers, body) in cases {
            let result = client_credentials_token_inner(&fixture.ctx, &headers, body).await;
            assert_eq!(StatusCode::BAD_REQUEST, get_status(&result), "{expected}");
            assert_eq!(expected, error_code(&result));
        }

        assert_eq!(0, fixture.recorded_assertions());
    }

    /// Assertions that fail authentication are refused as invalid_client, and an assertion that
    /// fails verification never takes up its jti
    #[tokio::test]
    async fn refuses_assertions_that_fail_authentication() {
        let fixture = fixture().await;
        let kid = &fixture.key.kid;

        let requests = [
            // A key left behind by a client that has been deleted
            request_from(
                fixture.orphan.client_id,
                fixture.orphan.assertion_for(fixture.orphan.client_id),
                None,
            ),
            // A kid that no client holds
            fixture.request(
                fixture.key.key.assertion(fixture.client_id, "unknown-kid"),
                None,
            ),
            // Signed by a key that is not registered under the kid
            fixture.request(TestKey::new().assertion(fixture.client_id, kid), None),
            // An audience other than v-api
            fixture.request(
                fixture.key.key.sign(&header(kid), &{
                    let mut claims = claims(fixture.client_id);
                    claims["aud"] = json!("https://elsewhere");
                    claims
                }),
                None,
            ),
        ];

        for body in requests {
            let result = client_credentials_token_inner(&fixture.ctx, &no_headers(), body).await;
            assert_eq!(StatusCode::UNAUTHORIZED, get_status(&result));
            assert_eq!("invalid_client", error_code(&result));
        }

        assert_eq!(0, fixture.recorded_assertions());
        assert!(fixture.recorded.lock().unwrap().tokens.is_empty());
    }

    /// A client_id in the request is optional, as RFC 7521 §4.2 allows when the client
    /// authenticates with an assertion. When it is present it must name the client that issued
    /// the assertion, and a request naming another client is refused without issuing a token.
    #[tokio::test]
    async fn a_client_id_must_match_the_assertion_when_present() {
        let fixture = fixture().await;
        let assertion = fixture.assertion();

        let mismatched = client_credentials_token_inner(
            &fixture.ctx,
            &no_headers(),
            ClientCredentialsTokenBody {
                client_id: Some(TypedUuid::new_v4()),
                ..fixture.request(assertion.clone(), None)
            },
        )
        .await;
        assert_eq!(StatusCode::UNAUTHORIZED, get_status(&mismatched));
        assert_eq!("invalid_client", error_code(&mismatched));
        assert!(fixture.recorded.lock().unwrap().tokens.is_empty());
        assert_eq!(
            0,
            fixture.recorded_assertions(),
            "a refused request must not consume the assertion"
        );

        // The same assertion is still usable once the request names the right client
        let corrected = client_credentials_token_inner(
            &fixture.ctx,
            &no_headers(),
            ClientCredentialsTokenBody {
                client_id: Some(fixture.client_id),
                ..fixture.request(assertion, None)
            },
        )
        .await;
        assert_eq!(StatusCode::OK, get_status(&corrected));

        let without_client_id = client_credentials_token_inner(
            &fixture.ctx,
            &no_headers(),
            ClientCredentialsTokenBody {
                client_id: None,
                ..fixture.request(fixture.assertion(), None)
            },
        )
        .await;
        assert_eq!(StatusCode::OK, get_status(&without_client_id));
        assert_eq!(2, fixture.recorded.lock().unwrap().tokens.len());
    }

    /// A client can never act as another client. An assertion signed with one client's key that
    /// names a different client is refused even though its signature is valid, whichever client
    /// the request claims to come from.
    #[tokio::test]
    async fn refuses_an_assertion_signed_by_another_clients_key() {
        let fixture = fixture().await;
        let impersonation = fixture.other.assertion_for(fixture.client_id);

        for client_id in [fixture.client_id, fixture.other.client_id] {
            let result = client_credentials_token_inner(
                &fixture.ctx,
                &no_headers(),
                request_from(client_id, impersonation.clone(), Some("full")),
            )
            .await;
            assert_eq!(
                StatusCode::UNAUTHORIZED,
                get_status(&result),
                "{client_id:?}"
            );
            assert_eq!("invalid_client", error_code(&result));
        }

        assert_eq!(0, fixture.recorded_assertions());
        assert!(fixture.recorded.lock().unwrap().tokens.is_empty());
    }
}
