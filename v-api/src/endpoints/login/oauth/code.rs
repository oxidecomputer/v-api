// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use chrono::{TimeDelta, Utc};
use dropshot::{
    http_response_temporary_redirect, Body, ClientErrorStatusCode, HttpError, HttpResponseOk,
    HttpResponseTemporaryRedirect, Path, Query, RequestContext, RequestInfo, SharedExtractor,
    TypedBody,
};
use dropshot_authorization_header::basic::BasicAuth;
use http::{
    header::{LOCATION, SET_COOKIE},
    HeaderValue, StatusCode,
};
use hyper::Response;
use newtype_uuid::TypedUuid;
use oauth2::{
    AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope, TokenResponse,
};
use schemars::JsonSchema;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt::Debug, ops::Add};
use tap::TapFallible;
use tracing::instrument;
use v_model::{
    permissions::{AsScope, PermissionStorage},
    schema_ext::LoginAttemptState,
    LoginAttempt, LoginAttemptId, NewLoginAttempt, OAuthClient, OAuthClientId,
};

use super::{OAuthProvider, OAuthProviderNameParam, UserInfoProvider, WebClientConfig};
use crate::{
    authn::key::RawKey,
    context::{ApiContext, VContext},
    endpoints::login::{
        oauth::{CheckOAuthClient, ClientType},
        LoginError, UserInfo,
    },
    error::ApiError,
    permissions::{VAppPermission, VPermission},
    secrets::OpenApiSecretString,
    util::{
        request::RequestCookies,
        response::{internal_error, to_internal_error, unauthorized, ResourceError},
    },
};

static LOGIN_ATTEMPT_COOKIE: &str = "__v_login";
static DEFAULT_SCOPE: &str = "user:info:r";

#[derive(Debug, Deserialize, JsonSchema, Serialize, PartialEq, Eq)]
struct OAuthError {
    error: OAuthErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize, PartialEq, Eq)]
#[serde(untagged)]
enum OAuthErrorCode {
    AccessDenied,
    InvalidClient,
    InvalidGrant,
    InvalidRequest,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum OAuthTokenErrorCode {}

impl From<OAuthError> for HttpError {
    fn from(value: OAuthError) -> Self {
        let serialized = serde_json::to_string(&value).unwrap();
        HttpError {
            headers: None,
            status_code: ClientErrorStatusCode::BAD_REQUEST.into(),
            error_code: None,
            external_message: serialized.clone(),
            internal_message: serialized,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct OAuthAuthzCodeQuery {
    pub client_id: TypedUuid<OAuthClientId>,
    pub redirect_uri: String,
    pub response_type: String,
    pub state: String,
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct OAuthAuthzCodeRedirectHeaders {
    #[serde(rename = "set-cookies")]
    cookies: String,
    location: String,
}

// Lookup the client specified by the provided client id and verify that the redirect uri
// is a valid for this client. If either of these fail we return an unauthorized response
async fn get_oauth_client<T>(
    ctx: &VContext<T>,
    client_id: &TypedUuid<OAuthClientId>,
    redirect_uri: &str,
) -> Result<OAuthClient, OAuthError>
where
    T: VAppPermission + PermissionStorage,
{
    let client = ctx
        .oauth
        .get_oauth_client(&ctx.builtin_registration_user(), client_id)
        .await
        .map_err(|err| {
            tracing::error!(?err, "Failed to lookup OAuth client");

            match err {
                ResourceError::DoesNotExist => OAuthError {
                    error: OAuthErrorCode::InvalidClient,
                    error_description: Some("Unknown client id".to_string()),
                    error_uri: None,
                    state: None,
                },
                // Given that the builtin caller should have access to all OAuth clients, any other
                // error is considered an internal error
                _ => OAuthError {
                    error: OAuthErrorCode::ServerError,
                    error_description: None,
                    error_uri: None,
                    state: None,
                },
            }
        })?;

    if client.is_redirect_uri_valid(&redirect_uri) {
        Ok(client)
    } else {
        Err(OAuthError {
            error: OAuthErrorCode::InvalidRequest,
            error_description: Some("Invalid redirect uri".to_string()),
            error_uri: None,
            state: None,
        })
    }
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn authz_code_redirect_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<OAuthProviderNameParam>,
    query: Query<OAuthAuthzCodeQuery>,
) -> Result<Response<Body>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let ctx = rqctx.v_ctx();
    let path = path.into_inner();
    let query = query.into_inner();

    get_oauth_client(ctx, &query.client_id, &query.redirect_uri).await?;

    tracing::debug!(?query.client_id, ?query.redirect_uri, "Verified client id and redirect uri");

    // Find the configured provider for the requested remote backend. We should always have a valid
    // provider value, so if this fails then a 500 is returned
    let provider = ctx
        .get_oauth_provider(&path.provider)
        .await
        .map_err(ApiError::OAuth)?;

    tracing::debug!(provider = ?provider.name(), "Acquired OAuth provider for authz code login");

    // Check that the passed in scopes are valid. The scopes are not currently restricted by client
    let scope = query.scope.unwrap_or_else(|| DEFAULT_SCOPE.to_string());
    let scope_error = VPermission::from_scope_arg(&scope)
        .err()
        .map(|_| "invalid_scope".to_string());

    // Construct a new login attempt with the minimum required values
    let mut attempt = NewLoginAttempt::new(
        provider.name().to_string(),
        query.client_id,
        query.redirect_uri,
        scope,
    )
    .map_err(|err| {
        tracing::error!(?err, "Attempted to construct invalid login attempt");
        internal_error("Attempted to construct invalid login attempt".to_string())
    })?;

    // Set a default expiration for the login attempt
    // TODO: Make this configurable
    attempt.expires_at = Some(Utc::now().add(TimeDelta::try_minutes(5).unwrap()));

    // Assign any scope errors that arose
    attempt.error = scope_error;

    // Add in the user defined state and redirect uri
    attempt.state = Some(query.state);

    // If the remote provider supports pkce, set up a challenge
    let pkce_challenge = if provider.supports_pkce() {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        attempt.provider_pkce_verifier = Some(pkce_verifier.secret().to_string());
        Some(pkce_challenge)
    } else {
        None
    };

    // Store the generated attempt
    let attempt = ctx
        .login
        .create_login_attempt(attempt)
        .await
        .map_err(to_internal_error)?;

    tracing::info!(?attempt.id, "Created login attempt");

    Ok(oauth_redirect_response(
        ctx.public_url(),
        &*provider,
        &attempt,
        pkce_challenge,
    )?)
}

fn oauth_redirect_response(
    public_url: &str,
    provider: &dyn OAuthProvider,
    attempt: &LoginAttempt,
    code_challenge: Option<PkceCodeChallenge>,
) -> Result<Response<Body>, HttpError> {
    // We may fail if the provider configuration is not correctly configured
    // TODO: This behavior should be changed so that clients are precomputed. We do not need to be
    // constructing a new client on every request. That said, we need to ensure the client does not
    // maintain state between requests
    let client = provider
        .as_web_client(&WebClientConfig {
            prefix: public_url.to_string(),
        })
        .map_err(to_internal_error)?;

    // Create an attempt cookie header for storing the login attempt. This also acts as our csrf
    // check
    let login_cookie = HeaderValue::from_str(&format!("{}={}", LOGIN_ATTEMPT_COOKIE, attempt.id))
        .map_err(to_internal_error)?;

    // Generate the url to the remote provider that the user will be redirected to
    let mut authz_url = client
        .authorize_url(|| CsrfToken::new(attempt.id.to_string()))
        .add_scopes(
            provider
                .scopes()
                .into_iter()
                .map(|s| Scope::new(s.to_string()))
                .collect::<Vec<_>>(),
        );

    // If the caller has provided a code challenge, add it to the url
    if let Some(challenge) = code_challenge {
        authz_url = authz_url.set_pkce_challenge(challenge);
    };

    Ok(Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(SET_COOKIE, login_cookie)
        .header(
            LOCATION,
            HeaderValue::from_str(authz_url.url().0.as_str()).map_err(to_internal_error)?,
        )
        .body(Body::empty())?)
}

// TODO: Determine if 401 empty responses are correct here
fn verify_csrf(
    request: &RequestInfo,
    query: &OAuthAuthzCodeReturnQuery,
) -> Result<TypedUuid<LoginAttemptId>, HttpError> {
    // If we are missing the expected state parameter then we can not proceed at all with verifying
    // this callback request. We also do not have a redirect uri to send the user to so we instead
    // report unauthorized
    let attempt_id = query
        .state
        .as_ref()
        .ok_or_else(|| {
            tracing::warn!("OAuth callback is missing a state parameter");
            unauthorized()
        })?
        .parse()
        .map_err(|err| {
            tracing::warn!(?err, "Failed to parse state");
            unauthorized()
        })?;

    // The client must present the attempt cookie at a minimum. Without it we are unable to lookup a
    // login attempt to match against. Without the cookie to verify the state parameter we can not
    // determine a redirect uri so we instead report unauthorized
    let attempt_cookie = request
        .cookie(LOGIN_ATTEMPT_COOKIE)
        .ok_or_else(|| {
            tracing::warn!("OAuth callback is missing a login state cookie");
            unauthorized()
        })?
        .value()
        .parse()
        .map_err(|err| {
            tracing::warn!(?err, "Failed to parse state");
            unauthorized()
        })?;

    // Verify that the attempt_id returned from the state matches the expected client value. If they
    // do not match we can not lookup a redirect uri so we instead return unauthorized
    if attempt_id != attempt_cookie {
        tracing::warn!(
            ?attempt_id,
            ?attempt_cookie,
            "OAuth state does not match expected cookie value"
        );
        Err(unauthorized())
    } else {
        Ok(attempt_id)
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct OAuthAuthzCodeReturnQuery {
    pub state: Option<String>,
    pub code: Option<String>,
    pub error: Option<String>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn authz_code_callback_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<OAuthProviderNameParam>,
    query: Query<OAuthAuthzCodeReturnQuery>,
) -> Result<HttpResponseTemporaryRedirect, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let ctx = rqctx.v_ctx();
    let path = path.into_inner();
    let query = query.into_inner();
    let provider = ctx
        .get_oauth_provider(&path.provider)
        .await
        .map_err(ApiError::OAuth)?;

    tracing::debug!(provider = ?provider.name(), "Acquired OAuth provider for authz code exchange");

    // Verify and extract the attempt id before performing any work
    let attempt_id = verify_csrf(&rqctx.request, &query)?;

    http_response_temporary_redirect(
        authz_code_callback_op_inner(&ctx, &attempt_id, query.code, query.error).await?,
    )
}

pub async fn authz_code_callback_op_inner<T>(
    ctx: &VContext<T>,
    attempt_id: &TypedUuid<LoginAttemptId>,
    code: Option<String>,
    error: Option<String>,
) -> Result<String, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    // We have now verified the attempt id and can use it to look up the rest of the login attempt
    // material to try and complete the flow
    let mut attempt = ctx
        .login
        .get_login_attempt(&attempt_id)
        .await
        .map_err(to_internal_error)?
        .ok_or_else(|| {
            // If we fail to find a matching attempt, there is not much we can do other than return
            // unauthorized
            unauthorized()
        })
        .and_then(|attempt| {
            if attempt.attempt_state == LoginAttemptState::New {
                Ok(attempt)
            } else {
                Err(unauthorized())
            }
        })?;

    attempt = match (code, error) {
        (Some(code), None) => {
            tracing::info!(?attempt.id, "Received valid login attempt. Storing authorization code");

            // Store the authorization code returned by the underlying OAuth provider and transition the
            // attempt to the awaiting state
            ctx.login
                .set_login_provider_authz_code(attempt, code.to_string())
                .await
                .map_err(to_internal_error)?
        }
        (code, error) => {
            tracing::info!(?attempt.id, ?error, "Received an error response from the remote server");

            // Store the provider return error for future debugging, but if an error has been
            // returned or there is a missing code, then we can not report a successful process
            attempt.provider_authz_code = code;

            // When a user has explicitly denied access we want to forward that error message
            // onwards to the upstream requester. All other errors should be opaque to the
            // original requester and are returned as server errors
            let error_message = match error.as_deref() {
                Some("access_denied") => "access_denied",
                _ => "server_error",
            };

            // TODO: Specialize the returned error
            ctx.login
                .fail_login_attempt(attempt, Some(error_message), error.as_deref())
                .await
                .map_err(to_internal_error)?
        }
    };

    // Redirect back to the original authenticator
    Ok(attempt.callback_url())
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OAuthAuthzCodeExchangeBody {
    pub client_id: Option<TypedUuid<OAuthClientId>>,
    pub client_secret: Option<OpenApiSecretString>,
    pub redirect_uri: String,
    pub grant_type: String,
    pub code: String,
    pub pkce_verifier: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct OAuthAuthzCodeExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn authz_code_exchange_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<OAuthProviderNameParam>,
    body: TypedBody<OAuthAuthzCodeExchangeBody>,
) -> Result<HttpResponseOk<OAuthAuthzCodeExchangeResponse>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let ctx = rqctx.v_ctx();
    let path = path.into_inner();
    let body = body.into_inner();

    let (client_id, client_secret) =
        if let (Some(client_id), Some(client_secret)) = (body.client_id, body.client_secret) {
            Ok::<_, HttpError>((client_id, client_secret))
        } else {
            // Attempt to extract basic authorization credentials from the request if they were not
            // present in the request body
            let auth = <BasicAuth as SharedExtractor>::from_request(rqctx)
                .await
                .tap_err(|err| {
                    tracing::warn!(?err, "Failed to extract basic authentication values");
                });
            let (client_id, client_secret) = match auth {
                Ok(auth) if auth.username().is_some() && auth.password().is_some() => Ok((
                    auth.username().unwrap().to_string(),
                    auth.password().unwrap().to_string(),
                )),
                _ => Err(internal_error(
                    "Missing client id and client secret from authz code exchange",
                )),
            }?;

            Ok((
                client_id.parse().map_err(to_internal_error)?,
                OpenApiSecretString(client_secret.into()),
            ))
        }?;

    let provider = ctx
        .get_oauth_provider(&path.provider)
        .await
        .map_err(ApiError::OAuth)?;

    tracing::debug!("Attempting code exchange");

    // Verify the submitted client credentials
    authorize_code_exchange(
        &ctx,
        &body.grant_type,
        client_id,
        &client_secret.0,
        &body.redirect_uri,
    )
    .await?;

    tracing::debug!("Authorized code exchange");

    // Lookup the request assigned to this code
    let attempt = ctx
        .login
        .get_login_attempt_for_code(&body.code)
        .await
        .map_err(to_internal_error)?
        .ok_or_else(|| OAuthError {
            error: OAuthErrorCode::InvalidGrant,
            error_description: None,
            error_uri: None,
            state: None,
        })?;

    // Verify that the login attempt is valid and matches the submitted client credentials
    verify_login_attempt(
        &attempt,
        client_id,
        &body.redirect_uri,
        body.pkce_verifier.as_deref(),
    )?;

    tracing::debug!("Verified login attempt");

    // Now that the attempt has been confirmed, use it to fetch user information form the remote
    // provider
    let info = fetch_user_info(ctx.public_url(), &ctx.web_client(), &*provider, &attempt).await?;

    tracing::debug!("Retrieved user information from remote provider");

    // Register this user as an API user if needed
    let (api_user_info, api_user_provider) = ctx
        .register_api_user(&ctx.builtin_registration_user(), info)
        .await?;

    tracing::info!(api_user_id = ?api_user_info.user.id, "Retrieved api user to generate access token for");

    let scope = attempt
        .scope
        .split(' ')
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    let token = ctx
        .generate_access_token(
            &ctx.builtin_registration_user(),
            &api_user_info.user.id,
            &api_user_provider.id,
            Some(scope),
        )
        .await?;

    Ok(HttpResponseOk(OAuthAuthzCodeExchangeResponse {
        token_type: "Bearer".to_string(),
        access_token: token.signed_token,
        expires_in: token.expires_in,
    }))
}

async fn authorize_code_exchange<T>(
    ctx: &VContext<T>,
    grant_type: &str,
    client_id: TypedUuid<OAuthClientId>,
    client_secret: &SecretString,
    redirect_uri: &str,
) -> Result<(), OAuthError>
where
    T: VAppPermission + PermissionStorage,
{
    let client = get_oauth_client(ctx, &client_id, &redirect_uri).await?;

    // Verify that we received the expected grant type
    if grant_type != "authorization_code" {
        return Err(OAuthError {
            error: OAuthErrorCode::UnsupportedGrantType,
            error_description: None,
            error_uri: None,
            state: None,
        });
    }

    tracing::debug!(grant_type, "Verified grant type");

    let client_secret = RawKey::try_from(client_secret).map_err(|err| {
        tracing::warn!(?err, "Failed to parse OAuth client secret");

        OAuthError {
            error: OAuthErrorCode::InvalidRequest,
            error_description: Some("Malformed client secret".to_string()),
            error_uri: None,
            state: None,
        }
    })?;

    tracing::debug!("Constructed client secret");

    if !client.is_secret_valid(&client_secret, ctx) {
        Err(OAuthError {
            error: OAuthErrorCode::InvalidClient,
            error_description: Some("Invalid client secret".to_string()),
            error_uri: None,
            state: None,
        })
    } else {
        tracing::debug!("Verified client secret validity");

        Ok(())
    }
}

fn verify_login_attempt(
    attempt: &LoginAttempt,
    client_id: TypedUuid<OAuthClientId>,
    redirect_uri: &str,
    pkce_verifier: Option<&str>,
) -> Result<(), OAuthError> {
    if attempt.client_id != client_id {
        Err(OAuthError {
            error: OAuthErrorCode::InvalidGrant,
            error_description: Some("Invalid client id".to_string()),
            error_uri: None,
            state: None,
        })
    } else if attempt.redirect_uri != redirect_uri {
        Err(OAuthError {
            error: OAuthErrorCode::InvalidGrant,
            error_description: Some("Invalid redirect uri".to_string()),
            error_uri: None,
            state: None,
        })
    } else if attempt.attempt_state != LoginAttemptState::RemoteAuthenticated {
        Err(OAuthError {
            error: OAuthErrorCode::InvalidGrant,
            error_description: Some("Grant is in an invalid state".to_string()),
            error_uri: None,
            state: None,
        })
    } else if attempt.expires_at.map(|t| t <= Utc::now()).unwrap_or(true) {
        Err(OAuthError {
            error: OAuthErrorCode::InvalidGrant,
            error_description: Some("Grant has expired".to_string()),
            error_uri: None,
            state: None,
        })
    } else {
        match (attempt.pkce_challenge.as_deref(), pkce_verifier) {
            (Some(_), None) => Err(OAuthError {
                error: OAuthErrorCode::InvalidRequest,
                error_description: Some("Missing pkce verifier".to_string()),
                error_uri: None,
                state: None,
            }),
            (Some(challenge), Some(verifier)) => {
                let mut hasher = Sha256::new();
                hasher.update(verifier);
                let hash = hasher.finalize();
                let computed_challenge = BASE64_URL_SAFE_NO_PAD.encode(hash);

                if challenge == computed_challenge {
                    Ok(())
                } else {
                    Err(OAuthError {
                        error: OAuthErrorCode::InvalidGrant,
                        error_description: Some("Invalid pkce verifier".to_string()),
                        error_uri: None,
                        state: None,
                    })
                }
            }
            (None, _) => Ok(()),
        }
    }
}

#[instrument(skip(attempt))]
async fn fetch_user_info(
    public_url: &str,
    client_type: &ClientType,
    provider: &dyn OAuthProvider,
    attempt: &LoginAttempt,
) -> Result<UserInfo, HttpError> {
    // Exchange the stored authorization code with the remote provider for a remote access token
    let client = provider
        .as_web_client(&WebClientConfig {
            prefix: public_url.to_string(),
        })
        .map_err(to_internal_error)?;

    let mut request = client.exchange_code(AuthorizationCode::new(
        attempt
            .provider_authz_code
            .as_ref()
            .ok_or_else(|| {
                internal_error("Expected authorization code to exist due to attempt state")
            })?
            .to_string(),
    ));

    if let Some(pkce_verifier) = &attempt.provider_pkce_verifier {
        request = request.set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_string()))
    }

    let response = request
        .request_async(provider.client())
        .await
        .map_err(to_internal_error)?;

    tracing::info!("Fetched access token from remote service");

    // Use the retrieved access token to fetch the user information from the remote API
    let info = provider
        .get_user_info(response.access_token().secret())
        .await
        .map_err(LoginError::UserInfo)
        .tap_err(|err| tracing::error!(?err, "Failed to look up user information"))?;

    tracing::info!("Fetched user info from remote service");

    // Now that we are done with fetching user information from the remote API, we can revoke it if
    // the provider supports it
    if provider.token_revocation_endpoint().is_some() {
        client
            .revoke_token(response.access_token().into())
            .map_err(internal_error)?
            .request_async(provider.client())
            .await
            .map_err(internal_error)?;
    }

    Ok(info)
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        ops::Add,
        sync::{Arc, Mutex},
    };

    use chrono::{TimeDelta, Utc};
    use dropshot::RequestInfo;
    use http::{
        header::{COOKIE, LOCATION, SET_COOKIE},
        HeaderValue, StatusCode,
    };
    use http_body_util::Empty;
    use mockall::predicate::eq;
    use newtype_uuid::TypedUuid;
    use oauth2::PkceCodeChallenge;
    use secrecy::SecretString;
    use uuid::Uuid;
    use v_model::{
        schema_ext::LoginAttemptState,
        storage::{MockLoginAttemptStore, MockOAuthClientStore},
        LoginAttempt, OAuthClient, OAuthClientRedirectUri, OAuthClientSecret,
    };

    use crate::{
        authn::key::RawKey,
        context::{
            test_mocks::{mock_context, MockStorage},
            VContext,
        },
        endpoints::login::oauth::{
            code::{
                authz_code_callback_op_inner, verify_csrf, verify_login_attempt,
                OAuthAuthzCodeReturnQuery, OAuthError, OAuthErrorCode, LOGIN_ATTEMPT_COOKIE,
            },
            OAuthProviderName,
        },
        permissions::VPermission,
    };

    use super::{authorize_code_exchange, get_oauth_client, oauth_redirect_response};

    async fn mock_client() -> (VContext<VPermission>, OAuthClient, SecretString) {
        let ctx = mock_context(Arc::new(MockStorage::new())).await;
        let client_id = TypedUuid::new_v4();
        let key = RawKey::generate::<8>(&Uuid::new_v4())
            .sign(&*ctx.signer())
            .await
            .unwrap();
        let secret_signature = key.signature().to_string();
        let client_secret = key.key();
        let redirect_uri = "callback-destination";

        (
            ctx,
            OAuthClient {
                id: client_id,
                secrets: vec![OAuthClientSecret {
                    id: TypedUuid::new_v4(),
                    oauth_client_id: client_id,
                    secret_signature,
                    created_at: Utc::now(),
                    deleted_at: None,
                }],
                redirect_uris: vec![OAuthClientRedirectUri {
                    id: TypedUuid::new_v4(),
                    oauth_client_id: client_id,
                    redirect_uri: redirect_uri.to_string(),
                    created_at: Utc::now(),
                    deleted_at: None,
                }],
                created_at: Utc::now(),
                deleted_at: None,
            },
            client_secret,
        )
    }

    #[tokio::test]
    async fn test_oauth_client_lookup_checks_redirect_uri() {
        let client_id = TypedUuid::new_v4();
        let client = OAuthClient {
            id: client_id,
            secrets: vec![],
            redirect_uris: vec![OAuthClientRedirectUri {
                id: TypedUuid::new_v4(),
                oauth_client_id: client_id,
                redirect_uri: "https://test.oxeng.dev/callback".to_string(),
                created_at: Utc::now(),
                deleted_at: None,
            }],
            created_at: Utc::now(),
            deleted_at: None,
        };

        let mut client_store = MockOAuthClientStore::new();
        client_store
            .expect_get()
            .with(eq(client_id), eq(false))
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut storage = MockStorage::new();
        storage.oauth_client_store = Some(Arc::new(client_store));
        let ctx = mock_context(Arc::new(storage)).await;

        let failure = get_oauth_client(&ctx, &client_id, "https://not-test.oxeng.dev/callback")
            .await
            .unwrap_err();
        assert_eq!(OAuthErrorCode::InvalidRequest, failure.error);
        assert_eq!(
            Some("Invalid redirect uri".to_string()),
            failure.error_description
        );

        let success = get_oauth_client(&ctx, &client_id, "https://test.oxeng.dev/callback").await;
        assert_eq!(client_id, success.unwrap().id);
    }

    #[tokio::test]
    async fn test_remote_provider_redirect_url() {
        let storage = MockStorage::new();
        let mut ctx = mock_context(Arc::new(storage)).await;
        ctx.with_public_url("https://api.oxeng.dev");

        let (challenge, _) = PkceCodeChallenge::new_random_sha256();
        let attempt = LoginAttempt {
            id: TypedUuid::new_v4(),
            attempt_state: LoginAttemptState::New,
            client_id: TypedUuid::new_v4(),
            redirect_uri: "https://test.oxeng.dev/callback".to_string(),
            state: Some("ox_state".to_string()),
            pkce_challenge: Some("ox_challenge".to_string()),
            pkce_challenge_method: Some("S256".to_string()),
            authz_code: None,
            expires_at: None,
            error: None,
            provider: "google".to_string(),
            provider_pkce_verifier: Some("v_verifier".to_string()),
            provider_authz_code: None,
            provider_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            scope: String::new(),
        };

        let response = oauth_redirect_response(
            &ctx.public_url(),
            &*ctx
                .get_oauth_provider(&OAuthProviderName::Google)
                .await
                .unwrap(),
            &attempt,
            Some(challenge.clone()),
        )
        .unwrap();

        let expected_location = format!("https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=google_web_client_id&state={}&code_challenge={}&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fapi.oxeng.dev%2Flogin%2Foauth%2Fgoogle%2Fcode%2Fcallback&scope=openid+email+profile", attempt.id, challenge.as_str());

        assert_eq!(
            expected_location,
            String::from_utf8(
                response
                    .headers()
                    .get(LOCATION)
                    .unwrap()
                    .as_bytes()
                    .to_vec()
            )
            .unwrap()
        );
        assert_eq!(
            attempt.id.to_string().as_str(),
            String::from_utf8(
                response
                    .headers()
                    .get(SET_COOKIE)
                    .unwrap()
                    .as_bytes()
                    .to_vec()
            )
            .unwrap()
            .split_once('=')
            .unwrap()
            .1
        )
    }

    #[tokio::test]
    async fn test_csrf_check() {
        let id = TypedUuid::new_v4();

        let mut rq = hyper::Request::new(Empty::<()>::new());
        rq.headers_mut().insert(
            COOKIE,
            HeaderValue::from_str(&format!("{}={}", LOGIN_ATTEMPT_COOKIE, id)).unwrap(),
        );
        let with_valid_cookie = RequestInfo::new(
            &rq,
            std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8888)),
        );
        let query = OAuthAuthzCodeReturnQuery {
            state: Some(id.to_string()),
            code: None,
            error: None,
        };
        assert_eq!(id, verify_csrf(&with_valid_cookie, &query).unwrap());

        let query = OAuthAuthzCodeReturnQuery {
            state: None,
            code: None,
            error: None,
        };
        assert_eq!(
            StatusCode::UNAUTHORIZED,
            verify_csrf(&with_valid_cookie, &query)
                .unwrap_err()
                .status_code
        );

        let mut rq = hyper::Request::new(Empty::<()>::new());
        rq.headers_mut().insert(
            COOKIE,
            HeaderValue::from_str(&format!("{}={}", LOGIN_ATTEMPT_COOKIE, Uuid::new_v4())).unwrap(),
        );
        let with_invalid_cookie = RequestInfo::new(
            &rq,
            std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8888)),
        );
        let query = OAuthAuthzCodeReturnQuery {
            state: Some(id.to_string()),
            code: None,
            error: None,
        };
        assert_eq!(
            StatusCode::UNAUTHORIZED,
            verify_csrf(&with_invalid_cookie, &query)
                .unwrap_err()
                .status_code
        );

        let rq = hyper::Request::new(Empty::<()>::new());
        let with_missing_cookie = RequestInfo::new(
            &rq,
            std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 8888)),
        );
        let query = OAuthAuthzCodeReturnQuery {
            state: Some(id.to_string()),
            code: None,
            error: None,
        };
        assert_eq!(
            StatusCode::UNAUTHORIZED,
            verify_csrf(&with_missing_cookie, &query)
                .unwrap_err()
                .status_code
        );
    }

    #[tokio::test]
    async fn test_callback_fails_when_not_in_new_state() {
        let invalid_states = [
            LoginAttemptState::Complete,
            LoginAttemptState::Failed,
            LoginAttemptState::RemoteAuthenticated,
        ];

        for state in invalid_states {
            let attempt_id = TypedUuid::new_v4();
            let attempt = LoginAttempt {
                id: attempt_id,
                attempt_state: state,
                client_id: TypedUuid::new_v4(),
                redirect_uri: "https://test.oxeng.dev/callback".to_string(),
                state: Some("ox_state".to_string()),
                pkce_challenge: Some("ox_challenge".to_string()),
                pkce_challenge_method: Some("S256".to_string()),
                authz_code: None,
                expires_at: None,
                error: None,
                provider: "google".to_string(),
                provider_pkce_verifier: Some("v_verifier".to_string()),
                provider_authz_code: None,
                provider_error: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                scope: String::new(),
            };

            let mut storage = MockStorage::new();
            let mut attempt_store = MockLoginAttemptStore::new();
            attempt_store
                .expect_get()
                .with(eq(attempt.id))
                .returning(move |_| Ok(Some(attempt.clone())));
            storage.login_attempt_store = Some(Arc::new(attempt_store));

            let ctx = mock_context(Arc::new(storage)).await;
            let err = authz_code_callback_op_inner(
                &ctx,
                &attempt_id,
                Some("remote-code".to_string()),
                None,
            )
            .await;

            assert_eq!(StatusCode::UNAUTHORIZED, err.unwrap_err().status_code);
        }
    }

    #[tokio::test]
    async fn test_callback_fails_when_error_is_passed() {
        let attempt_id = TypedUuid::new_v4();
        let attempt = LoginAttempt {
            id: attempt_id,
            attempt_state: LoginAttemptState::New,
            client_id: TypedUuid::new_v4(),
            redirect_uri: "https://test.oxeng.dev/callback".to_string(),
            state: Some("ox_state".to_string()),
            pkce_challenge: Some("ox_challenge".to_string()),
            pkce_challenge_method: Some("S256".to_string()),
            authz_code: None,
            expires_at: None,
            error: None,
            provider: "google".to_string(),
            provider_pkce_verifier: Some("v_verifier".to_string()),
            provider_authz_code: None,
            provider_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            scope: String::new(),
        };

        let mut attempt_store = MockLoginAttemptStore::new();
        let original_attempt = attempt.clone();
        attempt_store
            .expect_get()
            .with(eq(attempt.id))
            .returning(move |_| Ok(Some(original_attempt.clone())));

        attempt_store
            .expect_upsert()
            .withf(|attempt| attempt.attempt_state == LoginAttemptState::Failed)
            .returning(move |arg| {
                let mut returned = attempt.clone();
                returned.attempt_state = arg.attempt_state;
                returned.authz_code = arg.authz_code;
                returned.error = arg.error;
                Ok(returned)
            });

        let mut storage = MockStorage::new();
        storage.login_attempt_store = Some(Arc::new(attempt_store));
        let ctx = mock_context(Arc::new(storage)).await;

        let location = authz_code_callback_op_inner(
            &ctx,
            &attempt_id,
            Some("remote-code".to_string()),
            Some("not_access_denied".to_string()),
        )
        .await
        .unwrap();

        assert_eq!(
            format!("https://test.oxeng.dev/callback?error=server_error&state=ox_state",),
            location
        );
    }

    #[tokio::test]
    async fn test_callback_forwards_access_denied() {
        let attempt_id = TypedUuid::new_v4();
        let attempt = LoginAttempt {
            id: attempt_id,
            attempt_state: LoginAttemptState::New,
            client_id: TypedUuid::new_v4(),
            redirect_uri: "https://test.oxeng.dev/callback".to_string(),
            state: Some("ox_state".to_string()),
            pkce_challenge: Some("ox_challenge".to_string()),
            pkce_challenge_method: Some("S256".to_string()),
            authz_code: None,
            expires_at: None,
            error: None,
            provider: "google".to_string(),
            provider_pkce_verifier: Some("v_verifier".to_string()),
            provider_authz_code: None,
            provider_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            scope: String::new(),
        };

        let mut attempt_store = MockLoginAttemptStore::new();
        let original_attempt = attempt.clone();
        attempt_store
            .expect_get()
            .with(eq(attempt.id))
            .returning(move |_| Ok(Some(original_attempt.clone())));

        attempt_store
            .expect_upsert()
            .withf(|attempt| attempt.attempt_state == LoginAttemptState::Failed)
            .returning(move |arg| {
                let mut returned = attempt.clone();
                returned.attempt_state = arg.attempt_state;
                returned.authz_code = arg.authz_code;
                returned.error = arg.error;
                Ok(returned)
            });

        let mut storage = MockStorage::new();
        storage.login_attempt_store = Some(Arc::new(attempt_store));
        let ctx = mock_context(Arc::new(storage)).await;

        let location = authz_code_callback_op_inner(
            &ctx,
            &attempt_id,
            Some("remote-code".to_string()),
            Some("access_denied".to_string()),
        )
        .await
        .unwrap();

        assert_eq!(
            format!("https://test.oxeng.dev/callback?error=access_denied&state=ox_state",),
            location
        );
    }

    #[tokio::test]
    async fn test_handles_callback_with_code() {
        let attempt_id = TypedUuid::new_v4();
        let attempt = LoginAttempt {
            id: attempt_id,
            attempt_state: LoginAttemptState::New,
            client_id: TypedUuid::new_v4(),
            redirect_uri: "https://test.oxeng.dev/callback".to_string(),
            state: Some("ox_state".to_string()),
            pkce_challenge: Some("ox_challenge".to_string()),
            pkce_challenge_method: Some("S256".to_string()),
            authz_code: None,
            expires_at: None,
            error: None,
            provider: "google".to_string(),
            provider_pkce_verifier: Some("v_verifier".to_string()),
            provider_authz_code: None,
            provider_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            scope: String::new(),
        };

        let mut attempt_store = MockLoginAttemptStore::new();
        let original_attempt = attempt.clone();
        attempt_store
            .expect_get()
            .with(eq(attempt.id))
            .returning(move |_| Ok(Some(original_attempt.clone())));

        let extracted_code = Arc::new(Mutex::new(None));
        let extractor = extracted_code.clone();
        attempt_store
            .expect_upsert()
            .withf(|attempt| attempt.attempt_state == LoginAttemptState::RemoteAuthenticated)
            .returning(move |arg| {
                let mut returned = attempt.clone();
                returned.attempt_state = arg.attempt_state;
                returned.authz_code = arg.authz_code;
                *extractor.lock().unwrap() = returned.authz_code.clone();
                Ok(returned)
            });

        let mut storage = MockStorage::new();
        storage.login_attempt_store = Some(Arc::new(attempt_store));
        let ctx = mock_context(Arc::new(storage)).await;

        let location =
            authz_code_callback_op_inner(&ctx, &attempt_id, Some("remote-code".to_string()), None)
                .await
                .unwrap();

        let lock = extracted_code.lock();
        assert_eq!(
            format!(
                "https://test.oxeng.dev/callback?code={}&state=ox_state",
                lock.unwrap().as_ref().unwrap()
            ),
            location
        );
    }

    #[tokio::test]
    async fn test_fails_callback_with_error() {}

    #[tokio::test]
    async fn test_exchange_checks_client_id_and_redirect() {
        let (mut ctx, client, client_secret) = mock_client().await;
        let client_id = client.id;
        let redirect_uri = client.redirect_uris[0].redirect_uri.clone();
        let wrong_client_id = TypedUuid::new_v4();

        let mut client_store = MockOAuthClientStore::new();
        client_store
            .expect_get()
            .with(eq(wrong_client_id), eq(false))
            .returning(move |_, _| Ok(None));
        client_store
            .expect_get()
            .with(eq(client_id), eq(false))
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut storage = MockStorage::new();
        storage.oauth_client_store = Some(Arc::new(client_store));

        ctx.set_storage(Arc::new(storage));

        // 1. Verify exchange fails when passing an incorrect client id
        assert_eq!(
            Some("Unknown client id".to_string()),
            authorize_code_exchange(
                &ctx,
                "authorization_code",
                wrong_client_id,
                &client_secret,
                &redirect_uri,
            )
            .await
            .unwrap_err()
            .error_description
        );

        // 2. Verify exchange fails when passing an incorrect redirect uri
        assert_eq!(
            Some("Invalid redirect uri".to_string()),
            authorize_code_exchange(
                &ctx,
                "authorization_code",
                client_id,
                &client_secret,
                "wrong-callback-destination",
            )
            .await
            .unwrap_err()
            .error_description
        );

        // 3. Verify a successful exchange
        assert_eq!(
            (),
            authorize_code_exchange(
                &ctx,
                "authorization_code",
                client_id,
                &client_secret,
                &redirect_uri,
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_exchange_checks_grant_type() {
        let (mut ctx, client, client_secret) = mock_client().await;
        let client_id = client.id;
        let redirect_uri = client.redirect_uris[0].redirect_uri.clone();

        let mut client_store = MockOAuthClientStore::new();
        client_store
            .expect_get()
            .with(eq(client_id), eq(false))
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut storage = MockStorage::new();
        storage.oauth_client_store = Some(Arc::new(client_store));

        ctx.set_storage(Arc::new(storage));

        assert_eq!(
            OAuthErrorCode::UnsupportedGrantType,
            authorize_code_exchange(
                &ctx,
                "not_authorization_code",
                client_id,
                &client_secret,
                &redirect_uri
            )
            .await
            .unwrap_err()
            .error
        );

        assert_eq!(
            (),
            authorize_code_exchange(
                &ctx,
                "authorization_code",
                client_id,
                &client_secret,
                &redirect_uri
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_exchange_checks_for_valid_secret() {
        let (mut ctx, client, client_secret) = mock_client().await;
        let client_id = client.id;
        let redirect_uri = client.redirect_uris[0].redirect_uri.clone();

        let mut client_store = MockOAuthClientStore::new();
        client_store
            .expect_get()
            .with(eq(client_id), eq(false))
            .returning(move |_, _| Ok(Some(client.clone())));

        let mut storage = MockStorage::new();
        storage.oauth_client_store = Some(Arc::new(client_store));

        ctx.set_storage(Arc::new(storage));

        let invalid_secret = RawKey::generate::<8>(&Uuid::new_v4())
            .sign(&*ctx.signer())
            .await
            .unwrap()
            .signature()
            .to_string();

        assert_eq!(
            OAuthErrorCode::InvalidRequest,
            authorize_code_exchange(
                &ctx,
                "authorization_code",
                client_id,
                &"too-short".to_string().into(),
                &redirect_uri
            )
            .await
            .unwrap_err()
            .error
        );

        assert_eq!(
            OAuthErrorCode::InvalidClient,
            authorize_code_exchange(
                &ctx,
                "authorization_code",
                client_id,
                &invalid_secret.into(),
                &redirect_uri
            )
            .await
            .unwrap_err()
            .error
        );

        assert_eq!(
            (),
            authorize_code_exchange(
                &ctx,
                "authorization_code",
                client_id,
                &client_secret,
                &redirect_uri
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_login_attempt_verification() {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let attempt = LoginAttempt {
            id: TypedUuid::new_v4(),
            attempt_state: LoginAttemptState::RemoteAuthenticated,
            client_id: TypedUuid::new_v4(),
            redirect_uri: "https://test.oxeng.dev/callback".to_string(),
            state: Some("ox_state".to_string()),
            pkce_challenge: Some(challenge.as_str().to_string()),
            pkce_challenge_method: Some("S256".to_string()),
            authz_code: None,
            expires_at: Some(Utc::now().add(TimeDelta::try_seconds(60).unwrap())),
            error: None,
            provider: "google".to_string(),
            provider_pkce_verifier: Some("v_verifier".to_string()),
            provider_authz_code: None,
            provider_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            scope: String::new(),
        };

        let bad_client_id = LoginAttempt {
            client_id: TypedUuid::new_v4(),
            ..attempt.clone()
        };

        assert_eq!(
            OAuthError {
                error: OAuthErrorCode::InvalidGrant,
                error_description: Some("Invalid client id".to_string()),
                error_uri: None,
                state: None,
            },
            verify_login_attempt(
                &bad_client_id,
                attempt.client_id,
                &attempt.redirect_uri,
                Some(verifier.secret().as_str()),
            )
            .unwrap_err()
        );

        let bad_redirect_uri = LoginAttempt {
            redirect_uri: "https://bad.oxeng.dev/callback".to_string(),
            ..attempt.clone()
        };

        assert_eq!(
            OAuthError {
                error: OAuthErrorCode::InvalidGrant,
                error_description: Some("Invalid redirect uri".to_string()),
                error_uri: None,
                state: None,
            },
            verify_login_attempt(
                &bad_redirect_uri,
                attempt.client_id,
                &attempt.redirect_uri,
                Some(verifier.secret().as_str()),
            )
            .unwrap_err()
        );

        let unconfirmed_state = LoginAttempt {
            attempt_state: LoginAttemptState::New,
            ..attempt.clone()
        };

        assert_eq!(
            OAuthError {
                error: OAuthErrorCode::InvalidGrant,
                error_description: Some("Grant is in an invalid state".to_string()),
                error_uri: None,
                state: None,
            },
            verify_login_attempt(
                &unconfirmed_state,
                attempt.client_id,
                &attempt.redirect_uri,
                Some(verifier.secret().as_str()),
            )
            .unwrap_err()
        );

        let already_used_state = LoginAttempt {
            attempt_state: LoginAttemptState::Complete,
            ..attempt.clone()
        };

        assert_eq!(
            OAuthError {
                error: OAuthErrorCode::InvalidGrant,
                error_description: Some("Grant is in an invalid state".to_string()),
                error_uri: None,
                state: None,
            },
            verify_login_attempt(
                &already_used_state,
                attempt.client_id,
                &attempt.redirect_uri,
                Some(verifier.secret().as_str()),
            )
            .unwrap_err()
        );

        let failed_state = LoginAttempt {
            attempt_state: LoginAttemptState::Failed,
            ..attempt.clone()
        };

        assert_eq!(
            OAuthError {
                error: OAuthErrorCode::InvalidGrant,
                error_description: Some("Grant is in an invalid state".to_string()),
                error_uri: None,
                state: None,
            },
            verify_login_attempt(
                &failed_state,
                attempt.client_id,
                &attempt.redirect_uri,
                Some(verifier.secret().as_str()),
            )
            .unwrap_err()
        );

        let expired = LoginAttempt {
            expires_at: Some(Utc::now()),
            ..attempt.clone()
        };

        assert_eq!(
            OAuthError {
                error: OAuthErrorCode::InvalidGrant,
                error_description: Some("Grant has expired".to_string()),
                error_uri: None,
                state: None,
            },
            verify_login_attempt(
                &expired,
                attempt.client_id,
                &attempt.redirect_uri,
                Some(verifier.secret().as_str()),
            )
            .unwrap_err()
        );

        let missing_pkce = LoginAttempt { ..attempt.clone() };

        assert_eq!(
            OAuthError {
                error: OAuthErrorCode::InvalidRequest,
                error_description: Some("Missing pkce verifier".to_string()),
                error_uri: None,
                state: None,
            },
            verify_login_attempt(
                &missing_pkce,
                attempt.client_id,
                &attempt.redirect_uri,
                None,
            )
            .unwrap_err()
        );

        let invalid_pkce = LoginAttempt {
            pkce_challenge: Some("no-the-correct-value".to_string()),
            ..attempt.clone()
        };

        assert_eq!(
            OAuthError {
                error: OAuthErrorCode::InvalidGrant,
                error_description: Some("Invalid pkce verifier".to_string()),
                error_uri: None,
                state: None,
            },
            verify_login_attempt(
                &invalid_pkce,
                attempt.client_id,
                &attempt.redirect_uri,
                Some(verifier.secret().as_str()),
            )
            .unwrap_err()
        );

        assert_eq!(
            (),
            verify_login_attempt(
                &attempt,
                attempt.client_id,
                &attempt.redirect_uri,
                Some(verifier.secret().as_str()),
            )
            .unwrap()
        );
    }
}
