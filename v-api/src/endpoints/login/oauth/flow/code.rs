// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{TimeDelta, Utc};
use cookie::{Cookie, SameSite};
use dropshot::{
    ClientErrorStatusCode, HttpError, HttpResponseOk, HttpResponseTemporaryRedirect, Path, Query,
    RequestContext, RequestInfo, SharedExtractor, TypedBody, http_response_temporary_redirect,
};
use dropshot_authorization_header::basic::BasicAuth;
use http::{HeaderValue, header::SET_COOKIE};
use newtype_uuid::{GenericUuid, TypedUuid};
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
use uuid::Uuid;
use v_model::{
    LoginAttempt, LoginAttemptId, NewLoginAttempt, OAuthClient, OAuthClientId,
    permissions::{AsScope, PermissionStorage},
    schema_ext::LoginAttemptState,
};

use super::super::{OAuthProvider, OAuthProviderNameParam};
use crate::endpoints::login::UserInfoProvider;
use crate::{
    authn::key::RawKey,
    context::{ApiContext, VContext},
    endpoints::login::{
        LoginError, UserInfo,
        oauth::{CheckOAuthClient, OAuthProviderAuthorizationCodePkceInfo},
    },
    error::ApiError,
    permissions::{VAppPermission, VPermission},
    response::bad_request,
    secrets::OpenApiSecretString,
    util::{
        request::RequestCookies,
        response::{ResourceError, internal_error, to_internal_error, unauthorized},
    },
};

static LOGIN_ATTEMPT_COOKIE: &str = "__v_login";
static LOGIN_ATTEMPT_COOKIE_PATH: &str = "/login/oauth/";

/// Build the login attempt cookie with consistent attributes.
/// The `Path` is scoped to the OAuth login endpoints so the cookie is not
/// sent to unrelated paths on the same domain.
fn build_login_attempt_cookie<'a>(
    value: &'a str,
    public_url: &str,
    max_age_secs: i64,
) -> Cookie<'a> {
    let mut cookie = Cookie::new(LOGIN_ATTEMPT_COOKIE, value.to_string());
    cookie.set_path(LOGIN_ATTEMPT_COOKIE_PATH);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_secure(public_url.starts_with("https"));
    cookie.set_max_age(cookie::time::Duration::seconds(max_age_secs));
    cookie
}

// RFC 6749 §5.2 shaped error
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

impl OAuthError {
    pub fn new(error: OAuthErrorCode, error_description: Option<&str>) -> Self {
        Self {
            error,
            error_description: error_description.map(|s| s.to_string()),
            error_uri: None,
            state: None,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
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
    /// PKCE code challenge (RFC 7636). Required for all authorization code flows.
    pub code_challenge: String,
    /// PKCE code challenge method. Must be "S256".
    pub code_challenge_method: String,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct OAuthAuthzCodeRedirectHeaders {
    #[serde(rename = "set-cookies")]
    cookies: String,
    location: String,
}

/// Validate the PKCE code challenge. For S256, this must be a base64url-no-pad
/// encoding of a SHA256 hash, which is always exactly 43 characters of [A-Za-z0-9_-]
/// (RFC 7636 §4.2).
fn validate_code_challenge(code_challenge: &str) -> Result<(), OAuthError> {
    if !BASE64_URL_SAFE_NO_PAD
        .decode(code_challenge)
        .is_ok_and(|bytes| bytes.len() == 32)
    {
        Err(OAuthError::new(
            OAuthErrorCode::InvalidRequest,
            Some(
                "Invalid code_challenge. Must be a base64url-encoded SHA256 hash (43 characters).",
            ),
        ))
    } else {
        Ok(())
    }
}

/// Validate that response_type is "code" per RFC 6749 §4.1.1.
fn validate_response_type(response_type: &str) -> Result<(), OAuthError> {
    if response_type == "code" {
        Ok(())
    } else {
        Err(OAuthError::new(
            OAuthErrorCode::UnsupportedResponseType,
            Some("Only response_type=code is supported"),
        ))
    }
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
                ResourceError::DoesNotExist => {
                    OAuthError::new(OAuthErrorCode::InvalidClient, Some("Unknown client id"))
                }
                // Given that the builtin caller should have access to all OAuth clients, any other
                // error is considered an internal error
                _ => OAuthError::new(OAuthErrorCode::ServerError, None),
            }
        })?;

    if client.is_redirect_uri_valid(redirect_uri) {
        Ok(client)
    } else {
        Err(OAuthError::new(
            OAuthErrorCode::InvalidRequest,
            Some("Invalid redirect uri"),
        ))
    }
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn get_public_pkce_provider_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<OAuthProviderNameParam>,
) -> Result<HttpResponseOk<OAuthProviderAuthorizationCodePkceInfo>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let path = path.into_inner();

    tracing::trace!("Getting OAuth data for {}", path.provider);

    let provider = rqctx
        .v_ctx()
        .get_oauth_provider(&path.provider)
        .await
        .map_err(ApiError::OAuth)?;

    Ok(HttpResponseOk(
        provider
            .authz_code_pkce_flow_info()
            .cloned()
            .ok_or_else(|| bad_request("Provider does not support web pkce clients"))?,
    ))
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn authz_code_redirect_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<OAuthProviderNameParam>,
    query: Query<OAuthAuthzCodeQuery>,
) -> Result<HttpResponseTemporaryRedirect, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let ctx = rqctx.v_ctx();
    let path = path.into_inner();
    let query = query.into_inner();

    get_oauth_client(ctx, &query.client_id, &query.redirect_uri).await?;

    tracing::debug!(?query.client_id, ?query.redirect_uri, "Verified client id and redirect uri");

    // Validate response_type. Only "code" is supported (RFC 6749 §4.1.1).
    validate_response_type(&query.response_type)?;

    // Validate the client's PKCE challenge method. Only S256 is supported.
    if query.code_challenge_method != "S256" {
        Err(OAuthError::new(
            OAuthErrorCode::InvalidRequest,
            Some("Unsupported code_challenge_method. Only S256 is supported."),
        ))?;
    }

    // Validate the PKCE code challenge (RFC 7636 §4.2).
    validate_code_challenge(&query.code_challenge)?;

    // Find the configured provider for the requested remote backend. We should always have a valid
    // provider value, so if this fails then a 500 is returned
    let provider = ctx
        .get_oauth_provider(&path.provider)
        .await
        .map_err(ApiError::OAuth)?;

    tracing::debug!(provider = ?provider.name(), "Acquired OAuth provider for authz code login");

    // Check that the passed in scopes are valid. A None scope means no permissions.
    // Use the special scope "full" to request all permissions.
    if let Some(ref scope) = query.scope
        && let Err(err) = VPermission::from_scope_arg(scope)
    {
        tracing::warn!(?err, ?scope, "Client submitted an invalid scope");
        Err(OAuthError::new(
            OAuthErrorCode::InvalidScope,
            Some(format!("Invalid scope: {}", scope).as_str()),
        ))?;
    }

    // Construct a new login attempt with the minimum required values
    let mut attempt = NewLoginAttempt::new(
        provider.name().to_string(),
        query.client_id,
        Some(query.redirect_uri),
        query.scope.unwrap_or_default(),
        "authorization_code".to_string(),
    )
    .map_err(|err| {
        tracing::error!(?err, "Attempted to construct invalid login attempt");
        internal_error("Attempted to construct invalid login attempt".to_string())
    })?;

    // Set a default expiration for the login attempt
    // TODO: Make this configurable
    attempt.expires_at = Some(Utc::now().add(TimeDelta::try_minutes(5).unwrap()));

    // Store the client's state value as-is. Per RFC 6749 §4.1.1, the authorization server
    // MUST return the state parameter unmodified. The value will be properly percent-encoded
    // when it is placed into the redirect URL by `callback_url()` via `append_pair`.
    attempt.state = Some(query.state);

    // Always store the client's PKCE challenge so we can verify it during the token exchange.
    // This is the client-to-v-api PKCE leg and is mandatory for all flows.
    attempt.pkce_challenge = Some(query.code_challenge);
    attempt.pkce_challenge_method = Some(query.code_challenge_method);

    // If the remote provider supports PKCE, also set up a challenge for the v-api-to-remote leg.
    // This is independent of the client-to-v-api PKCE above.
    let remote_pkce_challenge = if provider.supports_pkce() {
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

    oauth_redirect_response(
        ctx.public_url(),
        &*provider,
        &attempt,
        remote_pkce_challenge,
    )
}

fn oauth_redirect_response(
    public_url: &str,
    provider: &dyn OAuthProvider,
    attempt: &LoginAttempt,
    code_challenge: Option<PkceCodeChallenge>,
) -> Result<HttpResponseTemporaryRedirect, HttpError> {
    // We may fail if the provider configuration is not correctly configured
    // TODO: This behavior should be changed so that clients are precomputed. We do not need to be
    // constructing a new client on every request. That said, we need to ensure the client does not
    // maintain state between requests
    let client = provider.as_web_client().map_err(to_internal_error)?;

    // Create an attempt cookie header for storing the login attempt. This also acts as our csrf
    // check
    let attempt_id_str = attempt.id.to_string();
    let cookie = build_login_attempt_cookie(&attempt_id_str, public_url, 600);
    let login_cookie = HeaderValue::from_str(&cookie.to_string()).map_err(to_internal_error)?;

    // Generate the url to the remote provider that the user will be redirected to
    let mut authz_url = client
        .authorize_url(|| CsrfToken::new(attempt.id.to_string()))
        .add_scopes(
            provider
                .default_scopes()
                .iter()
                .map(|s| Scope::new(s.to_string()))
                .collect::<Vec<_>>(),
        );

    // If the caller has provided a code challenge, add it to the url
    if let Some(challenge) = code_challenge {
        authz_url = authz_url.set_pkce_challenge(challenge);
    };

    let mut redirect = http_response_temporary_redirect(authz_url.url().0.to_string())?;
    redirect.headers_mut().append(SET_COOKIE, login_cookie);

    Ok(redirect)
}

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
            bad_request("Invalid or missing OAuth state parameter")
        })?
        .parse()
        .map_err(|err| {
            tracing::warn!(?err, "Failed to parse state");
            bad_request("Invalid or missing OAuth state parameter")
        })?;

    // The client must present the attempt cookie at a minimum. Without it we are unable to lookup a
    // login attempt to match against. Without the cookie to verify the state parameter we can not
    // determine a redirect uri so we instead report a bad request
    let attempt_cookie = request
        .cookie(LOGIN_ATTEMPT_COOKIE)
        .ok_or_else(|| {
            tracing::warn!("OAuth callback is missing a login state cookie");
            bad_request("Invalid or missing OAuth state parameter")
        })?
        .value()
        .parse()
        .map_err(|err| {
            tracing::warn!(?err, "Failed to parse state cookie");
            bad_request("Invalid or missing OAuth state parameter")
        })?;

    // Verify that the attempt_id returned from the state matches the expected client value. If they
    // do not match we can not lookup a redirect uri so we instead return a bad request
    if attempt_id != attempt_cookie {
        tracing::warn!(
            ?attempt_id,
            ?attempt_cookie,
            "OAuth state does not match expected cookie value"
        );
        Err(bad_request("Invalid or missing OAuth state parameter"))
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

    // Clear the login attempt cookie
    let cookie = build_login_attempt_cookie("", ctx.public_url(), 0);
    let login_cookie = HeaderValue::from_str(&cookie.to_string()).map_err(to_internal_error)?;

    let mut redirect = http_response_temporary_redirect(
        authz_code_callback_op_inner(ctx, &attempt_id, query.code, query.error).await?,
    )?;
    redirect.headers_mut().append(SET_COOKIE, login_cookie);

    Ok(redirect)
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
        .get_login_attempt(attempt_id)
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

    // Re-validate the redirect URI against the OAuth client's current registered URIs.
    // The URI was checked when the login attempt was created, but it may have been removed
    // since then. We must not redirect to a URI that is no longer registered (TOCTOU).
    let client = ctx
        .oauth
        .get_oauth_client(&ctx.builtin_registration_user(), &attempt.client_id)
        .await?;
    if !attempt
        .redirect_uri
        .as_deref()
        .is_some_and(|uri| client.is_redirect_uri_valid(uri))
    {
        tracing::warn!(
            redirect_uri = ?attempt.redirect_uri,
            client_id = ?attempt.client_id,
            "Login attempt redirect URI is no longer registered on the OAuth client"
        );
        return Err(unauthorized());
    }

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
        // If the remote provider returned an error than we can not accept the authorization
        // flow. We are intentionally dropping the code here as we do not get debugging value in
        // keeping it, but are accepting risk of holding an unused authorization code.
        (_code, error) => {
            tracing::info!(?attempt.id, ?error, "Received an error response from the remote server");

            // When a user has explicitly denied access we want to forward that error message
            // onwards to the upstream requester. All other errors should be opaque to the
            // original requester and are returned as server errors
            let error_message = match error.as_deref() {
                Some("access_denied") => "access_denied",
                _ => "server_error",
            };

            // TODO: Specialize the returned error
            ctx.login
                .fail_login_attempt(
                    attempt,
                    LoginAttemptState::New,
                    Some(error_message),
                    error.as_deref(),
                )
                .await
                .map_err(to_internal_error)?
        }
    };

    // Redirect back to the original authenticator
    attempt.callback_url().map_err(|err| {
        tracing::error!(?err, redirect_uri = ?attempt.redirect_uri, "Login attempt contains an invalid redirect URI");
        to_internal_error(err)
    })?.ok_or_else(|| {
        tracing::error!("Login attempt has no redirect URI");
        internal_error("Login attempt has no redirect URI")
    })
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OAuthAuthzCodeExchangeQuery {
    #[serde(default)]
    pub request_idp_token: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct OAuthAuthzCodeExchangeBody {
    pub client_id: Option<TypedUuid<OAuthClientId>>,
    pub client_secret: Option<OpenApiSecretString>,
    pub redirect_uri: String,
    pub grant_type: String,
    pub code: String,
    /// PKCE code verifier (RFC 7636). Required for all authorization code exchanges.
    pub pkce_verifier: String,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct OAuthAuthzCodeExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    /// The scope granted to the access token per RFC 6749 §5.1. An empty
    /// string indicates no permissions. Use "full" for all permissions.
    pub scope: String,
    pub idp_token: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct OAuthAuthzCodeIdpToken {
    pub token: String,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn authz_code_exchange_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    query: Query<OAuthAuthzCodeExchangeQuery>,
    path: Path<OAuthProviderNameParam>,
    body: TypedBody<OAuthAuthzCodeExchangeBody>,
) -> Result<HttpResponseOk<OAuthAuthzCodeExchangeResponse>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let ctx = rqctx.v_ctx();
    let query = query.into_inner();
    let path = path.into_inner();
    let body = body.into_inner();

    let provider = ctx
        .get_oauth_provider(&path.provider)
        .await
        .map_err(ApiError::OAuth)?;

    // Extract basic authorization credentials from the request if they were provided.
    let auth = <BasicAuth as SharedExtractor>::from_request(rqctx)
        .await
        .tap_err(|err| {
            tracing::warn!(?err, "Failed to extract basic authentication values");
        });
    let basic_credentials = match auth {
        Ok(auth) if auth.username().is_some() && auth.password().is_some() => Ok(Some((
            TypedUuid::from_untyped_uuid(
                Uuid::parse_str(auth.username().unwrap())
                    .map_err(|_| bad_request("Malformed client ID presented to code exchange"))?,
            ),
            auth.password().unwrap().to_string(),
        ))),
        Ok(auth) if auth.username().is_none() && auth.password().is_none() => {
            tracing::info!("Credentials for code exchange not defined via basic auth");
            Ok(None)
        }
        Ok(_) => Err(bad_request(
            "Malformed credentials presented to code exchange",
        )),
        Err(err) => {
            tracing::info!(?err, "Failed to extract basic authentication credentials");
            Ok(None)
        }
    }?;

    // Extract credentials from the request body if they were provided.
    let body_credentials = (body.client_id, body.client_secret);

    // Now validate if the credentials provided by the client support one of our expected schemes.
    // We of course deny underspecifying credentials, but we also want to disallow over specifying
    // them. For example, if the client provides both basic auth and a client id/secret in the
    // request body, we should reject the request.
    tracing::debug!(
        ?basic_credentials,
        ?body_credentials,
        "Extracted credentials from request"
    );
    let (client_id, client_secret) = match (basic_credentials, body_credentials) {
        (Some(_), (Some(_), _)) => Err(bad_request(
            "Cannot provide both basic auth and client credentials",
        )),
        (Some(_), (_, Some(_))) => Err(bad_request(
            "Cannot provide both basic auth and client credentials",
        )),
        (Some((client_id, client_secret)), (None, None)) => Ok((
            client_id,
            Some(OpenApiSecretString(SecretString::from(client_secret))),
        )),
        (None, (Some(client_id), Some(client_secret))) => Ok((client_id, Some(client_secret))),
        (None, (Some(client_id), _)) if provider.authz_code_pkce_flow_info().is_some() => {
            Ok((client_id, None))
        }
        _ => Err(bad_request("Missing client credentials")),
    }?;

    tracing::debug!("Attempting code exchange");

    // Verify the submitted client credentials
    authorize_code_exchange(
        ctx,
        &*provider,
        &body.grant_type,
        client_id,
        client_secret.map(|s| s.0).as_ref(),
        &body.redirect_uri,
    )
    .await?;

    tracing::debug!("Authorized code exchange");

    // Lookup the request assigned to this code
    let mut attempt = ctx
        .login
        .get_login_attempt_for_code(&body.code, &provider.name().to_string())
        .await
        .map_err(to_internal_error)?
        .ok_or(OAuthError::new(OAuthErrorCode::InvalidGrant, None))?;

    // Verify that the login attempt is valid and matches the submitted client credentials
    verify_login_attempt(
        &attempt,
        &provider.name().to_string(),
        client_id,
        &body.redirect_uri,
        &body.pkce_verifier,
    )?;

    tracing::debug!("Verified login attempt");

    // Atomically claim this login attempt before doing any remote work. This transitions
    // the attempt from RemoteAuthenticated -> Complete in a single conditional UPDATE,
    // ensuring that a concurrent request using the same authorization code will fail.
    // Per RFC 6749 §4.1.2, authorization codes MUST be single-use.
    let attempt_id = attempt.id;
    attempt = ctx
        .login
        .claim_login_attempt(attempt)
        .await
        .map_err(|err| {
            tracing::warn!(
                ?err,
                ?attempt_id,
                "Failed to claim login attempt (may have been consumed by a concurrent request)"
            );
            OAuthError::new(
                OAuthErrorCode::InvalidGrant,
                Some("Authorization code has already been used"),
            )
        })?;

    tracing::debug!("Claimed login attempt");

    // Now that the attempt has been claimed, use it to fetch user information from the
    // remote provider. If this fails, the attempt is already consumed and the user must
    // re-authenticate. The upstream access token is always preserved here so that
    // revocation can be deferred until after the permission check.
    let (info, upstream_token) = fetch_user_info(ctx.public_url(), &*provider, &attempt).await?;

    tracing::debug!("Retrieved user information from remote provider");

    super::complete_exchange(
        ctx,
        info,
        &*provider,
        &attempt,
        query.request_idp_token,
        upstream_token,
    )
    .await
}

async fn authorize_code_exchange<T>(
    ctx: &VContext<T>,
    provider: &dyn OAuthProvider,
    grant_type: &str,
    client_id: TypedUuid<OAuthClientId>,
    client_secret: Option<&SecretString>,
    redirect_uri: &str,
) -> Result<(), OAuthError>
where
    T: VAppPermission + PermissionStorage,
{
    let client = get_oauth_client(ctx, &client_id, redirect_uri).await?;

    // Verify that we received the expected grant type
    if grant_type != "authorization_code" {
        Err(OAuthError::new(OAuthErrorCode::UnsupportedGrantType, None))?;
    }

    tracing::debug!(grant_type, "Verified grant type");

    // If we were provided a client secret, then it must be verified. If a client secret was not
    // provided, then we can skip this step as long as the provider supports pkce_only
    // authentication.
    if let Some(client_secret) = client_secret {
        let client_secret = RawKey::try_from(client_secret).map_err(|err| {
            tracing::warn!(?err, "Failed to parse OAuth client secret");

            OAuthError::new(
                OAuthErrorCode::InvalidRequest,
                Some("Malformed client secret"),
            )
        })?;

        tracing::debug!("Constructed client secret");

        if !client.is_secret_valid(&client_secret, ctx) {
            Err(OAuthError::new(
                OAuthErrorCode::InvalidClient,
                Some("Invalid client secret"),
            ))
        } else {
            tracing::debug!("Verified client secret validity");

            Ok(())
        }
    } else if provider.authz_code_pkce_flow_info().is_some() {
        Ok(())
    } else {
        Err(OAuthError::new(
            OAuthErrorCode::InvalidRequest,
            Some("Client secret required"),
        ))
    }
}

fn verify_login_attempt(
    attempt: &LoginAttempt,
    provider: &str,
    client_id: TypedUuid<OAuthClientId>,
    redirect_uri: &str,
    pkce_verifier: &str,
) -> Result<(), OAuthError> {
    if attempt.provider != provider {
        Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            Some("Provider mismatch"),
        ))
    } else if attempt.client_id != client_id {
        Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            Some("Invalid client id"),
        ))
    } else if attempt.redirect_uri.as_deref() != Some(redirect_uri) {
        Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            Some("Invalid redirect uri"),
        ))
    } else if attempt.attempt_state != LoginAttemptState::RemoteAuthenticated {
        Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            Some("Grant is in an invalid state"),
        ))
    } else if attempt.expires_at.map(|t| t <= Utc::now()).unwrap_or(true) {
        Err(OAuthError::new(
            OAuthErrorCode::InvalidGrant,
            Some("Grant has expired"),
        ))
    } else {
        match attempt.pkce_challenge.as_deref() {
            Some(challenge) => {
                let mut hasher = Sha256::new();
                hasher.update(pkce_verifier);
                let hash = hasher.finalize();
                let computed_challenge = BASE64_URL_SAFE_NO_PAD.encode(hash);

                if challenge == computed_challenge {
                    Ok(())
                } else {
                    Err(OAuthError::new(
                        OAuthErrorCode::InvalidGrant,
                        Some("Invalid pkce verifier"),
                    ))
                }
            }
            // PKCE is mandatory for all authorization code flows. A missing challenge
            // means the login attempt was not properly initialized.
            None => Err(OAuthError::new(
                OAuthErrorCode::InvalidGrant,
                Some("Login attempt is missing a PKCE challenge"),
            )),
        }
    }
}

#[instrument(skip(attempt))]
async fn fetch_user_info(
    public_url: &str,
    provider: &dyn OAuthProvider,
    attempt: &LoginAttempt,
) -> Result<(UserInfo, Option<String>), HttpError> {
    // Exchange the stored authorization code with the remote provider for a remote access token
    let client = provider.as_web_client().map_err(to_internal_error)?;

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

    if let Some(expires_in) = provider.expires_in() {
        request = request.add_extra_param("expires_in", expires_in.to_string());
    }

    let oauth_client: oauth2_reqwest::ReqwestClient = provider.client().clone().into();
    let response = request
        .request_async(&oauth_client)
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

    // Return the upstream access token alongside the user info so the caller
    // can decide whether to revoke it after the permission check.
    let upstream_token = Some(response.access_token().secret().to_string());

    Ok((info, upstream_token))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddrV4},
        ops::Add,
        sync::{Arc, Mutex},
    };

    use chrono::{TimeDelta, Utc};
    use dropshot::{HttpResponse, RequestInfo};
    use http::{
        HeaderValue, StatusCode,
        header::{COOKIE, LOCATION, SET_COOKIE},
    };
    use http_body_util::Empty;
    use mockall::predicate::eq;
    use newtype_uuid::TypedUuid;
    use oauth2::PkceCodeChallenge;
    use secrecy::{SecretBox, SecretString};
    use uuid::Uuid;
    use v_model::{
        AccessToken, ApiUser, ApiUserInfo, ApiUserProvider, LoginAttempt, NewApiUser,
        NewApiUserProvider, OAuthClient, OAuthClientRedirectUri, OAuthClientSecret,
        schema_ext::LoginAttemptState,
        storage::{
            MockAccessGroupStore, MockAccessTokenStore, MockApiUserProviderStore, MockApiUserStore,
            MockLoginAttemptStore, MockMapperStore, MockOAuthClientStore,
        },
    };

    use crate::{
        authn::{
            jwt::{Claims, Jwt},
            key::RawKey,
        },
        context::{
            VContext,
            test_mocks::{MockStorage, mock_context},
        },
        endpoints::login::{
            ExternalUserId, UserInfo,
            oauth::{
                OAuthProviderName,
                flow::{
                    code::{
                        LOGIN_ATTEMPT_COOKIE, OAuthAuthzCodeReturnQuery, OAuthError,
                        OAuthErrorCode, authz_code_callback_op_inner, verify_csrf,
                        verify_login_attempt,
                    },
                    should_provide_idp_token,
                },
            },
        },
        permissions::VPermission,
    };

    use super::super::complete_exchange;
    use super::{authorize_code_exchange, get_oauth_client, oauth_redirect_response};

    /// A minimal no-op `OAuthProvider` for unit tests that need to pass a
    /// provider reference to `complete_exchange` without performing any real
    /// network I/O.  `authz_code_flow_info` returns `None`, so
    /// `revoke_upstream_token` will short-circuit immediately.
    #[derive(Debug)]
    struct NoOpOAuthProvider {
        client: reqwest::Client,
    }

    impl NoOpOAuthProvider {
        fn new() -> Self {
            Self {
                client: reqwest::Client::new(),
            }
        }
    }

    impl crate::endpoints::login::oauth::ExtractUserInfo for NoOpOAuthProvider {
        fn extract_user_info(
            &self,
            _data: &[hyper::body::Bytes],
        ) -> Result<UserInfo, crate::endpoints::login::oauth::UserInfoError> {
            unimplemented!("not used in tests")
        }
    }

    impl crate::endpoints::login::oauth::OAuthProvider for NoOpOAuthProvider {
        fn name(&self) -> OAuthProviderName {
            OAuthProviderName::Google
        }
        fn initialize_headers(&self, _request: &mut reqwest::Request) {}
        fn client(&self) -> &reqwest::Client {
            &self.client
        }
        fn user_info_endpoints(&self) -> Vec<&str> {
            vec![]
        }
        fn authz_code_flow_info(
            &self,
        ) -> Option<&crate::endpoints::login::oauth::OAuthProviderAuthorizationCodeInfo> {
            None
        }
        fn authz_code_pkce_flow_info(
            &self,
        ) -> Option<&crate::endpoints::login::oauth::OAuthProviderAuthorizationCodePkceInfo>
        {
            None
        }
        fn device_code_flow_info(
            &self,
        ) -> Option<&crate::endpoints::login::oauth::OAuthProviderDeviceInfo> {
            None
        }
        fn expires_in(&self) -> Option<u64> {
            None
        }
        fn default_scopes(&self) -> &[String] {
            &[]
        }
        fn supports_pkce(&self) -> bool {
            false
        }
    }

    /// Create a mock `OAuthClientStore` that returns a client with the given
    /// `client_id` and a single registered `redirect_uri`. This is needed by
    /// any test that exercises `authz_code_callback_op_inner`, which re-validates
    /// the redirect URI against the client before redirecting.
    fn mock_oauth_client_store_for_callback(
        client_id: TypedUuid<v_model::OAuthClientId>,
        redirect_uri: &str,
    ) -> Arc<MockOAuthClientStore> {
        let redirect_uri = redirect_uri.to_string();
        let mut store = MockOAuthClientStore::new();
        store
            .expect_get()
            .with(eq(client_id), eq(false))
            .returning(move |_, _| {
                Ok(Some(OAuthClient {
                    id: client_id,
                    secrets: vec![],
                    redirect_uris: vec![OAuthClientRedirectUri {
                        id: TypedUuid::new_v4(),
                        oauth_client_id: client_id,
                        redirect_uri: redirect_uri.clone(),
                        created_at: Utc::now(),
                        deleted_at: None,
                    }],
                    created_at: Utc::now(),
                    deleted_at: None,
                }))
            });
        Arc::new(store)
    }

    async fn mock_client() -> (VContext<VPermission>, OAuthClient, SecretString) {
        let ctx = mock_context(Arc::new(MockStorage::new())).await;
        let client_id = TypedUuid::new_v4();
        let key = RawKey::generate::<8>(&Uuid::new_v4())
            .sign(ctx.signer())
            .await
            .unwrap();
        let secret_signature = key.signature().to_string();
        let client_secret = key.key();
        let redirect_uri = "https://example.com/callback";

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
        let ctx = mock_context(Arc::new(storage)).await;

        let (challenge, _) = PkceCodeChallenge::new_random_sha256();
        let attempt = LoginAttempt {
            id: TypedUuid::new_v4(),
            attempt_state: LoginAttemptState::New,
            client_id: TypedUuid::new_v4(),
            redirect_uri: Some("https://test.oxeng.dev/callback".to_string()),
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
            grant_type: "authorization_code".to_string(),
            device_code: None,
            provider_device_code: None,
        };

        let response = oauth_redirect_response(
            ctx.public_url(),
            &*ctx
                .get_oauth_provider(&OAuthProviderName::Google)
                .await
                .unwrap(),
            &attempt,
            Some(challenge.clone()),
        )
        .unwrap()
        .to_result()
        .unwrap();
        let headers = response.headers();

        let expected_location = format!(
            "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=google_web_client_id&state={}&code_challenge={}&code_challenge_method=S256&redirect_uri=https%3A%2F%2Ftest_public_url%2Flogin%2Foauth%2Fgoogle%2Fcode%2Fcallback&scope=openid+email+profile",
            attempt.id,
            challenge.as_str()
        );

        assert_eq!(
            expected_location,
            String::from_utf8(headers.get(LOCATION).unwrap().as_bytes().to_vec()).unwrap()
        );
        assert_eq!(
            format!(
                "{}; HttpOnly; SameSite=Lax; Secure; Path=/login/oauth/; Max-Age=600",
                attempt.id
            )
            .as_str(),
            String::from_utf8(headers.get(SET_COOKIE).unwrap().as_bytes().to_vec())
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
            StatusCode::BAD_REQUEST,
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
            StatusCode::BAD_REQUEST,
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
            StatusCode::BAD_REQUEST,
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
                redirect_uri: Some("https://test.oxeng.dev/callback".to_string()),
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
                grant_type: "authorization_code".to_string(),
                device_code: None,
                provider_device_code: None,
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
        let client_id = TypedUuid::new_v4();
        let attempt = LoginAttempt {
            id: attempt_id,
            attempt_state: LoginAttemptState::New,
            client_id,
            redirect_uri: Some("https://test.oxeng.dev/callback".to_string()),
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
            grant_type: "authorization_code".to_string(),
            device_code: None,
            provider_device_code: None,
        };

        let mut attempt_store = MockLoginAttemptStore::new();
        let original_attempt = attempt.clone();
        attempt_store
            .expect_get()
            .with(eq(attempt.id))
            .returning(move |_| Ok(Some(original_attempt.clone())));

        attempt_store
            .expect_update_if_state()
            .withf(|attempt, expected| {
                attempt.attempt_state == LoginAttemptState::Failed
                    && *expected == LoginAttemptState::New
            })
            .returning(move |arg, _| {
                let mut returned = attempt.clone();
                returned.attempt_state = arg.attempt_state;
                returned.authz_code = arg.authz_code;
                returned.error = arg.error;
                Ok(returned)
            });

        let mut storage = MockStorage::new();
        storage.login_attempt_store = Some(Arc::new(attempt_store));
        storage.oauth_client_store = Some(mock_oauth_client_store_for_callback(
            client_id,
            "https://test.oxeng.dev/callback",
        ));
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
            format!("https://test.oxeng.dev/callback?state=ox_state&error=server_error",),
            location
        );
    }

    #[tokio::test]
    async fn test_callback_forwards_access_denied() {
        let attempt_id = TypedUuid::new_v4();
        let client_id = TypedUuid::new_v4();
        let attempt = LoginAttempt {
            id: attempt_id,
            attempt_state: LoginAttemptState::New,
            client_id,
            redirect_uri: Some("https://test.oxeng.dev/callback".to_string()),
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
            grant_type: "authorization_code".to_string(),
            device_code: None,
            provider_device_code: None,
        };

        let mut attempt_store = MockLoginAttemptStore::new();
        let original_attempt = attempt.clone();
        attempt_store
            .expect_get()
            .with(eq(attempt.id))
            .returning(move |_| Ok(Some(original_attempt.clone())));

        attempt_store
            .expect_update_if_state()
            .withf(|attempt, expected| {
                attempt.attempt_state == LoginAttemptState::Failed
                    && *expected == LoginAttemptState::New
            })
            .returning(move |arg, _| {
                let mut returned = attempt.clone();
                returned.attempt_state = arg.attempt_state;
                returned.authz_code = arg.authz_code;
                returned.error = arg.error;
                Ok(returned)
            });

        let mut storage = MockStorage::new();
        storage.login_attempt_store = Some(Arc::new(attempt_store));
        storage.oauth_client_store = Some(mock_oauth_client_store_for_callback(
            client_id,
            "https://test.oxeng.dev/callback",
        ));
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
            format!("https://test.oxeng.dev/callback?state=ox_state&error=access_denied",),
            location
        );
    }

    #[tokio::test]
    async fn test_handles_callback_with_code() {
        let attempt_id = TypedUuid::new_v4();
        let client_id = TypedUuid::new_v4();
        let attempt = LoginAttempt {
            id: attempt_id,
            attempt_state: LoginAttemptState::New,
            client_id,
            redirect_uri: Some("https://test.oxeng.dev/callback".to_string()),
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
            grant_type: "authorization_code".to_string(),
            device_code: None,
            provider_device_code: None,
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
            .expect_update_if_state()
            .withf(|attempt, expected| {
                attempt.attempt_state == LoginAttemptState::RemoteAuthenticated
                    && *expected == LoginAttemptState::New
            })
            .returning(move |arg, _| {
                let mut returned = attempt.clone();
                returned.attempt_state = arg.attempt_state;
                returned.authz_code = arg.authz_code;
                *extractor.lock().unwrap() = returned.authz_code.clone();
                Ok(returned)
            });

        let mut storage = MockStorage::new();
        storage.login_attempt_store = Some(Arc::new(attempt_store));
        storage.oauth_client_store = Some(mock_oauth_client_store_for_callback(
            client_id,
            "https://test.oxeng.dev/callback",
        ));
        let ctx = mock_context(Arc::new(storage)).await;

        let location =
            authz_code_callback_op_inner(&ctx, &attempt_id, Some("remote-code".to_string()), None)
                .await
                .unwrap();

        let lock = extracted_code.lock();
        assert_eq!(
            format!(
                "https://test.oxeng.dev/callback?state=ox_state&code={}",
                lock.unwrap().as_ref().unwrap()
            ),
            location
        );
    }

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
        let provider = ctx
            .get_oauth_provider(&OAuthProviderName::Google)
            .await
            .unwrap();

        // 1. Verify exchange fails when passing an incorrect client id
        assert_eq!(
            Some("Unknown client id".to_string()),
            authorize_code_exchange(
                &ctx,
                &*provider,
                "authorization_code",
                wrong_client_id,
                Some(&client_secret),
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
                &*provider,
                "authorization_code",
                client_id,
                Some(&client_secret),
                "wrong-callback-destination",
            )
            .await
            .unwrap_err()
            .error_description
        );

        // 3. Verify a successful exchange with a client secret
        assert_eq!(
            (),
            authorize_code_exchange(
                &ctx,
                &*provider,
                "authorization_code",
                client_id,
                Some(&client_secret),
                &redirect_uri,
            )
            .await
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_exchange_requires_secret_except_for_pkce_only() {
        let (mut ctx, client, _) = mock_client().await;
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

        let provider = ctx
            .get_oauth_provider(&OAuthProviderName::Google)
            .await
            .unwrap();
        let pkce_only_provider = ctx
            .get_oauth_provider(&OAuthProviderName::Zendesk)
            .await
            .unwrap();

        // 1. Verify exchange fails when not passing a client secret for a client that does not
        // support pkce_only
        assert_eq!(
            Some("Client secret required".to_string()),
            authorize_code_exchange(
                &ctx,
                &*provider,
                "authorization_code",
                client_id,
                None,
                &redirect_uri,
            )
            .await
            .unwrap_err()
            .error_description
        );

        // 2. Verify exchange passes when omitting the client secret for a client that does
        // support pkce_only
        assert_eq!(
            (),
            authorize_code_exchange(
                &ctx,
                &*pkce_only_provider,
                "authorization_code",
                client_id,
                None,
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
        let provider = ctx
            .get_oauth_provider(&OAuthProviderName::Google)
            .await
            .unwrap();

        assert_eq!(
            OAuthErrorCode::UnsupportedGrantType,
            authorize_code_exchange(
                &ctx,
                &*provider,
                "not_authorization_code",
                client_id,
                Some(&client_secret),
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
                &*provider,
                "authorization_code",
                client_id,
                Some(&client_secret),
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
        let provider = ctx
            .get_oauth_provider(&OAuthProviderName::Google)
            .await
            .unwrap();

        let invalid_secret = RawKey::generate::<8>(&Uuid::new_v4())
            .sign(ctx.signer())
            .await
            .unwrap()
            .signature()
            .to_string();

        assert_eq!(
            OAuthErrorCode::InvalidRequest,
            authorize_code_exchange(
                &ctx,
                &*provider,
                "authorization_code",
                client_id,
                Some(&"too-short".to_string().into()),
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
                &*provider,
                "authorization_code",
                client_id,
                Some(&invalid_secret.into()),
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
                &*provider,
                "authorization_code",
                client_id,
                Some(&client_secret),
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
            redirect_uri: Some("https://test.oxeng.dev/callback".to_string()),
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
            grant_type: "authorization_code".to_string(),
            device_code: None,
            provider_device_code: None,
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
                &attempt.provider,
                attempt.client_id,
                attempt.redirect_uri.as_deref().unwrap(),
                verifier.secret().as_str(),
            )
            .unwrap_err()
        );

        let bad_redirect_uri = LoginAttempt {
            redirect_uri: Some("https://bad.oxeng.dev/callback".to_string()),
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
                &attempt.provider,
                attempt.client_id,
                attempt.redirect_uri.as_deref().unwrap(),
                verifier.secret().as_str(),
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
                &attempt.provider,
                attempt.client_id,
                attempt.redirect_uri.as_deref().unwrap(),
                verifier.secret().as_str(),
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
                &attempt.provider,
                attempt.client_id,
                attempt.redirect_uri.as_deref().unwrap(),
                verifier.secret().as_str(),
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
                &attempt.provider,
                attempt.client_id,
                attempt.redirect_uri.as_deref().unwrap(),
                verifier.secret().as_str(),
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
                &attempt.provider,
                attempt.client_id,
                attempt.redirect_uri.as_deref().unwrap(),
                verifier.secret().as_str(),
            )
            .unwrap_err()
        );

        // Verify that a login attempt with no stored PKCE challenge is rejected.
        // PKCE is mandatory, so a missing challenge means the attempt is invalid.
        let missing_challenge = LoginAttempt {
            pkce_challenge: None,
            pkce_challenge_method: None,
            ..attempt.clone()
        };

        assert_eq!(
            OAuthError {
                error: OAuthErrorCode::InvalidGrant,
                error_description: Some("Login attempt is missing a PKCE challenge".to_string()),
                error_uri: None,
                state: None,
            },
            verify_login_attempt(
                &missing_challenge,
                &attempt.provider,
                attempt.client_id,
                attempt.redirect_uri.as_deref().unwrap(),
                verifier.secret().as_str(),
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
                &attempt.provider,
                attempt.client_id,
                attempt.redirect_uri.as_deref().unwrap(),
                verifier.secret().as_str(),
            )
            .unwrap_err()
        );

        assert_eq!(
            (),
            verify_login_attempt(
                &attempt,
                &attempt.provider,
                attempt.client_id,
                attempt.redirect_uri.as_deref().unwrap(),
                verifier.secret().as_str(),
            )
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_provider_mismatch_is_rejected() {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();

        // Login attempt was created via Google
        let attempt = LoginAttempt {
            id: TypedUuid::new_v4(),
            attempt_state: LoginAttemptState::RemoteAuthenticated,
            client_id: TypedUuid::new_v4(),
            redirect_uri: Some("https://test.oxeng.dev/callback".to_string()),
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
            grant_type: "authorization_code".to_string(),
            device_code: None,
            provider_device_code: None,
        };

        // Exchanging against a different provider must fail
        assert_eq!(
            OAuthError {
                error: OAuthErrorCode::InvalidGrant,
                error_description: Some("Provider mismatch".to_string()),
                error_uri: None,
                state: None,
            },
            verify_login_attempt(
                &attempt,
                "github",
                attempt.client_id,
                attempt.redirect_uri.as_deref().unwrap(),
                verifier.secret().as_str(),
            )
            .unwrap_err()
        );

        // Exchanging against the correct provider must succeed
        assert_eq!(
            (),
            verify_login_attempt(
                &attempt,
                "google",
                attempt.client_id,
                attempt.redirect_uri.as_deref().unwrap(),
                verifier.secret().as_str(),
            )
            .unwrap()
        );
    }

    #[test]
    fn test_login_attempt_cookie_has_path() {
        let cookie =
            super::build_login_attempt_cookie("test-attempt-id", "https://example.com", 600);

        assert_eq!(cookie.path(), Some(super::LOGIN_ATTEMPT_COOKIE_PATH));
    }

    #[test]
    fn test_login_attempt_cookie_is_http_only() {
        let cookie =
            super::build_login_attempt_cookie("test-attempt-id", "https://example.com", 600);

        assert_eq!(cookie.http_only(), Some(true));
    }

    #[test]
    fn test_login_attempt_cookie_is_same_site_lax() {
        let cookie =
            super::build_login_attempt_cookie("test-attempt-id", "https://example.com", 600);

        assert_eq!(cookie.same_site(), Some(cookie::SameSite::Lax));
    }

    #[test]
    fn test_login_attempt_cookie_is_secure_for_https() {
        let https_cookie =
            super::build_login_attempt_cookie("test-attempt-id", "https://example.com", 600);
        assert_eq!(https_cookie.secure(), Some(true));

        let http_cookie =
            super::build_login_attempt_cookie("test-attempt-id", "http://localhost", 600);
        assert_eq!(http_cookie.secure(), Some(false));
    }

    #[test]
    fn test_login_attempt_clear_cookie_has_same_path() {
        // The clear cookie must use the same Path as the set cookie,
        // otherwise browsers won't clear it.
        let set_cookie =
            super::build_login_attempt_cookie("test-attempt-id", "https://example.com", 600);
        let clear_cookie = super::build_login_attempt_cookie("", "https://example.com", 0);

        assert_eq!(set_cookie.path(), clear_cookie.path());
        assert_eq!(
            clear_cookie.max_age(),
            Some(cookie::time::Duration::seconds(0))
        );
    }

    #[test]
    fn test_valid_response_type_is_accepted() {
        assert!(super::validate_response_type("code").is_ok());
    }

    #[test]
    fn test_invalid_response_type_is_rejected() {
        let err = super::validate_response_type("token").unwrap_err();
        assert_eq!(err.error, OAuthErrorCode::UnsupportedResponseType);
    }

    #[test]
    fn test_empty_response_type_is_rejected() {
        assert!(super::validate_response_type("").is_err());
    }

    #[test]
    fn test_response_type_rejects_similar_values() {
        assert!(super::validate_response_type("Code").is_err());
        assert!(super::validate_response_type("CODE").is_err());
        assert!(super::validate_response_type("code ").is_err());
        assert!(super::validate_response_type("token").is_err());
        assert!(super::validate_response_type("code token").is_err());
    }

    #[test]
    fn test_code_challenge_rejects_invalid_base64() {
        // Contains characters not valid in base64url (e.g. `!` and `@`)
        let err = super::validate_code_challenge("not!valid@base64").unwrap_err();
        assert_eq!(err.error, OAuthErrorCode::InvalidRequest);
    }

    #[test]
    fn test_code_challenge_rejects_incorrect_length() {
        use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
        // Valid base64url but decodes to 16 bytes instead of the required 32
        let short = BASE64_URL_SAFE_NO_PAD.encode([0u8; 16]);
        let err = super::validate_code_challenge(&short).unwrap_err();
        assert_eq!(err.error, OAuthErrorCode::InvalidRequest);
    }

    #[test]
    fn test_code_challenge_accepts_valid_input() {
        use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
        let short = BASE64_URL_SAFE_NO_PAD.encode([0u8; 32]);
        assert!(super::validate_code_challenge(&short).is_ok());
    }

    /// Create a mock context and ApiUserInfo for `should_provide_idp_token` tests.
    async fn mock_should_provide_idp_token_ctx(
        user_permissions: Vec<VPermission>,
    ) -> (VContext<VPermission>, ApiUserInfo<VPermission>) {
        let mut access_group_store = MockAccessGroupStore::new();
        access_group_store
            .expect_list()
            .returning(|_, _| Ok(vec![]));

        let mut storage = MockStorage::new();
        storage.access_group_store = Some(Arc::new(access_group_store));

        let ctx = mock_context(Arc::new(storage)).await;
        let info = ApiUserInfo {
            user: ApiUser {
                id: TypedUuid::new_v4(),
                permissions: user_permissions.into(),
                groups: Default::default(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                deleted_at: None,
            },
            email: None,
            providers: vec![],
        };
        (ctx, info)
    }

    #[tokio::test]
    async fn test_should_provide_idp_token_returns_true_when_requested_and_permitted() {
        let (ctx, info) =
            mock_should_provide_idp_token_ctx(vec![VPermission::RetrieveRemoteAccessToken]).await;
        let result = should_provide_idp_token(&ctx, true, &info).await;
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_should_provide_idp_token_returns_false_when_not_requested() {
        let (ctx, info) =
            mock_should_provide_idp_token_ctx(vec![VPermission::RetrieveRemoteAccessToken]).await;

        // Even with the permission, if not requested the token is not returned
        let result = should_provide_idp_token(&ctx, false, &info).await;
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_should_provide_idp_token_returns_false_when_permission_missing() {
        // User has some permissions but not RetrieveRemoteAccessToken
        let (ctx, info) = mock_should_provide_idp_token_ctx(vec![VPermission::CreateApiUser]).await;
        let result = should_provide_idp_token(&ctx, true, &info).await;
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_should_provide_idp_token_returns_false_when_no_permissions() {
        let (ctx, info) = mock_should_provide_idp_token_ctx(vec![]).await;
        let result = should_provide_idp_token(&ctx, true, &info).await;
        assert!(!result.unwrap());
    }

    /// Set up mock storage for `complete_exchange` tests. The registered user will
    /// have the given `user_permissions`.
    fn mock_exchange_storage(user_permissions: Vec<VPermission>) -> MockStorage {
        // ApiUserProviderStore: list returns empty (new user), upsert returns a provider
        let mut provider_store = MockApiUserProviderStore::new();
        provider_store
            .expect_list()
            .returning(move |_, _| Ok(vec![]));
        provider_store
            .expect_upsert()
            .returning(move |p: NewApiUserProvider| {
                Ok(ApiUserProvider {
                    id: p.id,
                    user_id: p.user_id,
                    provider: p.provider,
                    provider_id: p.provider_id,
                    emails: p.emails,
                    display_names: p.display_names,
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    deleted_at: None,
                })
            });

        // ApiUserStore: upsert creates a user with the specified permissions
        let mut user_store = MockApiUserStore::new();
        user_store
            .expect_upsert()
            .returning(move |u: NewApiUser<VPermission>| {
                Ok(ApiUserInfo {
                    user: ApiUser {
                        id: u.id,
                        permissions: user_permissions.clone().into(),
                        groups: u.groups,
                        created_at: Utc::now(),
                        updated_at: Utc::now(),
                        deleted_at: None,
                    },
                    email: None,
                    providers: vec![],
                })
            });

        // MapperStore: list returns empty (no mappers configured)
        let mut mapper_store = MockMapperStore::new();
        mapper_store.expect_list().returning(|_, _| Ok(vec![]));

        // AccessTokenStore: upsert returns a token
        let mut access_token_store = MockAccessTokenStore::new();
        access_token_store.expect_upsert().returning(|token| {
            Ok(AccessToken {
                id: token.id,
                user_id: token.user_id,
                revoked_at: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
        });

        // AccessGroupStore: list returns empty (no groups configured)
        let mut access_group_store = MockAccessGroupStore::new();
        access_group_store
            .expect_list()
            .returning(|_, _| Ok(vec![]));

        let mut storage = MockStorage::new();
        storage.api_user_provider_store = Some(Arc::new(provider_store));
        storage.api_user_store = Some(Arc::new(user_store));
        storage.mapper_store = Some(Arc::new(mapper_store));
        storage.access_token_store = Some(Arc::new(access_token_store));
        storage.access_group_store = Some(Arc::new(access_group_store));
        storage
    }

    fn mock_user_info_with_idp_token() -> UserInfo {
        UserInfo {
            external_id: ExternalUserId::Google("test-google-id".to_string()),
            verified_emails: vec!["user@example.com".to_string()],
            display_name: Some("Test User".to_string()),
            idp_token: Some(SecretBox::from("secret-upstream-token")),
        }
    }

    fn mock_completed_attempt() -> LoginAttempt {
        LoginAttempt {
            id: TypedUuid::new_v4(),
            attempt_state: LoginAttemptState::Complete,
            client_id: TypedUuid::new_v4(),
            redirect_uri: Some("https://example.com/callback".to_string()),
            state: Some("test-state".to_string()),
            pkce_challenge: Some("test-challenge".to_string()),
            pkce_challenge_method: Some("S256".to_string()),
            authz_code: Some("test-code".to_string()),
            expires_at: Some(Utc::now().add(TimeDelta::try_seconds(300).unwrap())),
            error: None,
            provider: "google".to_string(),
            provider_pkce_verifier: None,
            provider_authz_code: Some("remote-code".to_string()),
            provider_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            scope: "user:info:r".to_string(),
            grant_type: "authorization_code".to_string(),
            device_code: None,
            provider_device_code: None,
        }
    }

    #[tokio::test]
    async fn test_exchange_returns_idp_token_when_requested_and_permitted() {
        let storage = mock_exchange_storage(vec![
            VPermission::CreateAccessToken,
            VPermission::RetrieveRemoteAccessToken,
        ]);
        let ctx = mock_context(Arc::new(storage)).await;
        let attempt = mock_completed_attempt();
        let info = mock_user_info_with_idp_token();
        let provider = NoOpOAuthProvider::new();

        let response = complete_exchange(
            &ctx,
            info,
            &provider,
            &attempt,
            true,
            Some("secret-upstream-token".to_string()),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(
            response.idp_token,
            Some("secret-upstream-token".to_string()),
            "IdP token must be returned when requested and user has RetrieveRemoteAccessToken"
        );
    }

    #[tokio::test]
    async fn test_exchange_omits_idp_token_when_permission_missing() {
        let storage = mock_exchange_storage(vec![
            VPermission::CreateAccessToken,
            // Notably missing: VPermission::RetrieveRemoteAccessToken
        ]);
        let ctx = mock_context(Arc::new(storage)).await;
        let attempt = mock_completed_attempt();
        let info = mock_user_info_with_idp_token();
        let provider = NoOpOAuthProvider::new();

        let response = complete_exchange(
            &ctx,
            info,
            &provider,
            &attempt,
            true,
            Some("secret-upstream-token".to_string()),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(
            response.idp_token, None,
            "IdP token must NOT be returned when user lacks RetrieveRemoteAccessToken"
        );
    }

    /// Verifies that the `state` parameter survives the authorization code flow
    /// round trip without modification, as required by RFC 6749 §4.1.1. The
    /// authorization server MUST return the exact `state` value that the client
    /// originally provided. This test uses a state value containing characters
    /// that require percent-encoding (`+`, `/`, spaces, `&`, `=`) to ensure
    /// they are encoded exactly once in the final redirect URL and decoded back
    /// to the original value by standard URL parsing.
    #[tokio::test]
    async fn test_state_roundtrip_preserves_special_characters() {
        let attempt_id = TypedUuid::new_v4();
        let client_id = TypedUuid::new_v4();
        let original_state = "random+state/with spaces&special=chars";

        // State is now stored as-is (no pre-encoding). callback_url() handles
        // percent-encoding when building the redirect URL.
        let attempt = LoginAttempt {
            id: attempt_id,
            attempt_state: LoginAttemptState::New,
            client_id,
            redirect_uri: Some("https://test.oxeng.dev/callback".to_string()),
            state: Some(original_state.to_string()),
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
            grant_type: "authorization_code".to_string(),
            device_code: None,
            provider_device_code: None,
        };

        let mut attempt_store = MockLoginAttemptStore::new();
        let original_attempt = attempt.clone();
        attempt_store
            .expect_get()
            .with(eq(attempt.id))
            .returning(move |_| Ok(Some(original_attempt.clone())));

        attempt_store
            .expect_update_if_state()
            .withf(|attempt, expected| {
                attempt.attempt_state == LoginAttemptState::RemoteAuthenticated
                    && *expected == LoginAttemptState::New
            })
            .returning(move |arg, _| {
                let mut returned = attempt.clone();
                returned.attempt_state = arg.attempt_state;
                returned.authz_code = arg.authz_code;
                Ok(returned)
            });

        let mut storage = MockStorage::new();
        storage.login_attempt_store = Some(Arc::new(attempt_store));
        storage.oauth_client_store = Some(mock_oauth_client_store_for_callback(
            client_id,
            "https://test.oxeng.dev/callback",
        ));
        let ctx = mock_context(Arc::new(storage)).await;

        let location =
            authz_code_callback_op_inner(&ctx, &attempt_id, Some("remote-code".to_string()), None)
                .await
                .unwrap();

        let url = url::Url::parse(&location).unwrap();
        let returned_state = url
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
            .expect("state parameter must be present in callback URL");

        // RFC 6749 §4.1.1: the state value MUST be returned to the client
        // unmodified. The client sent `original_state`, so it should get back
        // exactly `original_state` after URL decoding.
        assert_eq!(
            original_state, returned_state,
            "RFC 6749 §4.1.1 requires the state parameter to be returned unmodified. \
             The client sent {:?} but received {:?}.",
            original_state, returned_state,
        );
    }

    /// RFC 6749 §5.1 requires the token response to include a `scope` parameter
    /// when the issued scope differs from what the client requested, and recommends
    /// it in all cases. The token response should echo back the scope that was
    /// granted so clients can verify what permissions they received.
    #[tokio::test]
    async fn test_exchange_response_includes_scope() {
        let storage = mock_exchange_storage(vec![VPermission::CreateAccessToken]);
        let ctx = mock_context(Arc::new(storage)).await;
        let attempt = mock_completed_attempt(); // scope = "user:info:r"
        let info = UserInfo {
            external_id: ExternalUserId::Google("test-google-id".to_string()),
            verified_emails: vec!["user@example.com".to_string()],
            display_name: Some("Test User".to_string()),
            idp_token: None,
        };

        let provider = NoOpOAuthProvider::new();

        let response = complete_exchange(&ctx, info, &provider, &attempt, false, None)
            .await
            .unwrap()
            .0;

        // Serialize the response to JSON and check for a "scope" field.
        // Per RFC 6749 §5.1, the authorization server SHOULD include the scope
        // in the token response, and MUST include it if it differs from what
        // the client requested.
        let json = serde_json::to_value(&response).unwrap();
        assert!(
            json.get("scope").is_some(),
            "Token response must include a 'scope' field per RFC 6749 §5.1. \
             The login attempt had scope {:?} but the response was: {}",
            attempt.scope,
            serde_json::to_string_pretty(&json).unwrap(),
        );
    }

    #[tokio::test]
    async fn test_exchange_omits_idp_token_when_not_requested() {
        let storage = mock_exchange_storage(vec![
            VPermission::CreateAccessToken,
            VPermission::RetrieveRemoteAccessToken,
        ]);
        let ctx = mock_context(Arc::new(storage)).await;
        let attempt = mock_completed_attempt();
        let info = mock_user_info_with_idp_token();
        let provider = NoOpOAuthProvider::new();

        let response = complete_exchange(
            &ctx,
            info,
            &provider,
            &attempt,
            false,
            Some("secret-upstream-token".to_string()),
        )
        .await
        .unwrap()
        .0;

        assert_eq!(
            response.idp_token, None,
            "IdP token must NOT be returned when not requested, even with permission"
        );
    }

    /// The OAuth callback (`authz_code_callback_op_inner`) redirects the user to
    /// the `redirect_uri` stored in the login attempt without re-validating it
    /// against the OAuth client's currently registered redirect URIs. This means
    /// that if a redirect URI is removed from the client between the authorization
    /// request and the callback, the redirect still proceeds to the now-deregistered
    /// URI (a TOCTOU gap). The callback should re-validate the redirect URI before
    /// using it.
    #[tokio::test]
    async fn test_callback_revalidates_redirect_uri() {
        let client_id = TypedUuid::new_v4();
        // The login attempt was created with a redirect_uri that was valid at the
        // time, but has since been removed from the client's allowed list.
        let deregistered_uri = "https://formerly-valid.example.com/callback";

        let attempt_id = TypedUuid::new_v4();
        let attempt = LoginAttempt {
            id: attempt_id,
            attempt_state: LoginAttemptState::New,
            client_id,
            redirect_uri: Some(deregistered_uri.to_string()),
            state: Some("test-state".to_string()),
            pkce_challenge: Some("test-challenge".to_string()),
            pkce_challenge_method: Some("S256".to_string()),
            authz_code: None,
            expires_at: None,
            error: None,
            provider: "google".to_string(),
            provider_pkce_verifier: None,
            provider_authz_code: None,
            provider_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            scope: "user:info:r".to_string(),
            grant_type: "authorization_code".to_string(),
            device_code: None,
            provider_device_code: None,
        };

        let mut attempt_store = MockLoginAttemptStore::new();
        let original_attempt = attempt.clone();
        attempt_store
            .expect_get()
            .with(eq(attempt_id))
            .returning(move |_| Ok(Some(original_attempt.clone())));

        attempt_store
            .expect_update_if_state()
            .withf(|attempt, expected| {
                attempt.attempt_state == LoginAttemptState::RemoteAuthenticated
                    && *expected == LoginAttemptState::New
            })
            .returning(move |arg, _| {
                let mut returned = attempt.clone();
                returned.attempt_state = arg.attempt_state;
                returned.authz_code = arg.authz_code;
                Ok(returned)
            });

        // Configure the OAuth client with NO registered redirect URIs,
        // simulating that the URI was removed after the login attempt
        // was created.
        let mut client_store = MockOAuthClientStore::new();
        client_store
            .expect_get()
            .with(eq(client_id), eq(false))
            .returning(move |_, _| {
                Ok(Some(OAuthClient {
                    id: client_id,
                    secrets: vec![],
                    redirect_uris: vec![], // No registered URIs
                    created_at: Utc::now(),
                    deleted_at: None,
                }))
            });

        let mut storage = MockStorage::new();
        storage.login_attempt_store = Some(Arc::new(attempt_store));
        storage.oauth_client_store = Some(Arc::new(client_store));
        let ctx = mock_context(Arc::new(storage)).await;

        // The callback should reject the request because the redirect URI is no
        // longer registered on the OAuth client.
        let err = authz_code_callback_op_inner(
            &ctx,
            &attempt_id,
            Some("remote-code".to_string()),
            None,
        )
        .await
        .expect_err(
            "Callback should fail when the redirect URI is no longer registered on the client",
        );

        assert_eq!(
            err.status_code,
            StatusCode::UNAUTHORIZED,
            "Expected 401 when redirect URI is deregistered, got {}",
            err.status_code,
        );
    }

    /// The authorization code lookup should filter by provider so that a code
    /// issued for one provider (e.g. Google) is not returned when exchanging
    /// against a different provider (e.g. GitHub). This is a defense-in-depth
    /// measure — codes should be scoped to their issuing provider at the query
    /// level rather than relying solely on post-lookup validation.
    #[tokio::test]
    async fn test_code_lookup_filters_by_provider() {
        // Create a login attempt that was authenticated via Google
        let google_attempt = LoginAttempt {
            id: TypedUuid::new_v4(),
            attempt_state: LoginAttemptState::RemoteAuthenticated,
            client_id: TypedUuid::new_v4(),
            redirect_uri: Some("https://test.oxeng.dev/callback".to_string()),
            state: Some("test-state".to_string()),
            pkce_challenge: Some("test-challenge".to_string()),
            pkce_challenge_method: Some("S256".to_string()),
            authz_code: Some("authz-code-for-google".to_string()),
            expires_at: None,
            error: None,
            provider: "google".to_string(),
            provider_pkce_verifier: None,
            provider_authz_code: Some("remote-code".to_string()),
            provider_error: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            scope: "user:info:r".to_string(),
            grant_type: "authorization_code".to_string(),
            device_code: None,
            provider_device_code: None,
        };

        // The mock store simulates a real database: it only returns the
        // attempt when the filter's provider field matches.
        let returned_attempt = google_attempt.clone();
        let mut attempt_store = MockLoginAttemptStore::new();
        attempt_store.expect_list().returning(move |filter, _| {
            let dominated = &returned_attempt;
            if let Some(providers) = &filter.provider {
                if providers.iter().any(|p| p == &dominated.provider) {
                    Ok(vec![dominated.clone()])
                } else {
                    Ok(vec![])
                }
            } else {
                Ok(vec![dominated.clone()])
            }
        });

        let mut storage = MockStorage::new();
        storage.login_attempt_store = Some(Arc::new(attempt_store));
        let ctx = mock_context(Arc::new(storage)).await;

        // Looking up the code for the correct provider should succeed.
        let google_result = ctx
            .login
            .get_login_attempt_for_code("authz-code-for-google", "google")
            .await
            .unwrap();
        assert!(
            google_result.is_some(),
            "Code lookup for the issuing provider must return the attempt"
        );

        // Looking up the same code but for a different provider should return
        // None, because the provider filter now scopes the query.
        let github_result = ctx
            .login
            .get_login_attempt_for_code("authz-code-for-google", "github")
            .await
            .unwrap();
        assert!(
            github_result.is_none(),
            "Code lookup must not return an attempt for a different provider. \
             Expected None, but got {:?}.",
            github_result.as_ref().map(|a| &a.provider),
        );
    }

    /// When a login attempt has no scope (`None`), the minted JWT must have
    /// `scp: ""` (empty string) which the caller-resolution layer interprets as
    /// `BasePermissions::Restricted` with an empty permission set (no permissions).
    #[tokio::test]
    async fn test_null_scope_produces_no_permission_token() {
        let storage = mock_exchange_storage(vec![VPermission::CreateAccessToken]);
        let ctx = mock_context(Arc::new(storage)).await;

        let mut attempt = mock_completed_attempt();
        attempt.scope = String::new();

        let info = UserInfo {
            external_id: ExternalUserId::Google("test-google-id".to_string()),
            verified_emails: vec!["user@example.com".to_string()],
            display_name: Some("Test User".to_string()),
            idp_token: None,
        };
        let provider = NoOpOAuthProvider::new();

        let response = complete_exchange(&ctx, info, &provider, &attempt, false, None)
            .await
            .unwrap()
            .0;

        assert_eq!(
            response.scope, "",
            "Exchange response scope must be empty when the login attempt has no scope",
        );

        let jwt = Jwt::<Claims>::new(&ctx, &response.access_token)
            .await
            .expect("JWT should decode successfully");

        assert_eq!(
            jwt.claims.scp,
            Vec::<String>::new(),
            "JWT scp claim must be an empty list (implying no permissions) when no scope was requested",
        );
    }

    /// When a login attempt specifies the special `"full"` scope, the minted JWT
    /// must carry `scp: "full"` which the caller-resolution layer interprets as
    /// `BasePermissions::Full` (all permissions).
    #[tokio::test]
    async fn test_full_scope_produces_full_permission_token() {
        let storage = mock_exchange_storage(vec![VPermission::CreateAccessToken]);
        let ctx = mock_context(Arc::new(storage)).await;

        let mut attempt = mock_completed_attempt();
        attempt.scope = "full".to_string();

        let info = UserInfo {
            external_id: ExternalUserId::Google("test-google-id".to_string()),
            verified_emails: vec!["user@example.com".to_string()],
            display_name: Some("Test User".to_string()),
            idp_token: None,
        };
        let provider = NoOpOAuthProvider::new();

        let response = complete_exchange(&ctx, info, &provider, &attempt, false, None)
            .await
            .unwrap()
            .0;

        assert_eq!(
            response.scope, "full",
            "Exchange response must echo back the full scope",
        );

        let jwt = Jwt::<Claims>::new(&ctx, &response.access_token)
            .await
            .expect("JWT should decode successfully");

        assert_eq!(
            jwt.claims.scp,
            vec!["full".to_string()],
            "JWT scp claim must contain 'full' when the full scope was requested",
        );
    }

    /// When a login attempt specifies an explicit scope, the minted JWT must
    /// carry that scope in the `scp` claim so that caller resolution treats it
    /// as `BasePermissions::Restricted`.
    #[tokio::test]
    async fn test_explicit_scope_produces_restricted_token() {
        let storage = mock_exchange_storage(vec![VPermission::CreateAccessToken]);
        let ctx = mock_context(Arc::new(storage)).await;

        let mut attempt = mock_completed_attempt();
        attempt.scope = "user:info:r".to_string();

        let info = UserInfo {
            external_id: ExternalUserId::Google("test-google-id".to_string()),
            verified_emails: vec!["user@example.com".to_string()],
            display_name: Some("Test User".to_string()),
            idp_token: None,
        };
        let provider = NoOpOAuthProvider::new();

        let response = complete_exchange(&ctx, info, &provider, &attempt, false, None)
            .await
            .unwrap()
            .0;

        assert_eq!(
            response.scope, "user:info:r",
            "Exchange response must echo back the explicit scope",
        );

        let jwt = Jwt::<Claims>::new(&ctx, &response.access_token)
            .await
            .expect("JWT should decode successfully");

        assert_eq!(
            jwt.claims.scp,
            vec!["user:info:r".to_string()],
            "JWT scp claim must contain the requested scope when one was provided",
        );
    }
}
