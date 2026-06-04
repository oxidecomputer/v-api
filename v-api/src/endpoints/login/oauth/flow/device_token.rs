// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{TimeDelta, Utc};
use dropshot::{Body, HttpError, Method, Path, RequestContext, TypedBody};
use http::{HeaderMap, HeaderValue, Response, StatusCode, header};
use hyper::body::Bytes;
use newtype_uuid::TypedUuid;
use oauth2::{
    CsrfToken, EmptyExtraTokenFields, StandardTokenResponse, TokenResponse, basic::BasicTokenType,
};
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::ops::Add;
use tap::TapFallible;
use tracing::instrument;
use url::Url;
use v_model::{
    NewLoginAttempt, OAuthClientId,
    permissions::{AsScope, PermissionStorage},
};

use super::super::OAuthProviderNameParam;
use crate::endpoints::login::UserInfoProvider;
use crate::{
    context::ApiContext,
    endpoints::login::LoginError,
    error::ApiError,
    permissions::VAppPermission,
    response::internal_error,
    util::response::bad_request,
};

use super::complete_exchange;
use crate::endpoints::login::oauth::OAuthProviderDeviceInfo;

#[instrument(skip(rqctx), err(Debug))]
pub async fn get_device_provider_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<OAuthProviderNameParam>,
) -> Result<dropshot::HttpResponseOk<OAuthProviderDeviceInfo>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let path = path.into_inner();

    let provider = rqctx
        .v_ctx()
        .get_oauth_provider(&path.provider)
        .await
        .map_err(ApiError::OAuth)?;

    Ok(dropshot::HttpResponseOk(
        provider
            .device_code_flow_info()
            .cloned()
            .ok_or_else(|| bad_request("Provider does not support device clients"))?,
    ))
}

/// Request body for initiating a device authorization flow. The client sends its
/// `client_id` and an optional `scope`. The API server proxies the device
/// authorization request to the upstream provider and tracks it as a login attempt.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeviceAuthorizationRequest {
    pub client_id: TypedUuid<OAuthClientId>,
    pub scope: Option<String>,
}

/// Subset of the upstream device authorization response that we forward to the
/// client (RFC 8628 §3.2).
#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct DeviceAuthorizationResponse {
    /// The device verification code (opaque to the end-user).
    pub device_code: String,
    /// The end-user verification code displayed to the user.
    pub user_code: String,
    /// The end-user verification URI on the authorization server.
    #[serde(alias = "verification_url")]
    pub verification_uri: Url,
    /// Optional verification URI that includes the user_code.
    #[serde(default)]
    pub verification_uri_complete: Option<Url>,
    /// Lifetime in seconds of the device_code and user_code.
    #[serde(default)]
    pub expires_in: Option<u32>,
    /// Minimum polling interval in seconds (default 5 per RFC 8628 §3.5).
    #[serde(default)]
    pub interval: Option<u32>,
}

/// Body sent to the upstream provider's device authorization endpoint.
#[derive(Debug, Serialize)]
struct UpstreamDeviceAuthzRequest {
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

/// Initiate a device authorization flow by proxying the request to the upstream
/// OAuth provider. On success a `LoginAttempt` is created (state = New) and the
/// upstream device authorization response is returned to the caller.
#[instrument(skip(rqctx, body), err(Debug))]
pub async fn device_authz_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<OAuthProviderNameParam>,
    body: TypedBody<DeviceAuthorizationRequest>,
) -> Result<Response<Body>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let ctx = rqctx.v_ctx();
    let path = path.into_inner();
    let body = body.into_inner();

    let provider = ctx
        .get_oauth_provider(&path.provider)
        .await
        .map_err(ApiError::OAuth)?;

    let device_info = provider
        .device_code_flow_info()
        .ok_or_else(|| bad_request("Provider does not support device code flow"))?;

    // Validate the client_id. In the future we may tie maximum scopes to a
    // client as well
    let _client = ctx
        .oauth
        .get_oauth_client(&ctx.builtin_registration_user(), &body.client_id)
        .await
        .map_err(|_| bad_request("Unknown client id"))?;

    // An omitted scope means no permissions
    let scope = body.scope.unwrap_or_default();
    if let Err(err) = T::from_scope_arg(&scope) {
        tracing::warn!(?err, ?scope, "Client submitted an invalid scope");
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_scope",
            Some(format!("Invalid scope: {}", scope)),
        ));
    }

    // Proxy the device authorization request to the upstream provider
    let client = reqwest::Client::new();
    let upstream_request = UpstreamDeviceAuthzRequest {
        client_id: device_info.remote.client_id.clone(),
        scope: Some(provider.default_scopes().join(" ")),
    };

    tracing::trace!(
        ?upstream_request,
        "Sending device authorization request to upstream provider"
    );

    let response = client
        .request(Method::POST, &device_info.remote.device_code_endpoint)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, "application/json")
        .body(serde_urlencoded::to_string(&upstream_request).unwrap())
        .send()
        .await
        .tap_err(|err| tracing::error!(?err, "Device authorization request failed"))
        .map_err(internal_error)?;

    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.bytes().await.map_err(internal_error)?;

    if !status.is_success() {
        tracing::debug!(
            provider = ?path.provider,
            ?status,
            "Upstream device authorization returned error"
        );
        return Ok(proxy_upstream_response(bytes, headers, status));
    }

    // Parse the upstream device authorization response
    let device_authz: DeviceAuthorizationResponse =
        serde_json::from_slice(&bytes).map_err(|err| {
            let body = String::from_utf8_lossy(&bytes);
            tracing::error!(
                ?err,
                ?body,
                "Failed to parse upstream device authorization response"
            );
            internal_error("Failed to parse upstream device authorization response")
        })?;

    // Create a LoginAttempt to track this device flow. Device flow has no
    // redirect_uri — the token is returned directly via the exchange endpoint.
    let mut attempt = NewLoginAttempt::new(
        provider.name().to_string(),
        body.client_id,
        None,
        scope,
        "urn:ietf:params:oauth:grant-type:device_code".to_string(),
    )
    .map_err(|err| {
        tracing::error!(?err, "Failed to construct login attempt");
        internal_error("Failed to construct login attempt")
    })?;

    // Set expiration from upstream response or default to 10 minutes
    let expires_in_secs = device_authz.expires_in.unwrap_or(600);
    attempt.expires_at =
        Some(Utc::now().add(TimeDelta::try_seconds(expires_in_secs as i64).unwrap()));

    // Store the upstream device_code privately — the caller never sees this.
    attempt.provider_device_code = Some(device_authz.device_code.clone());

    // Generate a v-api opaque device code that the caller will use to poll the
    // exchange endpoint.
    let vapi_device_code = CsrfToken::new_random().secret().to_string();
    attempt.device_code = Some(vapi_device_code.clone());

    let attempt = ctx
        .login
        .create_login_attempt(attempt)
        .await
        .map_err(|err| {
            tracing::error!(?err, "Failed to store login attempt");
            internal_error("Failed to store login attempt")
        })?;

    tracing::info!(?attempt.id, "Created device flow login attempt");

    // Return the response to the client, replacing the upstream device_code with
    // our v-api-issued code. The user_code and verification_uri are passed through
    // so the end-user can complete the browser-based authorization.
    let client_response = DeviceAuthorizationResponse {
        device_code: vapi_device_code,
        user_code: device_authz.user_code,
        verification_uri: device_authz.verification_uri,
        verification_uri_complete: device_authz.verification_uri_complete,
        expires_in: device_authz.expires_in,
        interval: device_authz.interval,
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&client_response).unwrap().into())?)
}

/// Request body for the device token exchange. The client polls this endpoint
/// with the device_code received from the authorization step.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeviceTokenExchangeRequest {
    pub client_id: TypedUuid<OAuthClientId>,
    pub device_code: String,
    pub grant_type: String,
}

/// Body sent to the upstream provider's token endpoint during device code exchange.
#[derive(Serialize)]
struct UpstreamDeviceTokenRequest {
    client_id: String,
    device_code: String,
    grant_type: String,
    client_secret: String,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct ProxyTokenError {
    error: String,
    error_description: Option<String>,
    error_uri: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct ProxyTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<i64>,
    pub refresh_token: Option<String>,
    pub scopes: Option<Vec<String>>,
}

/// Exchange a device code for an access token. This endpoint is polled by the
/// client. Upstream pending/slow_down responses are proxied through directly.
/// On success the login attempt is completed, the user is registered, and a
/// v-api access token is minted.
#[instrument(skip(rqctx, body), err(Debug))]
pub async fn exchange_device_token_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<OAuthProviderNameParam>,
    body: TypedBody<DeviceTokenExchangeRequest>,
) -> Result<Response<Body>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let ctx = rqctx.v_ctx();
    let path = path.into_inner();
    let body = body.into_inner();

    let provider = ctx
        .get_oauth_provider(&path.provider)
        .await
        .map_err(ApiError::OAuth)?;

    let device_info = provider
        .device_code_flow_info()
        .ok_or_else(|| bad_request("Provider does not support device code flow"))?;

    tracing::debug!(provider = ?provider.name(), "Acquired OAuth provider for device token exchange");

    // Validate grant_type per RFC 8628 §3.4
    if !validate_device_grant_type(&body.grant_type) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            Some("grant_type must be urn:ietf:params:oauth:grant-type:device_code".to_string()),
        ));
    }

    // Look up the login attempt by the v-api-issued device code and client_id.
    let attempt = ctx
        .login
        .get_login_attempt_for_device_code(&body.device_code, &body.client_id)
        .await
        .map_err(|err| {
            tracing::error!(?err, "Failed to look up device login attempt");
            internal_error("Failed to look up login attempt")
        })?
        .ok_or_else(|| bad_request("Unknown device code or client id"))?;

    // Verify the attempt is still in the New state
    if attempt.attempt_state != v_model::schema_ext::LoginAttemptState::New {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            Some("Device code has already been exchanged".to_string()),
        ));
    }

    // Check expiration - An attempt without an expiration is by default
    // expired.
    // TODO: Change expires_at to be non-optional. A login attempt should always
    // have an expiration.
    if attempt.expires_at.map(|t| t <= Utc::now()).unwrap_or(true) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "expired_token",
            Some("The device code has expired".to_string()),
        ));
    }

    // Retrieve the real upstream device_code from the login attempt and proxy
    // the token exchange to the upstream provider.
    let upstream_device_code = attempt
        .provider_device_code
        .as_deref()
        .ok_or_else(|| {
            tracing::error!("Login attempt is missing upstream device code");
            internal_error("Login attempt is missing upstream device code")
        })?
        .to_string();

    let upstream_request = UpstreamDeviceTokenRequest {
        client_id: device_info.remote.client_id.clone(),
        device_code: upstream_device_code,
        grant_type: body.grant_type.clone(),
        client_secret: device_info
            .remote
            .client_secret
            .0
            .expose_secret()
            .to_string(),
    };

    let client = reqwest::Client::new();
    let response = client
        .request(Method::POST, &device_info.remote.token_endpoint)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::ACCEPT, HeaderValue::from_static("application/json"))
        .body(serde_urlencoded::to_string(&upstream_request).unwrap())
        .send()
        .await
        .tap_err(|err| tracing::error!(?err, "Token exchange request failed"))
        .map_err(internal_error)?;

    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.bytes().await.map_err(internal_error)?;

    if !status.is_success() {
        // Non-success status — proxy the upstream error through (includes
        // authorization_pending, slow_down, etc.)
        tracing::debug!(
            provider = ?path.provider,
            ?status,
            "Received error response from upstream provider during device exchange"
        );
        return Ok(proxy_upstream_response(bytes, headers, status));
    }

    // Try to parse as a successful token response
    let parsed: Result<
        StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
        serde_json::Error,
    > = serde_json::from_slice(&bytes);

    match parsed {
        Ok(parsed) => {
            // Success! The user has completed the device authorization.

            // Claim the login attempt (New -> Complete)
            let attempt = ctx
                .login
                .claim_device_login_attempt(attempt)
                .await
                .map_err(|err| {
                    tracing::warn!(?err, "Failed to claim device login attempt");
                    internal_error("Failed to claim login attempt")
                })?;

            // Fetch user info from the upstream provider
            let info = provider
                .get_user_info(parsed.access_token().secret())
                .await
                .map_err(LoginError::UserInfo)
                .tap_err(|err| tracing::error!(?err, "Failed to look up user information"))?;

            tracing::debug!("Verified and validated OAuth user via device flow");

            let response = complete_exchange(ctx, info, &*provider, &attempt, false, None).await?;

            let exchange_response = response.0;

            tracing::trace!(
                ?exchange_response,
                "Received device authorization response from upstream provider"
            );

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(serde_json::to_string(&exchange_response).unwrap().into())?)
        }
        Err(_) => {
            // Could not parse as a token — might be a GitHub-style 200 error
            tracing::debug!("Failed to parse a success response from the remote token endpoint");

            Ok(handle_token_parse_failure(
                &path.provider.to_string(),
                bytes,
                headers,
                status,
            ))
        }
    }
}

/// Validate the grant_type for device code exchange per RFC 8628 §3.4.
fn validate_device_grant_type(grant_type: &str) -> bool {
    grant_type == "urn:ietf:params:oauth:grant-type:device_code"
}

/// Build a JSON error response body.
fn error_response(status: StatusCode, error: &str, description: Option<String>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_vec(&ProxyTokenError {
                error: error.to_string(),
                error_description: description,
                error_uri: None,
            })
            .unwrap()
            .into(),
        )
        .unwrap()
}

/// Headers that are safe to forward from an upstream OAuth provider response.
const FORWARDED_HEADERS: &[header::HeaderName] = &[header::CONTENT_TYPE];

/// Copy only allowlisted headers from an upstream response.
fn filter_upstream_headers(upstream: &HeaderMap) -> HeaderMap {
    let mut filtered = HeaderMap::new();
    for name in FORWARDED_HEADERS {
        if let Some(value) = upstream.get(name) {
            filtered.insert(name.clone(), value.clone());
        }
    }
    filtered
}

/// Build a response to the client by proxying an upstream provider's response.
fn proxy_upstream_response(bytes: Bytes, headers: HeaderMap, status: StatusCode) -> Response<Body> {
    let mut client_response = Response::new(Body::from(bytes));
    *client_response.headers_mut() = filter_upstream_headers(&headers);
    *client_response.status_mut() = status;
    client_response
}

/// Handle the case where the upstream provider returned a 200 status but the body
/// could not be parsed as a valid token response.
fn handle_token_parse_failure(
    provider_name: &str,
    bytes: Bytes,
    headers: HeaderMap,
    status: StatusCode,
) -> Response<Body> {
    let mut error_response = match serde_json::from_slice::<ProxyTokenError>(&bytes) {
        Ok(error) => {
            tracing::debug!(
                ?error,
                provider_name,
                "Parsed error response from OAuth provider"
            );

            let mut client_response = Response::new(Body::from(bytes));
            *client_response.headers_mut() = filter_upstream_headers(&headers);
            *client_response.status_mut() = status;
            client_response
        }
        Err(_) => {
            tracing::warn!("Remote OAuth provider returned a response that we do not understand");

            Response::new(
                serde_json::to_vec(&ProxyTokenError {
                    error: "access_denied".to_string(),
                    error_description: Some(format!(
                        "{} returned a malformed response",
                        provider_name
                    )),
                    error_uri: None,
                })
                .unwrap()
                .into(),
            )
        }
    };

    *error_response.status_mut() = StatusCode::BAD_REQUEST;
    error_response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    error_response
}

#[cfg(test)]
mod tests {
    use http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{self, HeaderName, SET_COOKIE},
    };
    use hyper::body::Bytes;

    use super::{handle_token_parse_failure, proxy_upstream_response, validate_device_grant_type};

    #[test]
    fn test_upstream_set_cookie_is_stripped_from_error_response() {
        let mut upstream_headers = HeaderMap::new();
        upstream_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        upstream_headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("session=malicious-value; Path=/; HttpOnly"),
        );

        let body = Bytes::from_static(b"{\"error\": \"authorization_pending\"}");
        let response = proxy_upstream_response(body, upstream_headers, StatusCode::FORBIDDEN);

        assert!(
            response.headers().get(SET_COOKIE).is_none(),
            "Upstream Set-Cookie header must not be forwarded to the client"
        );
        assert!(
            response.headers().get(header::CONTENT_TYPE).is_some(),
            "Content-Type should be forwarded from upstream"
        );
    }

    #[test]
    fn test_upstream_cors_headers_are_stripped_from_error_response() {
        let mut upstream_headers = HeaderMap::new();
        upstream_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        upstream_headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        upstream_headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );

        let body = Bytes::from_static(b"{\"error\": \"authorization_pending\"}");
        let response = proxy_upstream_response(body, upstream_headers, StatusCode::BAD_REQUEST);

        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none(),
            "Upstream CORS header must not be forwarded to the client"
        );
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none(),
            "Upstream CORS credentials header must not be forwarded to the client"
        );
    }

    #[test]
    fn test_upstream_location_and_framing_headers_are_stripped_from_token_parse_failure() {
        let mut upstream_headers = HeaderMap::new();
        upstream_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        upstream_headers.insert(
            header::LOCATION,
            HeaderValue::from_static("https://evil.example.com/phishing"),
        );
        upstream_headers.insert(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("ALLOW-FROM https://evil.example.com"),
        );

        let body = Bytes::from_static(
            b"{\"error\": \"slow_down\", \"error_description\": null, \"error_uri\": null}",
        );
        let response =
            handle_token_parse_failure("test-provider", body, upstream_headers, StatusCode::OK);

        assert!(
            response.headers().get(header::LOCATION).is_none(),
            "Upstream Location header must not be forwarded to the client"
        );
        assert!(
            response.headers().get("x-frame-options").is_none(),
            "Upstream X-Frame-Options header must not be forwarded to the client"
        );
        assert!(
            response.headers().get(header::CONTENT_TYPE).is_some(),
            "Content-Type should be present on the response"
        );
    }

    #[test]
    fn test_upstream_set_cookie_is_stripped_from_token_parse_failure() {
        let mut upstream_headers = HeaderMap::new();
        upstream_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        upstream_headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("tracking=evil-tracker; Domain=.our-api.com; Path=/"),
        );

        let body = Bytes::from_static(
            b"{\"error\": \"authorization_pending\", \"error_description\": null, \"error_uri\": null}",
        );
        let response =
            handle_token_parse_failure("test-provider", body, upstream_headers, StatusCode::OK);

        assert!(
            response.headers().get(SET_COOKIE).is_none(),
            "Upstream Set-Cookie header must not be forwarded via token parse failure path"
        );
    }

    #[test]
    fn test_valid_device_grant_type_is_accepted() {
        assert!(validate_device_grant_type(
            "urn:ietf:params:oauth:grant-type:device_code"
        ));
    }

    #[test]
    fn test_invalid_device_grant_type_is_rejected() {
        assert!(!validate_device_grant_type("authorization_code"));
    }

    #[test]
    fn test_empty_device_grant_type_is_rejected() {
        assert!(!validate_device_grant_type(""));
    }

    #[test]
    fn test_device_grant_type_rejects_similar_values() {
        assert!(!validate_device_grant_type("device_code"));
        assert!(!validate_device_grant_type(
            "urn:ietf:params:oauth:grant-type:device_Code"
        ));
        assert!(!validate_device_grant_type(
            "urn:ietf:params:oauth:grant-type:authorization_code"
        ));
    }
}
