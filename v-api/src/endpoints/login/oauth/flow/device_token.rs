// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{DateTime, Utc};
use dropshot::{Body, HttpError, HttpResponseOk, Method, Path, RequestContext, TypedBody};
use http::{header, HeaderMap, HeaderValue, Response, StatusCode};
use hyper::body::Bytes;
use oauth2::{basic::BasicTokenType, EmptyExtraTokenFields, StandardTokenResponse, TokenResponse};
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tap::TapFallible;
use tracing::instrument;
use v_model::permissions::PermissionStorage;

use super::super::OAuthProviderNameParam;
use crate::endpoints::login::UserInfoProvider;
use crate::{
    context::ApiContext,
    endpoints::login::{oauth::OAuthProviderDeviceInfo, LoginError},
    error::ApiError,
    permissions::VAppPermission,
    response::internal_error,
    util::response::bad_request,
};

#[instrument(skip(rqctx), err(Debug))]
pub async fn get_device_provider_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<OAuthProviderNameParam>,
) -> Result<HttpResponseOk<OAuthProviderDeviceInfo>, HttpError>
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
            .device_code_flow_info()
            .cloned()
            .ok_or_else(|| bad_request("Provider does not support device clients"))?,
    ))
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct AccessTokenExchangeRequest {
    pub device_code: String,
    pub grant_type: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct AccessTokenExchange {
    provider: ProviderTokenExchange,
    expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct ProviderTokenExchange {
    client_id: String,
    device_code: String,
    grant_type: String,
    client_secret: String,
}

impl AccessTokenExchange {
    pub fn new(req: AccessTokenExchangeRequest, provider: &OAuthProviderDeviceInfo) -> Self {
        Self {
            provider: ProviderTokenExchange {
                client_id: provider.remote_client_id.clone(),
                device_code: req.device_code,
                grant_type: req.grant_type,
                client_secret: provider.remote_client_secret.0.expose_secret().to_string(),
            },
            expires_at: req.expires_at,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct ProxyTokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<i64>,
    pub refresh_token: Option<String>,
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct ProxyTokenError {
    error: String,
    error_description: Option<String>,
    error_uri: Option<String>,
}

// Complete a device exchange request against the specified provider. This effectively proxies the
// requests that would go to the provider, captures the returned access tokens, and registers a
// new internal user as needed. The user is then returned an token that is valid for interacting
// with the API
#[instrument(skip(rqctx, body), err(Debug))]
pub async fn exchange_device_token_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<OAuthProviderNameParam>,
    body: TypedBody<AccessTokenExchangeRequest>,
) -> Result<Response<Body>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let ctx = rqctx.v_ctx();
    let path = path.into_inner();
    let provider = ctx
        .get_oauth_provider(&path.provider)
        .await
        .map_err(ApiError::OAuth)?;
    let device_info = provider.device_code_flow_info();

    tracing::debug!(provider = ?provider.name(), "Acquired OAuth provider for token exchange");

    if device_info.is_none() {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_vec(&ProxyTokenError {
                    error: "unsupported_grant_type".to_string(),
                    error_description: Some(format!(
                        "{} does not support device code flow",
                        path.provider
                    )),
                    error_uri: None,
                })
                .unwrap()
                .into(),
            )?);
    }

    let device_info = device_info.unwrap();
    let exchange_request = body.into_inner();

    // Validate grant_type per RFC 8628 §3.4
    if !validate_device_grant_type(&exchange_request.grant_type) {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(header::CONTENT_TYPE, "application/json")
            .body(
                serde_json::to_vec(&ProxyTokenError {
                    error: "unsupported_grant_type".to_string(),
                    error_description: Some(
                        "grant_type must be urn:ietf:params:oauth:grant-type:device_code"
                            .to_string(),
                    ),
                    error_uri: None,
                })
                .unwrap()
                .into(),
            )?);
    }

    let exchange = AccessTokenExchange::new(exchange_request, device_info);

    let client = reqwest::Client::new();

    let response = client
        .request(Method::POST, &device_info.token_endpoint)
        .header(
            header::CONTENT_TYPE,
            &device_info.token_endpoint_content_type,
        )
        .header(header::ACCEPT, HeaderValue::from_static("application/json"))
        .body(
            // We know that this is safe to unwrap as we just deserialized it via the body Extractor
            serde_urlencoded::to_string(&exchange.provider).unwrap(),
        )
        .send()
        .await
        .tap_err(|err| tracing::error!(?err, "Token exchange request failed"))
        .map_err(internal_error)?;

    // Take a part the response as we will need the individual parts later
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.bytes().await.map_err(internal_error)?;

    // We unfortunately can not trust our providers to follow specs and therefore need to do
    // our own inspection of the response to determine what to do
    if !status.is_success() {
        // If the server returned a non-success status then we are going to trust the server and
        // report their error back to the client
        tracing::debug!(provider = ?path.provider, ?headers, ?status, "Received error response from OAuth provider");

        Ok(proxy_upstream_response(bytes, headers, status))
    } else {
        // The server gave us back a non-error response but it still may not be a success.
        // GitHub for instance does not use a status code for indicating the success or failure
        // of a call. So instead we try to deserialize the body into an access token, with the
        // understanding that it may fail and we will need to try and treat the response as
        // an error instead.

        let parsed: Result<
            StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
            serde_json::Error,
        > = serde_json::from_slice(&bytes);

        match parsed {
            Ok(parsed) => {
                let info = provider
                    .get_user_info(parsed.access_token().secret())
                    .await
                    .map_err(LoginError::UserInfo)
                    .tap_err(|err| tracing::error!(?err, "Failed to look up user information"))?;

                tracing::debug!("Verified and validated OAuth user");

                let (api_user_info, api_user_provider) = ctx
                    .register_api_user(&ctx.builtin_registration_user(), info)
                    .await?;

                tracing::info!(api_user_id = ?api_user_info.user.id, api_user_provider_id = ?api_user_provider.id, "Retrieved api user to generate device token for");

                let claims =
                    ctx.generate_claims(&api_user_info.user.id, &api_user_provider.id, None);
                let token = ctx
                    .user
                    .register_access_token(
                        &ctx.builtin_registration_user(),
                        ctx.jwt_signer(),
                        &api_user_info.user.id,
                        &claims,
                    )
                    .await?;

                tracing::info!(provider = ?path.provider, api_user_id = ?api_user_info.user.id, "Generated access token");

                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(
                        serde_json::to_string(&ProxyTokenResponse {
                            access_token: token.signed_token,
                            token_type: "Bearer".to_string(),
                            expires_in: Some(claims.exp - Utc::now().timestamp()),
                            refresh_token: None,
                            scopes: None,
                        })
                        .unwrap()
                        .into(),
                    )?)
            }
            Err(_) => {
                // Do not log the error here as we want to ensure we do not leak token information
                tracing::debug!(
                    "Failed to parse a success response from the remote token endpoint"
                );

                Ok(handle_token_parse_failure(
                    &path.provider.to_string(),
                    bytes,
                    headers,
                    status,
                ))
            }
        }
    }
}

/// Validate the grant_type for device code exchange per RFC 8628 §3.4.
fn validate_device_grant_type(grant_type: &str) -> bool {
    grant_type == "urn:ietf:params:oauth:grant-type:device_code"
}

/// Headers that are safe to forward from an upstream OAuth provider response.
/// Only `Content-Type` is needed so the client can parse the body. Polling backoff
/// is handled via the JSON body per RFC 8628 (`interval` field / `slow_down` error),
/// not via HTTP headers.
const FORWARDED_HEADERS: &[header::HeaderName] = &[header::CONTENT_TYPE];

/// Copy only allowlisted headers from an upstream response to avoid forwarding
/// dangerous headers such as `Set-Cookie`, `Location`, or CORS headers.
fn filter_upstream_headers(upstream: &HeaderMap) -> HeaderMap {
    let mut filtered = HeaderMap::new();
    for name in FORWARDED_HEADERS {
        if let Some(value) = upstream.get(name) {
            filtered.insert(name.clone(), value.clone());
        }
    }
    filtered
}

/// Build a response to the client by proxying an upstream provider's response. This is used
/// when the upstream provider returns a non-success status code.
fn proxy_upstream_response(bytes: Bytes, headers: HeaderMap, status: StatusCode) -> Response<Body> {
    let mut client_response = Response::new(Body::from(bytes));
    *client_response.headers_mut() = filter_upstream_headers(&headers);
    *client_response.status_mut() = status;
    client_response
}

/// Handle the case where the upstream provider returned a 200 status but the body could not be
/// parsed as a valid token response. We try to interpret the body as an error response and proxy
/// it back. If the body is not a recognizable error either, we return our own error.
fn handle_token_parse_failure(
    provider_name: &str,
    bytes: Bytes,
    headers: HeaderMap,
    status: StatusCode,
) -> Response<Body> {
    // Try to deserialize the body as an error
    let mut error_response = match serde_json::from_slice::<ProxyTokenError>(&bytes) {
        Ok(error) => {
            // We found an error in the message body. This is not ideal, but we at
            // least can understand what the server was trying to tell us
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
            // We still do not know what the remote server is doing... and need to
            // cancel the request ourselves
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
        header::{self, HeaderName, SET_COOKIE},
        HeaderMap, HeaderValue, StatusCode,
    };
    use hyper::body::Bytes;

    use super::{handle_token_parse_failure, proxy_upstream_response, validate_device_grant_type};

    #[test]
    fn test_upstream_set_cookie_is_stripped_from_error_response() {
        // A malicious or compromised upstream provider includes a Set-Cookie header
        // that would set a cookie on our API's domain in the user's browser
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

        // The Set-Cookie header must NOT be forwarded to our client
        assert!(
            response.headers().get(SET_COOKIE).is_none(),
            "Upstream Set-Cookie header must not be forwarded to the client"
        );
        // But Content-Type should still be forwarded
        assert!(
            response.headers().get(header::CONTENT_TYPE).is_some(),
            "Content-Type should be forwarded from upstream"
        );
    }

    #[test]
    fn test_upstream_cors_headers_are_stripped_from_error_response() {
        // A malicious upstream provider injects permissive CORS headers that would
        // weaken our API's cross-origin protections
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

        // CORS headers must NOT be forwarded from upstream
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
        // When the upstream returns a 200 status but the body is an error (not a valid
        // token), handle_token_parse_failure must not forward dangerous headers.
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

        // Body that parses as a ProxyTokenError but NOT as a valid token
        let body = Bytes::from_static(
            b"{\"error\": \"slow_down\", \"error_description\": null, \"error_uri\": null}",
        );
        let response =
            handle_token_parse_failure("test-provider", body, upstream_headers, StatusCode::OK);

        // Dangerous headers must NOT be forwarded
        assert!(
            response.headers().get(header::LOCATION).is_none(),
            "Upstream Location header must not be forwarded to the client"
        );
        assert!(
            response.headers().get("x-frame-options").is_none(),
            "Upstream X-Frame-Options header must not be forwarded to the client"
        );
        // But Content-Type should still be present (set by the function itself)
        assert!(
            response.headers().get(header::CONTENT_TYPE).is_some(),
            "Content-Type should be present on the response"
        );
    }

    #[test]
    fn test_upstream_set_cookie_is_stripped_from_token_parse_failure() {
        // Even when the upstream returns 200 and the body is a parseable error,
        // a Set-Cookie header must not be forwarded to our client
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

        // The Set-Cookie header must NOT be forwarded
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
