// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{DateTime, Utc};
use dropshot::{Body, HttpError, HttpResponseOk, Method, Path, RequestContext, TypedBody};
use http::{header, HeaderValue, Response, StatusCode};
use oauth2::{basic::BasicTokenType, EmptyExtraTokenFields, StandardTokenResponse, TokenResponse};
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use tap::TapFallible;
use tracing::instrument;
use v_model::permissions::PermissionStorage;

use super::{
    ClientType, OAuthProvider, OAuthProviderInfo, OAuthProviderNameParam, UserInfoProvider,
};
use crate::{
    context::ApiContext, endpoints::login::LoginError, error::ApiError,
    permissions::VAppPermission, response::internal_error, util::response::bad_request,
};

#[instrument(skip(rqctx), err(Debug))]
pub async fn get_device_provider_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<OAuthProviderNameParam>,
) -> Result<HttpResponseOk<OAuthProviderInfo>, HttpError>
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

    Ok(HttpResponseOk(provider.provider_info(
        &rqctx.v_ctx().public_url(),
        &ClientType::Device,
    )))
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
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
    pub fn new(
        req: AccessTokenExchangeRequest,
        provider: &Box<dyn OAuthProvider + Send + Sync>,
    ) -> Option<Self> {
        provider
            .client_secret(&ClientType::Device)
            .map(|client_secret| Self {
                provider: ProviderTokenExchange {
                    client_id: provider.client_id(&ClientType::Device).to_string(),
                    device_code: req.device_code,
                    grant_type: req.grant_type,
                    client_secret: client_secret.expose_secret().to_string(),
                },
                expires_at: req.expires_at,
            })
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
    let mut provider = ctx
        .get_oauth_provider(&path.provider)
        .await
        .map_err(ApiError::OAuth)?;

    tracing::debug!(provider = ?provider.name(), "Acquired OAuth provider for token exchange");

    let exchange_request = body.into_inner();

    if let Some(mut exchange) = AccessTokenExchange::new(exchange_request, &mut provider) {
        exchange.provider.client_secret = exchange.provider.client_secret;

        let token_exchange_endpoint = provider.token_exchange_endpoint();
        let client = reqwest::Client::new();

        let response = client
            .request(Method::POST, token_exchange_endpoint)
            .header(header::CONTENT_TYPE, provider.token_exchange_content_type())
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

            let mut client_response = Response::new(Body::from(bytes));
            *client_response.headers_mut() = headers;
            *client_response.status_mut() = status;

            Ok(client_response)
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
                        .tap_err(|err| {
                            tracing::error!(?err, "Failed to look up user information")
                        })?;

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

                    // Try to deserialize the body again, but this time as an error
                    let mut error_response = match serde_json::from_slice::<ProxyTokenError>(&bytes)
                    {
                        Ok(error) => {
                            // We found an error in the message body. This is not ideal, but we at
                            // least can understand what the server was trying to tell us
                            tracing::debug!(?error, provider = ?path.provider, "Parsed error response from OAuth provider");

                            let mut client_response = Response::new(Body::from(bytes));
                            *client_response.headers_mut() = headers;
                            *client_response.status_mut() = status;
                            
                            client_response
                        }
                        Err(_) => {
                            // We still do not know what the remote server is doing... and need to
                            // cancel the request ourselves
                            tracing::warn!(
                                "Remote OAuth provide returned a response that we do not undestand"
                            );

                            Response::new(
                                serde_json::to_vec(&ProxyTokenError {
                                    error: "access_denied".to_string(),
                                    error_description: Some(format!(
                                        "{} returned a malformed response",
                                        path.provider
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

                    Ok(error_response)
                }
            }
        }
    } else {
        tracing::info!(provider = ?path.provider, "Found an OAuth provider, but it is not configured properly");

        Err(bad_request("Invalid provider"))
    }
}
