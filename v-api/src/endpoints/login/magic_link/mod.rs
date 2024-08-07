// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{Duration, Utc};
use dropshot::{HttpError, HttpResponseOk, Path, RequestContext, TypedBody};
use http::StatusCode;
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::ops::Add;
use tracing::instrument;
use url::Url;
use v_model::{permissions::PermissionStorage, schema_ext::MagicLinkMedium, MagicLinkAttemptId};

use crate::{
    context::{
        magic_link::{MagicLinkSendError, MagicLinkTransitionError},
        VContextWithCaller,
    },
    endpoints::login::{ExternalUserId, UserInfo},
    permissions::VAppPermission,
    response::{to_internal_error, ResourceError},
    ApiContext,
};

#[derive(Debug, Deserialize, JsonSchema)]
struct MagicLinkPath {
    medium: MagicLinkMedium,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct MagicLinkSendRequest {
    secret: String,
    recipient: String,
    redirect_uri: Url,
    expires_in: i64,
}

#[derive(Debug, Serialize, JsonSchema)]
struct MagicLinkSendResponse {
    attempt_id: TypedUuid<MagicLinkAttemptId>,
}

// #[endpoint {
//     method = POST,
//     path = "/login/magic/{medium}/send"
// }]
#[instrument(skip(rqctx), err(Debug))]
pub async fn magic_link_send_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<MagicLinkPath>,
    body: TypedBody<MagicLinkSendRequest>,
) -> Result<HttpResponseOk<MagicLinkSendResponse>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, _) = rqctx.as_ctx().await?;
    let body = body.into_inner();

    // Any caller may create a magic link attempt by supplying the clients secret
    let secret_signature = ctx
        .signer()
        .sign(body.secret.as_bytes())
        .await
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .map_err(to_internal_error)?;
    let client = ctx
        .magic_link
        .find_client(&secret_signature, &body.redirect_uri)
        .await?;

    let attempt = ctx
        .magic_link
        .send_login_attempt(
            ctx.signer(),
            client.id,
            &body.redirect_uri,
            path.into_inner().medium,
            "",
            Utc::now().add(Duration::seconds(body.expires_in)),
            &body.recipient,
        )
        .await;

    match attempt {
        Ok(attempt) => Ok(HttpResponseOk(MagicLinkSendResponse {
            attempt_id: attempt.id,
        })),
        Err(ResourceError::InternalError(err)) => Err(err.into()),
        Err(err) => Err(err.into()),
    }
}

impl From<MagicLinkSendError> for HttpError {
    fn from(value: MagicLinkSendError) -> Self {
        match value {
            MagicLinkSendError::ApiKey(err) => ResourceError::InternalError(err).into(),
            MagicLinkSendError::NoMessageBuilder(_) => {
                unimplemented!()
            }
            MagicLinkSendError::NoMessageSender(_) => {
                unimplemented!()
            }
            MagicLinkSendError::Send(_) => {
                unimplemented!()
            }
            MagicLinkSendError::Signing(err) => ResourceError::InternalError(err).into(),
            MagicLinkSendError::Storage(err) => ResourceError::InternalError(err).into(),
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
struct MagicLinkExchangeRequest {
    attempt_id: TypedUuid<MagicLinkAttemptId>,
    recipient: String,
    secret: String,
}

#[derive(Debug, Serialize, JsonSchema)]
struct MagicLinkExchangeResponse {
    token_type: String,
    access_token: String,
    expires_in: i64,
}

// #[endpoint {
//     method = POST,
//     path = "/login/magic/{medium}/exchange"
// }]
#[instrument(skip(rqctx), err(Debug))]
pub async fn magic_link_exchange_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<MagicLinkPath>,
    body: TypedBody<MagicLinkExchangeRequest>,
) -> Result<HttpResponseOk<MagicLinkExchangeResponse>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, _) = rqctx.as_ctx().await?;
    let path = path.into_inner();
    let body = body.into_inner();

    // Any caller may consume a magic link by supplying the attempt secret
    let secret_signature = ctx
        .signer()
        .sign(body.secret.as_bytes())
        .await
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .map_err(to_internal_error)?;

    let recipient_signature = ctx
        .signer()
        .sign(body.recipient.as_bytes())
        .await
        .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
        .map_err(to_internal_error)?;

    let attempt = ctx
        .magic_link
        .complete_login_attempt(body.attempt_id, &secret_signature)
        .await?;

    // Register this user as an API user if needed
    let (api_user_info, api_user_provider) = ctx
        .register_api_user(
            &ctx.builtin_registration_user(),
            UserInfo {
                external_id: ExternalUserId::MagicLink(recipient_signature),
                verified_emails: vec![body.recipient],
                github_username: None,
            },
        )
        .await?;

    tracing::info!(api_user_id = ?api_user_info.user.id, "Retrieved api user to generate access token for");

    let scope = attempt
        .scope
        .split(' ')
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    let claims = ctx.generate_claims(&api_user_info.user.id, &api_user_provider.id, Some(scope));
    let token = ctx
        .user
        .register_access_token(
            &ctx.builtin_registration_user(),
            ctx.jwt_signer(),
            &api_user_info.user.id,
            &claims,
        )
        .await?;

    tracing::info!(medium = ?path.medium, api_user_id = ?api_user_info.user.id, "Generated access token");

    Ok(HttpResponseOk(MagicLinkExchangeResponse {
        token_type: "Bearer".to_string(),
        access_token: token.signed_token,
        expires_in: claims.exp - Utc::now().timestamp(),
    }))
}

impl From<MagicLinkTransitionError> for HttpError {
    fn from(value: MagicLinkTransitionError) -> Self {
        match value {
            MagicLinkTransitionError::Expired => HttpError {
                status_code: StatusCode::CONFLICT,
                error_code: Some("expired".to_string()),
                external_message: "Magic link attempt is expired".to_string(),
                internal_message: "Magic link attempt is expired".to_string(),
            },
            MagicLinkTransitionError::Nonce => HttpError {
                status_code: StatusCode::CONFLICT,
                error_code: Some("invalid_nonce".to_string()),
                external_message: "Supplied nonce is invalid".to_string(),
                internal_message: "Supplied nonce is invalid".to_string(),
            },
            MagicLinkTransitionError::State(state) => HttpError {
                status_code: StatusCode::CONFLICT,
                error_code: Some("invalid_state".to_string()),
                external_message: "Magic link has already been sent or completed".to_string(),
                internal_message: format!(
                    "Magic link attempted to send while in the {} state",
                    state
                ),
            },
            MagicLinkTransitionError::Storage(err) => ResourceError::InternalError(err).into(),
            MagicLinkTransitionError::Unknown => HttpError {
                status_code: StatusCode::INTERNAL_SERVER_ERROR,
                error_code: None,
                external_message: "".to_string(),
                internal_message: "Unknown error occurred".to_string(),
            },
        }
    }
}
