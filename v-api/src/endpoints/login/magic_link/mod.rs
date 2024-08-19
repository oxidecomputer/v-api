// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{Duration, Utc};
use dropshot::{HttpError, HttpResponseOk, Path, RequestContext, TypedBody};
use http::StatusCode;
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use std::ops::Add;
use tracing::instrument;
use url::Url;
use v_model::{
    permissions::PermissionStorage, schema_ext::MagicLinkMedium, MagicLink, MagicLinkAttemptId,
};

use crate::{
    authn::{key::RawKey, Signer},
    context::{
        magic_link::{MagicLinkSendError, MagicLinkTransitionError},
        VContextWithCaller,
    },
    endpoints::login::{ExternalUserId, UserInfo},
    permissions::VAppPermission,
    response::{to_internal_error, ResourceError},
    ApiContext, VContext,
};

pub mod client;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MagicLinkPath {
    medium: MagicLinkMedium,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MagicLinkSendRequest {
    secret: String,
    recipient: String,
    redirect_uri: Url,
    expires_in: i64,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MagicLinkSendResponse {
    attempt_id: TypedUuid<MagicLinkAttemptId>,
}

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
    let path = path.into_inner();
    let body = body.into_inner();

    Ok(HttpResponseOk(
        magic_link_send_op_inner(
            ctx,
            path.medium,
            body.secret,
            body.recipient,
            body.redirect_uri,
            body.expires_in,
        )
        .await?,
    ))
}

#[instrument(skip(ctx, secret, recipient, redirect_uri))]
async fn magic_link_send_op_inner<T>(
    ctx: &VContext<T>,
    medium: MagicLinkMedium,
    secret: String,
    recipient: String,
    redirect_uri: Url,
    expires_in: i64,
) -> Result<MagicLinkSendResponse, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    tracing::info!("Handling magic link send request");
    
    // Any caller may create a magic link attempt by supplying the clients secret
    let secret_signature = ctx
        .signer()
        .sign(secret.as_bytes())
        .await
        .map(|bytes| hex::encode(&bytes))
        .map_err(to_internal_error)?;
    let client = ctx
        .magic_link
        .find_client(&secret_signature, &redirect_uri)
        .await?;
    let key = RawKey::generate::<8>(&Uuid::new_v4());

    let attempt = ctx
        .magic_link
        .send_login_attempt(
            key,
            ctx.signer(),
            client.id,
            &redirect_uri,
            medium,
            "",
            Utc::now().add(Duration::seconds(expires_in)),
            &recipient,
        )
        .await;

    match attempt {
        Ok(attempt) => Ok(MagicLinkSendResponse {
            attempt_id: attempt.id,
        }),
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
pub struct MagicLinkExchangeRequest {
    attempt_id: TypedUuid<MagicLinkAttemptId>,
    recipient: String,
    secret: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct MagicLinkExchangeResponse {
    token_type: String,
    access_token: String,
    expires_in: i64,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn magic_link_exchange_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    body: TypedBody<MagicLinkExchangeRequest>,
) -> Result<HttpResponseOk<MagicLinkExchangeResponse>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, _) = rqctx.as_ctx().await?;
    let body = body.into_inner();

    // Any caller may consume a magic link by supplying the attempt secret
    let key: RawKey = body.secret.as_str().try_into().map_err(to_internal_error)?;
    let signed_key = key.sign(ctx.signer()).await.unwrap();

    let recipient_signature = ctx
        .signer()
        .sign(body.recipient.as_bytes())
        .await
        .map(|bytes| hex::encode(&bytes))
        .map_err(to_internal_error)?;

    let attempt = ctx
        .magic_link
        .complete_login_attempt(body.attempt_id, &signed_key.signature())
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

    let token = ctx
        .generate_access_token(
            &ctx.builtin_registration_user(),
            &api_user_info.user.id,
            &api_user_provider.id,
            Some(scope),
        )
        .await?;

    Ok(HttpResponseOk(MagicLinkExchangeResponse {
        token_type: "Bearer".to_string(),
        access_token: token.signed_token,
        expires_in: token.expires_in,
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

pub trait CheckMagicLinkClient {
    fn is_secret_valid(&self, key: &RawKey, signer: &dyn Signer) -> bool;
    fn is_redirect_uri_valid(&self, redirect_uri: &str) -> bool;
}

impl CheckMagicLinkClient for MagicLink {
    fn is_secret_valid(&self, key: &RawKey, signer: &dyn Signer) -> bool {
        for secret in &self.secrets {
            match key.verify(signer, secret.secret_signature.as_bytes()) {
                Ok(_) => return true,
                Err(err) => {
                    tracing::error!(?err, ?secret.id, "Client contains an invalid secret signature");
                }
            }
        }

        false
    }

    fn is_redirect_uri_valid(&self, redirect_uri: &str) -> bool {
        tracing::trace!(?redirect_uri, valid_uris = ?self.redirect_uris, "Checking redirect uri against list of valid uris");
        self.redirect_uris
            .iter()
            .any(|r| r.redirect_uri == redirect_uri)
    }
}
