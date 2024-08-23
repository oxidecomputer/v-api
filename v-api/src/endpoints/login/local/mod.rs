// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use chrono::{Duration, Utc};
use dropshot::{HttpError, RequestContext, TypedBody};
use http::{header, StatusCode, Response};
use hyper::Body;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use v_model::permissions::PermissionStorage;

use crate::{authn::jwt::Claims, context::ApiContext, endpoints::login::{oauth::device_token::ProxyTokenResponse, ExternalUserId, UserInfo}, permissions::{VAppPermission, VPermission}};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct LocalLogin {
    pub external_id: String,
    pub email: String,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn local_login_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    body: TypedBody<LocalLogin>,
) -> Result<Response<Body>, HttpError>
where
    T: VAppPermission + From<VPermission> + PermissionStorage,
{
    let ctx = rqctx.context();
    let body = body.into_inner();

    let info = UserInfo {
        external_id: ExternalUserId::Local(body.external_id),
        verified_emails: vec![body.email],
        github_username: Some("Local Dev".to_string()),
    };

    let (api_user, api_user_provider) = ctx
        .v_ctx()
        .register_api_user(&ctx.v_ctx().builtin_registration_user(), info)
        .await?;

    tracing::info!(api_user_id = ?api_user.user.id, api_user_provider_id = ?api_user_provider.id, "Retrieved api user to generate device token for");

    let token = ctx
        .v_ctx()
        .user
        .register_access_token(
            &ctx.v_ctx().builtin_registration_user(),
            ctx.v_ctx().jwt_signer(),
            &api_user.user.id,
            &Claims::new(
                &ctx.v_ctx(),
                &api_user.user.id,
                &api_user_provider.id,
                None,
                Utc::now() + Duration::seconds(60 * 60),
            ),
        )
        .await?;

    tracing::info!(provider = "local", api_user_id = ?api_user.user.id, "Generated access token");

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(
            serde_json::to_string(&ProxyTokenResponse {
                access_token: token.signed_token,
                token_type: "Bearer".to_string(),
                expires_in: Some(token.expires_in),
                refresh_token: None,
                scopes: None,
            })
            .unwrap()
            .into(),
        )?)
}
