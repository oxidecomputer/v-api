// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::{HttpError, HttpResponseOk, Path, RequestContext, TypedBody};
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use v_model::{permissions::PermissionStorage, UserId, UserProviderId};

use crate::{
    context::{ApiContext, VContextWithCaller},
    permissions::VAppPermission,
    secrets::OpenApiSecretString,
};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApiUserProviderPath {
    provider_id: TypedUuid<UserProviderId>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ApiUserLinkRequestPayload {
    user_id: TypedUuid<UserId>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ApiUserLinkRequestResponse {
    token: OpenApiSecretString,
}

/// Create a new link token for linking this provider to a different api user
#[instrument(skip(rqctx), err(Debug))]
pub async fn create_link_token_op<T>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: Path<ApiUserProviderPath>,
    body: TypedBody<ApiUserLinkRequestPayload>,
) -> Result<HttpResponseOk<ApiUserLinkRequestResponse>, HttpError>
where
    T: VAppPermission + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    let path = path.into_inner();
    let body = body.into_inner();

    let provider = ctx
        .user
        .get_api_user_provider(&caller, &caller.id, &path.provider_id)
        .await?;

    let token = ctx
        .link
        .create_link_request_token(
            &caller,
            ctx.signer(),
            &provider.id,
            &caller.id,
            &body.user_id,
        )
        .await?;

    Ok(HttpResponseOk(ApiUserLinkRequestResponse {
        token: token.key().into(),
    }))
}
