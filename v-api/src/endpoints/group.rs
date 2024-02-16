// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::{HttpError, HttpResponseCreated, HttpResponseOk, RequestContext};
use schemars::JsonSchema;
use serde::Deserialize;
use tracing::instrument;
use uuid::Uuid;
use v_api_permissions::Permissions;
use v_model::{AccessGroup, NewAccessGroup};

use crate::{context::ApiContext, permissions::ApiPermissionResponse, ApiPermissions, Group};

pub type GroupResponse = AccessGroup<ApiPermissionResponse>;

fn into_group_response(group: Group) -> GroupResponse {
    AccessGroup {
        id: group.id,
        name: group.name,
        permissions: group
            .permissions
            .into_iter()
            .map(|p| p.into())
            .collect::<Permissions<ApiPermissionResponse>>(),
        created_at: group.created_at,
        updated_at: group.updated_at,
        deleted_at: group.deleted_at,
    }
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn get_groups_op(
    rqctx: &RequestContext<impl ApiContext>,
) -> Result<HttpResponseOk<Vec<GroupResponse>>, HttpError> {
    let ctx = rqctx.v_ctx();
    let auth = ctx.authn_token(&rqctx).await?;
    let caller = ctx.get_caller(auth.as_ref()).await?;

    Ok(HttpResponseOk(
        ctx.get_groups(&caller)
            .await?
            .into_iter()
            .map(into_group_response)
            .collect(),
    ))
}

#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
pub struct AccessGroupUpdateParams {
    name: String,
    permissions: ApiPermissions,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn create_group_op(
    rqctx: &RequestContext<impl ApiContext>,
    body: AccessGroupUpdateParams,
) -> Result<HttpResponseCreated<GroupResponse>, HttpError> {
    let ctx = rqctx.v_ctx();
    let auth = ctx.authn_token(&rqctx).await?;
    let caller = ctx.get_caller(auth.as_ref()).await?;

    Ok(HttpResponseCreated(
        ctx.create_group(
            &caller,
            NewAccessGroup {
                id: Uuid::new_v4(),
                name: body.name,
                permissions: body.permissions,
            },
        )
        .await
        .map(into_group_response)?,
    ))
}

#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
pub struct AccessGroupPath {
    group_id: Uuid,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn update_group_op(
    rqctx: &RequestContext<impl ApiContext>,
    path: AccessGroupPath,
    body: AccessGroupUpdateParams,
) -> Result<HttpResponseOk<GroupResponse>, HttpError> {
    let ctx = rqctx.v_ctx();
    let auth = ctx.authn_token(&rqctx).await?;
    let caller = ctx.get_caller(auth.as_ref()).await?;

    Ok(HttpResponseOk(
        ctx.update_group(
            &caller,
            NewAccessGroup {
                id: path.group_id,
                name: body.name,
                permissions: body.permissions,
            },
        )
        .await
        .map(into_group_response)?,
    ))
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn delete_group_op(
    rqctx: &RequestContext<impl ApiContext>,
    path: AccessGroupPath,
) -> Result<HttpResponseOk<GroupResponse>, HttpError> {
    let ctx = rqctx.v_ctx();
    let auth = ctx.authn_token(&rqctx).await?;
    let caller = ctx.get_caller(auth.as_ref()).await?;

    Ok(HttpResponseOk(
        ctx.delete_group(&caller, &path.group_id)
            .await
            .map(into_group_response)?,
    ))
}
