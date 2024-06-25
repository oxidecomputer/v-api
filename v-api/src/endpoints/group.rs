// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::{HttpError, HttpResponseCreated, HttpResponseOk, RequestContext};
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::Deserialize;
use std::fmt::Debug;
use tracing::instrument;
use v_model::{
    permissions::{Permission, PermissionStorage, Permissions},
    AccessGroup, AccessGroupId, NewAccessGroup,
};

use crate::{
    context::{ApiContext, VContextWithCaller},
    permissions::VAppPermission,
};

fn into_group_response<T, U>(group: AccessGroup<T>) -> AccessGroup<U>
where
    T: Permission,
    U: Permission + From<T>,
{
    AccessGroup {
        id: group.id,
        name: group.name,
        permissions: group
            .permissions
            .into_iter()
            .map(|p| p.into())
            .collect::<Permissions<U>>(),
        created_at: group.created_at,
        updated_at: group.updated_at,
        deleted_at: group.deleted_at,
    }
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn get_groups_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
) -> Result<HttpResponseOk<Vec<AccessGroup<U>>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: From<T> + Permission + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    Ok(HttpResponseOk(
        ctx.group
            .get_groups(&caller)
            .await?
            .into_iter()
            .map(into_group_response)
            .collect(),
    ))
}

#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
pub struct AccessGroupUpdateParams<T> {
    name: String,
    permissions: Permissions<T>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn create_group_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    body: AccessGroupUpdateParams<T>,
) -> Result<HttpResponseCreated<AccessGroup<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: From<T> + Permission + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    Ok(HttpResponseCreated(
        ctx.group
            .create_group(
                &caller,
                NewAccessGroup {
                    id: TypedUuid::new_v4(),
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
    group_id: TypedUuid<AccessGroupId>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn update_group_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: AccessGroupPath,
    body: AccessGroupUpdateParams<T>,
) -> Result<HttpResponseOk<AccessGroup<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: From<T> + Permission + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    Ok(HttpResponseOk(
        ctx.group
            .update_group(
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
pub async fn delete_group_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: AccessGroupPath,
) -> Result<HttpResponseOk<AccessGroup<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: From<T> + Permission + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    Ok(HttpResponseOk(
        ctx.group
            .delete_group(&caller, &path.group_id)
            .await
            .map(into_group_response)?,
    ))
}
