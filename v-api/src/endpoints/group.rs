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
    Group, GroupId, NewGroup,
    permissions::{Permission, PermissionStorage, Permissions},
    storage::GroupFilter,
};

use crate::{
    context::{ApiContext, VContextWithCaller},
    permissions::VAppPermission,
};

fn into_group_response<T, U>(group: Group<T>) -> Group<U>
where
    T: Permission,
    U: Permission + From<T>,
{
    Group {
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
) -> Result<HttpResponseOk<Vec<Group<U>>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: From<T> + Permission + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    Ok(HttpResponseOk(
        ctx.group
            .list_groups(&caller, GroupFilter::default())
            .await?
            .into_iter()
            .map(into_group_response)
            .collect(),
    ))
}

#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
pub struct GroupUpdateParams<T> {
    name: String,
    permissions: Permissions<T>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn create_group_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    body: GroupUpdateParams<T>,
) -> Result<HttpResponseCreated<Group<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: From<T> + Permission + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    Ok(HttpResponseCreated(
        ctx.group
            .create_group(
                &caller,
                NewGroup {
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
pub struct GroupPath {
    group_id: TypedUuid<GroupId>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn update_group_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: GroupPath,
    body: GroupUpdateParams<T>,
) -> Result<HttpResponseOk<Group<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: From<T> + Permission + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    Ok(HttpResponseOk(
        ctx.group
            .update_group(
                &caller,
                NewGroup {
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
    path: GroupPath,
) -> Result<HttpResponseOk<Group<U>>, HttpError>
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
