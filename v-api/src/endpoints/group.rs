// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::{
    ClientErrorStatusCode, HttpError, HttpResponseCreated, HttpResponseOk, RequestContext,
};
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::Deserialize;
use std::fmt::Debug;
use tracing::instrument;
use v_model::{
    AccessGroup, AccessGroupId, NewAccessGroup,
    permissions::{Permission, PermissionStorage, Permissions},
    storage::AccessGroupFilter,
};

use crate::{
    context::{ApiContext, VContextWithCaller},
    permissions::VAppPermission,
    response::client_error,
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
        source: group.source,
        created_at: group.created_at,
        updated_at: group.updated_at,
        deleted_at: group.deleted_at,
        generation: group.generation,
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
            .list_groups(&caller, AccessGroupFilter::default())
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

#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
pub struct AccessGroupPermissionParams<T> {
    permission: T,
}

fn preset_group_error() -> HttpError {
    client_error(
        ClientErrorStatusCode::CONFLICT,
        "Preset groups are managed via service configuration and cannot be modified at runtime",
    )
}

/// Adds a single permission to a group. The caller must be able to grant it.
#[instrument(skip(rqctx), err(Debug))]
pub async fn add_group_permission_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: AccessGroupPath,
    body: AccessGroupPermissionParams<T>,
) -> Result<HttpResponseOk<AccessGroup<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: From<T> + Permission + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;

    if ctx.group.is_preset(&path.group_id) {
        Err(preset_group_error())
    } else {
        Ok(HttpResponseOk(
            ctx.group
                .add_permission_to_group(&caller, &path.group_id, body.permission)
                .await
                .map(into_group_response)?,
        ))
    }
}

/// Removes a single permission from a group. The caller must be able to grant it.
#[instrument(skip(rqctx), err(Debug))]
pub async fn remove_group_permission_op<T, U>(
    rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    path: AccessGroupPath,
    body: AccessGroupPermissionParams<T>,
) -> Result<HttpResponseOk<AccessGroup<U>>, HttpError>
where
    T: VAppPermission + PermissionStorage,
    U: From<T> + Permission + JsonSchema,
{
    let (ctx, caller) = rqctx.as_ctx().await?;

    if ctx.group.is_preset(&path.group_id) {
        Err(preset_group_error())
    } else {
        Ok(HttpResponseOk(
            ctx.group
                .remove_permission_from_group(&caller, &path.group_id, &body.permission)
                .await
                .map(into_group_response)?,
        ))
    }
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

    if ctx.group.is_preset(&path.group_id) {
        return Err(client_error(
            ClientErrorStatusCode::CONFLICT,
            "Preset groups are managed via service configuration and cannot be deleted at runtime",
        ));
    }

    Ok(HttpResponseOk(
        ctx.group
            .delete_group(&caller, &path.group_id)
            .await
            .map(into_group_response)?,
    ))
}
