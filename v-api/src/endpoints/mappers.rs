// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::{HttpError, HttpResponseCreated, HttpResponseOk, RequestContext};
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::instrument;
use v_model::{
    permissions::{AsScope, Permission, PermissionStorage},
    Mapper, MapperId, NewMapper,
};

use crate::{
    context::{ApiContext, VContextWithCaller},
    permissions::{VAppPermission, VPermission},
    response::bad_request,
};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListMappersQuery {
    /// Include depleted mappers in the returned results
    include_depleted: Option<bool>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn get_mappers_op<T>(
    rqctx: &RequestContext<T>,
    query: ListMappersQuery,
) -> Result<HttpResponseOk<Vec<Mapper>>, HttpError>
where
    T: ApiContext,
    T::AppPermissions: Permission + From<VPermission> + AsScope + PermissionStorage,
{
    let ctx = rqctx.v_ctx();
    let caller = ctx.get_caller(rqctx).await?;

    Ok(HttpResponseOk(
        ctx.mapping
            .get_mappers(&caller, query.include_depleted.unwrap_or(false))
            .await?,
    ))
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateMapper {
    name: String,
    rule: Value,
    max_activations: Option<i32>,
}

#[instrument(skip(rqctx, body), err(Debug))]
pub async fn create_mapper_op<T>(
    rqctx: &RequestContext<T>,
    body: CreateMapper,
) -> Result<HttpResponseCreated<Mapper>, HttpError>
where
    T: ApiContext,
    T::AppPermissions: VAppPermission,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    if ctx.mapping.validate(&body.rule) {
        let res = ctx
            .mapping
            .add_mapper(
                &caller,
                &NewMapper {
                    id: TypedUuid::new_v4(),
                    name: body.name,
                    rule: body.rule,
                    activations: body.max_activations.map(|_| 0),
                    max_activations: body.max_activations,
                },
            )
            .await;

        Ok(HttpResponseCreated(res?))
    } else {
        Err(bad_request("Invalid rule payload"))
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MapperPath {
    mapper_id: TypedUuid<MapperId>,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn delete_mapper_op<T>(
    rqctx: &RequestContext<T>,
    path: MapperPath,
) -> Result<HttpResponseOk<Mapper>, HttpError>
where
    T: ApiContext,
    T::AppPermissions: Permission + From<VPermission> + AsScope + PermissionStorage,
{
    let (ctx, caller) = rqctx.as_ctx().await?;
    Ok(HttpResponseOk(
        ctx.mapping.remove_mapper(&caller, &path.mapper_id).await?,
    ))
}
