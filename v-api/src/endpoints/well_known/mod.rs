// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::{HttpError, HttpResponseOk, RequestContext};
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, PublicKeyUse};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use v_api_permissions::Permissions;

use crate::{
    context::ApiContext,
    permissions::{PermissionStorage, VAppPermission},
};

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct OpenIdConfiguration {
    jwks_uri: String,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn openid_configuration_op<T>(
    rqctx: RequestContext<impl ApiContext<AppPermissions = T>>,
) -> Result<HttpResponseOk<OpenIdConfiguration>, HttpError>
where
    T: VAppPermission,
    Permissions<T>: PermissionStorage,
{
    Ok(HttpResponseOk(OpenIdConfiguration {
        jwks_uri: format!("{}/.well-known/jwks.json", rqctx.v_ctx().public_url()),
    }))
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Jwk {
    kty: String,
    kid: String,
    #[serde(rename = "use")]
    use_: String,
    n: String,
    e: String,
}

#[instrument(skip(rqctx), err(Debug))]
pub async fn jwks_json_op<T>(
    rqctx: RequestContext<impl ApiContext<AppPermissions = T>>,
) -> Result<HttpResponseOk<Jwks>, HttpError>
where
    T: VAppPermission,
    Permissions<T>: PermissionStorage,
{
    let jwks = rqctx.v_ctx().jwks().await;
    Ok(HttpResponseOk(jwks.into()))
}

impl From<&JwkSet> for Jwks {
    fn from(value: &JwkSet) -> Self {
        Self {
            keys: value
                .keys
                .iter()
                .map(|jwk| {
                    let (algo, n, e) = match &jwk.algorithm {
                        AlgorithmParameters::RSA(params) => {
                            ("RSA".to_string(), params.n.clone(), params.e.clone())
                        }
                        _ => panic!("Unexpected key type"),
                    };

                    Jwk {
                        kty: algo,
                        kid: jwk.common.key_id.as_ref().unwrap().clone(),
                        use_: match jwk.common.public_key_use {
                            Some(PublicKeyUse::Signature) => "sig".to_string(),
                            _ => panic!("Unexpected key use"),
                        },
                        n,
                        e,
                    }
                })
                .collect(),
        }
    }
}
