// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Expands every endpoint macro that `v_api::endpoints::handlers` exports as we need to test
//! that the endpoints register correctly.

use dropshot::{ApiDescription, semver::Version};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use v_api::{ApiContext, permissions::VPermission};
use v_api_permission_derive::v_api;

#[v_api(From(VPermission))]
#[derive(Debug, Clone, Hash, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
enum Permissions {
    None,
}

struct Context {}
impl ApiContext for Context {
    type AppPermissions = Permissions;
    fn v_ctx(&self) -> &v_api::VContext<Self::AppPermissions> {
        unimplemented!()
    }
}

/// The macros expand into the module that invokes them, and the saga and metrics endpoints rely
/// on the imports that `v_system_endpoints` brings in, so all three are expanded together.
mod system {
    use super::{Context, Permissions};
    use dropshot::ApiDescription;
    use v_api::{inject_endpoints, v_system_endpoints};
    #[cfg(feature = "metrics")]
    use v_api::{inject_v_metrics_endpoints, v_metrics_endpoints};
    #[cfg(feature = "sagas")]
    use v_api::{inject_v_saga_endpoints, v_saga_endpoints};

    v_system_endpoints!(Context, Permissions);

    #[cfg(feature = "sagas")]
    v_saga_endpoints!(Context, Permissions);

    #[cfg(feature = "metrics")]
    v_metrics_endpoints!(Context);

    /// Register every generated endpoint. The `inject_*` macros unwrap each registration, so a
    /// path that collides with another or a handler dropshot rejects panics here intentionally.
    pub fn api() -> ApiDescription<Context> {
        let mut api = ApiDescription::new();

        inject_endpoints!(api);

        #[cfg(feature = "sagas")]
        inject_v_saga_endpoints!(api);

        #[cfg(feature = "metrics")]
        inject_v_metrics_endpoints!(api);

        api
    }
}

/// The paths of the registered endpoints, taken from the generated OpenAPI document.
fn registered_paths(api: &ApiDescription<Context>) -> BTreeSet<String> {
    let document = api
        .openapi("v-api endpoint macros", Version::new(0, 0, 1))
        .json()
        .expect("Failed to generate an OpenAPI document for the registered endpoints");

    document["paths"]
        .as_object()
        .expect("OpenAPI document has no paths object")
        .keys()
        .cloned()
        .collect()
}

/// The endpoints of `v_system_endpoints` are reachable once `inject_endpoints` has run
#[test]
fn system_endpoints_are_registered() {
    let paths = registered_paths(&system::api());

    for expected in [
        "/.well-known/jwks.json",
        "/.well-known/openid-configuration",
        "/api-user",
        "/api-user/{user_id}",
        "/api-user/{user_id}/token/{api_key_id}",
        "/group",
        "/group/{group_id}",
        "/login/magic/{channel}/send",
        "/login/oauth/{provider}/code/token",
        "/login/oauth/{provider}/device",
        "/magic/client",
        "/mapper",
        "/oauth/client/{client_id}/secret",
        "/self",
    ] {
        assert!(paths.contains(expected), "{expected} was not registered");
    }
}

/// The endpoints of `v_saga_endpoints` are reachable once `inject_v_saga_endpoints` has run
#[cfg(feature = "sagas")]
#[test]
fn saga_endpoints_are_registered() {
    let paths = registered_paths(&system::api());

    assert!(paths.contains("/saga"), "/saga was not registered");
    assert!(
        paths.contains("/saga/{saga}"),
        "/saga/{{saga}} was not registered"
    );
}

/// The endpoint of `v_metrics_endpoints` is reachable once `inject_v_metrics_endpoints` has run
#[cfg(feature = "metrics")]
#[test]
fn metrics_endpoint_is_registered() {
    let paths = registered_paths(&system::api());

    assert!(
        paths.contains("/v/metrics"),
        "/v/metrics was not registered"
    );
}
