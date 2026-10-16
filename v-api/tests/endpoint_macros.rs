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

/// Every endpoint the API serves, as a method and path pair, taken from the generated OpenAPI
/// document.
///
/// Methods are included because several paths serve more than one, and a path alone would not
/// notice one of them going missing.
fn registered_endpoints(api: &ApiDescription<Context>) -> BTreeSet<(String, String)> {
    let document = api
        .openapi("v-api endpoint macros", Version::new(0, 0, 1))
        .json()
        .expect("Failed to generate an OpenAPI document for the registered endpoints");

    document["paths"]
        .as_object()
        .expect("OpenAPI document has no paths object")
        .iter()
        .flat_map(|(path, item)| {
            item.as_object()
                .expect("OpenAPI path item is not an object")
                .keys()
                .filter(|key| {
                    matches!(
                        key.as_str(),
                        "get" | "put" | "post" | "delete" | "options" | "head" | "patch" | "trace"
                    )
                })
                .map(|method| (method.to_uppercase(), path.clone()))
        })
        .collect()
}

/// Every endpoint the macros define for the features this test was built with.
///
/// This is kept by hand on purpose. A list derived from the macros could not tell an endpoint
/// that was meant to exist from one that was added or dropped by mistake.
fn expected_endpoints() -> BTreeSet<(String, String)> {
    let mut endpoints = vec![
        // OAuth clients
        ("GET", "/oauth/client"),
        ("POST", "/oauth/client"),
        ("GET", "/oauth/client/{client_id}"),
        ("POST", "/oauth/client/{client_id}/secret"),
        ("DELETE", "/oauth/client/{client_id}/secret/{secret_id}"),
        ("POST", "/oauth/client/{client_id}/redirect_uri"),
        (
            "DELETE",
            "/oauth/client/{client_id}/redirect_uri/{redirect_uri_id}",
        ),
        // Magic link clients
        ("GET", "/magic/client"),
        ("POST", "/magic/client"),
        ("GET", "/magic/client/{client_id}"),
        ("POST", "/magic/client/{client_id}/secret"),
        ("DELETE", "/magic/client/{client_id}/secret/{secret_id}"),
        ("POST", "/magic/client/{client_id}/redirect_uri"),
        (
            "DELETE",
            "/magic/client/{client_id}/redirect_uri/{redirect_uri_id}",
        ),
        // OAuth login
        ("GET", "/login/oauth/{provider}/code/authorize"),
        ("GET", "/login/oauth/{provider}/code/callback"),
        ("POST", "/login/oauth/{provider}/code/token"),
        ("GET", "/login/oauth/{provider}/public-pkce"),
        ("GET", "/login/oauth/{provider}/device"),
        ("POST", "/login/oauth/{provider}/device"),
        ("POST", "/login/oauth/{provider}/device/exchange"),
        // Magic link login
        ("POST", "/login/magic/{channel}/send"),
        ("POST", "/login/magic/{channel}/exchange"),
        // Well known
        ("GET", "/.well-known/openid-configuration"),
        ("GET", "/.well-known/jwks.json"),
        // Users
        ("POST", "/api-user-provider/{provider_id}/link-token"),
        ("GET", "/self"),
        ("GET", "/api-user"),
        ("POST", "/api-user"),
        ("GET", "/api-user/{user_id}"),
        ("POST", "/api-user/{user_id}"),
        ("GET", "/api-user/{user_id}/session"),
        ("POST", "/api-user/{user_id}/logout"),
        ("POST", "/api-user/{user_id}/permission"),
        ("DELETE", "/api-user/{user_id}/permission"),
        ("GET", "/api-user/{user_id}/token"),
        ("POST", "/api-user/{user_id}/token"),
        ("GET", "/api-user/{user_id}/token/{api_key_id}"),
        ("DELETE", "/api-user/{user_id}/token/{api_key_id}"),
        ("PUT", "/api-user/{user_id}/contact/email"),
        ("POST", "/api-user/{user_id}/group"),
        ("DELETE", "/api-user/{user_id}/group/{group_id}"),
        ("POST", "/api-user/{user_id}/link"),
        // Groups
        ("GET", "/group"),
        ("POST", "/group"),
        ("PUT", "/group/{group_id}"),
        ("DELETE", "/group/{group_id}"),
        ("GET", "/group-membership/{group_id}"),
        // Mappers
        ("GET", "/mapper"),
        ("POST", "/mapper"),
        ("DELETE", "/mapper/{mapper_id}"),
    ];

    #[cfg(feature = "local-dev")]
    endpoints.push(("POST", "/login/local"));

    #[cfg(feature = "sagas")]
    endpoints.extend([("GET", "/saga"), ("GET", "/saga/{saga}")]);

    #[cfg(feature = "metrics")]
    endpoints.push(("GET", "/v/metrics"));

    endpoints
        .into_iter()
        .map(|(method, path)| (method.to_string(), path.to_string()))
        .collect()
}

/// The macros register exactly the expected endpoints, with none missing and none extra.
///
/// A missing endpoint is usually one that was added to an endpoint macro but not to the matching
/// `inject_*` macro. An extra one is an endpoint nobody meant to expose.
#[test]
fn registered_endpoints_match_the_expected_set() {
    let registered = registered_endpoints(&system::api());
    let expected = expected_endpoints();

    let missing = expected.difference(&registered).collect::<Vec<_>>();
    let unexpected = registered.difference(&expected).collect::<Vec<_>>();

    assert!(
        missing.is_empty() && unexpected.is_empty(),
        "registered endpoints do not match\n  missing {missing:?}\n  unexpected {unexpected:?}"
    );
}
