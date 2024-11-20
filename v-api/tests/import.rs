// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use v_api::{permissions::VPermission, ApiContext};
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

mod system {
    use super::{Context, Permissions};
    use v_api::v_system_endpoints;

    v_system_endpoints!(Context, Permissions);
}

#[test]
fn run_import_test() {}
