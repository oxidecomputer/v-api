use std::collections::BTreeSet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use v_api::{permissions::VPermission, v_system_endpoints, ApiContext};
use v_api_permission_derive::v_api;

#[v_api(From(VPermission))]
#[derive(
  Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, JsonSchema,
)]
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

v_system_endpoints!(Context, Permissions);
