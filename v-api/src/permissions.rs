// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use partial_struct::partial;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use v_api_permission_derive::v_api;
use v_model::permissions::{AsScope, Permission, PermissionStorage};

pub trait VAppPermission: Permission + From<VPermission> + AsScope + PermissionStorage {}
impl<T> VAppPermission for T where T: Permission + From<VPermission> + AsScope + PermissionStorage {}

pub trait VAppPermissionResponse: Permission {}
impl<T> VAppPermissionResponse for T where T: Permission {}

// TODO: Split permissions into expanded and contracted permission sets. Contracted permissions
// are stored in the database as such

#[v_api(From(VPermission))]
#[partial(VPermissionResponse, attributes(#[serde(tag = "kind", content = "value")]))]
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema, PartialOrd, Ord,
)]
pub enum VPermission {}
