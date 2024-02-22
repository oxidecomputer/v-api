// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use permissions::ApiPermission;
use v_api_permissions::{Caller, Permissions};
use v_model::{AccessGroup, ApiKey, ApiUser};

pub mod authn;
pub mod config;
mod context;
pub mod endpoints;
pub mod error;
pub mod initial_data;
pub mod mapper;
pub mod permissions;
mod secrets;
mod util;

pub use context::{ApiContext, SecretContext, VContext};
pub use util::response;

type ApiCaller = Caller<ApiPermission>;
type ApiPermissions = Permissions<ApiPermission>;
type Group = AccessGroup<ApiPermission>;
type User = ApiUser<ApiPermission>;
type UserToken = ApiKey<ApiPermission>;
