// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::Deserialize;
use v_api_param::StringParam;

/// Where Vanta's API lives. Overridable so that tests can point at a local server.
fn default_base_url() -> String {
    "https://api.vanta.com".to_string()
}

/// The credentials and resource ids of one service's private integration.
///
/// All of these come from the Vanta dashboard: the client id and secret from the developer
/// console, and each resource id from the resource that was created there. The secret is a
/// [`StringParam`] so that it can be read from a file rather than sat inline in service config.
#[derive(Debug, Clone, Deserialize)]
pub struct VantaConfig {
    pub client_id: String,
    pub client_secret: StringParam,

    #[serde(default = "default_base_url")]
    pub base_url: String,

    /// The id of this service's `user_account` resource
    pub user_account_resource_id: String,

    /// The id of the custom resource that access groups are reported as. Groups are skipped when
    /// this is unset, for a service that has not created the custom resource yet.
    #[serde(default)]
    pub group_resource_id: Option<String>,

    /// The id of the custom resource that API keys are reported as. Keys are skipped when this is
    /// unset.
    #[serde(default)]
    pub api_key_resource_id: Option<String>,
}
