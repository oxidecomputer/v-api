// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::endpoints::login::UserInfo;

use super::{MapperRule, MappingGrants};

/// Adds all users to a set of groups.
pub struct DefaultMapper {
    grants: MappingGrants,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DefaultMapperData {
    groups: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DefaultMapperDataV1 {
    permissions: Option<Value>,
    #[serde(default)]
    groups: Vec<String>,
}

impl DefaultMapper {
    pub fn new(data: DefaultMapperData) -> Self {
        Self {
            grants: MappingGrants {
                groups: data.groups,
            },
        }
    }

    pub fn from_v1(data: DefaultMapperDataV1) -> Self {
        Self {
            grants: MappingGrants {
                groups: data.groups,
            },
        }
    }
}

#[async_trait]
impl MapperRule for DefaultMapper {
    fn grants(&self) -> &MappingGrants {
        &self.grants
    }

    async fn matches(&self, _user: &UserInfo) -> bool {
        true
    }
}
