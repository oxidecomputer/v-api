// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::endpoints::login::UserInfo;

use super::{MapperRule, MappingGrants};

/// Adds a user with a specific verified email address to a set of groups.
pub struct EmailAddressMapper {
    email: String,
    grants: MappingGrants,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailAddressMapperData {
    email: String,
    groups: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct EmailAddressMapperDataV1 {
    email: String,
    permissions: Option<Value>,
    #[serde(default)]
    groups: Vec<String>,
}

impl EmailAddressMapper {
    pub fn new(data: EmailAddressMapperData) -> Self {
        Self {
            email: data.email,
            grants: MappingGrants {
                groups: data.groups,
            },
        }
    }

    pub fn from_v1(data: EmailAddressMapperDataV1) -> Self {
        Self {
            email: data.email,
            grants: MappingGrants {
                groups: data.groups,
            },
        }
    }
}

#[async_trait]
impl MapperRule for EmailAddressMapper {
    fn grants(&self) -> &MappingGrants {
        &self.grants
    }

    async fn matches(&self, user: &UserInfo) -> bool {
        user.verified_emails
            .iter()
            .any(|email| email == &self.email)
    }
}
