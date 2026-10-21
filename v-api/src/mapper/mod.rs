// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use default::DefaultMapperData;
use email_address::EmailAddressMapperData;
use email_domain::EmailDomainMapperData;
use github_username::GitHubUsernameMapperData;
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, error::Error as StdError, fmt::Debug};
use tap::TapFallible;
use thiserror::Error;
use v_model::{AccessGroup, AccessGroupId};

use crate::endpoints::login::UserInfo;

use self::{
    default::DefaultMapper, email_address::EmailAddressMapper, email_domain::EmailDomainMapper,
    github_username::GitHubUsernameMapper,
};

pub mod default;
pub mod email_address;
pub mod email_domain;
pub mod github_username;

#[async_trait]
pub trait MapperRule: Send + Sync + 'static {
    /// Everything the rule hands to a user it matches.
    fn grants(&self) -> &MappingGrants;
    /// Whether the rule applies to the given user.
    async fn matches(&self, user: &UserInfo) -> bool;
}

#[derive(Debug, Error)]
pub enum MappingEngineError {
    #[error("Not mapping rules have been configured")]
    NotRulesConfigured,
    #[error("Mapping engine failed to create mapping")]
    Other(Box<dyn StdError + Send + Sync + 'static>),
}

/// The groups a mapping rule assigns to a user.
#[derive(Debug, Clone, PartialEq)]
pub struct MappingGrants {
    /// Names of the groups a matched user is added to.
    pub groups: Vec<String>,
}

/// Interface for generating mapping rules from mapper configurations
pub trait MappingEngine: Send + Sync + 'static {
    // TODO: Would love to fix this so it isn't a Value...
    /// Creates a mapping rule from a blob of rule data.
    fn create_mapping(&self, rule: &Value) -> Result<Box<dyn MapperRule>, MappingEngineError>;
    // TODO: Would love to fix this so it isn't a Value...
    /// Validates whether the provided data represents a known mapping rule.
    fn validate_mapping_data(&self, value: &Value) -> bool;
}

/// Resolve a rule's configured group names against the known groups. Names are the only
/// linkage between mapper rules and access groups; a configured name that resolves to
/// nothing (a typo, or a group id pasted in place of a name) is silently dropped when
/// the mapper fires, so any unresolved names are logged here.
pub(crate) fn resolve_mapped_groups<T>(
    configured: &[String],
    known: &[AccessGroup<T>],
) -> BTreeSet<TypedUuid<AccessGroupId>> {
    let unresolved = configured
        .iter()
        .filter(|name| !known.iter().any(|group| &&group.name == name))
        .collect::<Vec<_>>();

    if !unresolved.is_empty() {
        tracing::warn!(
            ?unresolved,
            "Mapper references one or more groups that do not exist"
        );
    }

    known
        .iter()
        .filter(|group| configured.contains(&group.name))
        .map(|group| group.id)
        .collect()
}

/// Default implementation of the MappingEngine trait
#[derive(Default)]
pub struct DefaultMappingEngine;

/// The default mapping rule configurations that are supported by the default mapping engine
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum MappingRulesData {
    Default(DefaultMapperData),
    EmailAddress(EmailAddressMapperData),
    EmailDomain(EmailDomainMapperData),
    #[serde(rename = "github_username")]
    GitHubUsername(GitHubUsernameMapperData),
}

impl MappingEngine for DefaultMappingEngine {
    fn create_mapping(&self, rule: &Value) -> Result<Box<dyn MapperRule>, MappingEngineError> {
        serde_json::from_value::<MappingRulesData>(rule.clone())
            .map_err(|err| {
                tracing::error!(?err, "Failed to translate stored rule to mapper");
                MappingEngineError::Other(Box::new(err))
            })
            .map(|rule| {
                let mapping: Box<dyn MapperRule> = match rule {
                    MappingRulesData::Default(data) => Box::new(DefaultMapper::new(data)),
                    MappingRulesData::EmailAddress(data) => Box::new(EmailAddressMapper::new(data)),
                    MappingRulesData::EmailDomain(data) => Box::new(EmailDomainMapper::new(data)),
                    MappingRulesData::GitHubUsername(data) => {
                        Box::new(GitHubUsernameMapper::new(data))
                    }
                };
                mapping
            })
    }

    fn validate_mapping_data(&self, value: &Value) -> bool {
        serde_json::from_value::<MappingRulesData>(value.clone())
            .tap_err(|err| {
                tracing::warn!(?value, ?err, "Failed to parse mapping rule");
            })
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use newtype_uuid::TypedUuid;
    use v_model::{AccessGroup, AccessGroupSource, permissions::Permissions};

    use crate::permissions::VPermission;

    use super::resolve_mapped_groups;

    fn group(name: &str) -> AccessGroup<VPermission> {
        AccessGroup {
            id: TypedUuid::new_v4(),
            name: name.to_string(),
            permissions: Permissions::new(),
            source: AccessGroupSource::Dynamic,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
            generation: 0,
        }
    }

    #[test]
    fn resolves_known_group_names() {
        let known = vec![group("friend-of-oxide"), group("customer")];
        let resolved = resolve_mapped_groups(&["friend-of-oxide".to_string()], &known);

        assert_eq!(resolved.len(), 1);
        assert!(resolved.contains(&known[0].id));
    }

    // Unresolved names (typos, or group ids pasted in place of names) are dropped.
    // resolve_mapped_groups logs them; this pins the resolution behavior.
    #[test]
    fn drops_unresolved_group_names() {
        let known = vec![group("friend-of-oxide")];
        let resolved = resolve_mapped_groups(
            &[
                "friend-of-oxid".to_string(),
                "0e12c84b-dd23-497d-85ef-e32364b1b86f".to_string(),
                "friend-of-oxide".to_string(),
            ],
            &known,
        );

        assert_eq!(resolved.len(), 1);
        assert!(resolved.contains(&known[0].id));
    }
}
