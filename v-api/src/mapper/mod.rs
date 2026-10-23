// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use default::{DefaultMapperData, DefaultMapperDataV1};
use email_address::{EmailAddressMapperData, EmailAddressMapperDataV1};
use email_domain::{EmailDomainMapperData, EmailDomainMapperDataV1};
use github_username::{GitHubUsernameMapperData, GitHubUsernameMapperDataV1};
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

/// What a mapping rule assigns to a user.
#[derive(Debug, Clone, PartialEq)]
pub struct MappingGrants {
    /// Names of the groups a matched user is added to.
    pub groups: Vec<String>,
}

/// Interface for generating mapping rules from mapper configurations
pub trait MappingEngine: Send + Sync + 'static {
    // TODO: Would love to fix this so it isn't a Value...
    /// Independent of a mapper rule being valid, and engine may only accept a mapper based on
    /// arbitrary restrictions.
    fn is_accepted(&self, value: &Value) -> bool;
    // TODO: Would love to fix this so it isn't a Value...
    /// Creates a mapping rule from a blob of rule data. This must be backwards compatible in terms
    /// of reading and parsing rules. The output is expected to be a current rule.
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

/// Current mapping rules that have dropped support for direct permission assignments, and require
/// at least one group assignment.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum MappingRulesData {
    Default(DefaultMapperData),
    EmailAddress(EmailAddressMapperData),
    EmailDomain(EmailDomainMapperData),
    #[serde(rename = "github_username")]
    GitHubUsername(GitHubUsernameMapperData),
}

/// V1 rules can carry permission assignments which are no longer supported.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum MappingRulesDataV1 {
    Default(DefaultMapperDataV1),
    EmailAddress(EmailAddressMapperDataV1),
    EmailDomain(EmailDomainMapperDataV1),
    #[serde(rename = "github_username")]
    GitHubUsername(GitHubUsernameMapperDataV1),
}

/// A rule as it may be stored. This may be either a legacy v1 rule or a current rule.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum StoredMappingRule {
    Current(MappingRulesData),
    V1(MappingRulesDataV1),
}

impl From<StoredMappingRule> for Box<dyn MapperRule> {
    fn from(rule: StoredMappingRule) -> Self {
        match rule {
            StoredMappingRule::Current(MappingRulesData::Default(data)) => {
                Box::new(DefaultMapper::new(data))
            }
            StoredMappingRule::Current(MappingRulesData::EmailAddress(data)) => {
                Box::new(EmailAddressMapper::new(data))
            }
            StoredMappingRule::Current(MappingRulesData::EmailDomain(data)) => {
                Box::new(EmailDomainMapper::new(data))
            }
            StoredMappingRule::Current(MappingRulesData::GitHubUsername(data)) => {
                Box::new(GitHubUsernameMapper::new(data))
            }
            StoredMappingRule::V1(MappingRulesDataV1::Default(data)) => {
                Box::new(DefaultMapper::from_v1(data))
            }
            StoredMappingRule::V1(MappingRulesDataV1::EmailAddress(data)) => {
                Box::new(EmailAddressMapper::from_v1(data))
            }
            StoredMappingRule::V1(MappingRulesDataV1::EmailDomain(data)) => {
                Box::new(EmailDomainMapper::from_v1(data))
            }
            StoredMappingRule::V1(MappingRulesDataV1::GitHubUsername(data)) => {
                Box::new(GitHubUsernameMapper::from_v1(data))
            }
        }
    }
}

impl MappingEngine for DefaultMappingEngine {
    fn is_accepted(&self, value: &Value) -> bool {
        serde_json::from_value::<MappingRulesData>(value.clone()).is_ok()
    }

    fn create_mapping(&self, rule: &Value) -> Result<Box<dyn MapperRule>, MappingEngineError> {
        serde_json::from_value::<StoredMappingRule>(rule.clone())
            .map_err(|err| {
                tracing::error!(?err, "Failed to translate stored rule to mapper");
                MappingEngineError::Other(Box::new(err))
            })
            .map(Box::<dyn MapperRule>::from)
    }

    fn validate_mapping_data(&self, value: &Value) -> bool {
        serde_json::from_value::<StoredMappingRule>(value.clone())
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
    use serde_json::{Value, json};
    use v_model::{AccessGroup, AccessGroupSource, permissions::Permissions};

    use crate::permissions::VPermission;

    use super::{DefaultMappingEngine, MappingEngine, resolve_mapped_groups};

    fn create(rule: Value) -> super::MappingGrants {
        DefaultMappingEngine
            .create_mapping(&rule)
            .unwrap_or_else(|err| panic!("{rule} was not read: {err}"))
            .grants()
            .clone()
    }

    /// One rule of each type in the original shape, granting permissions alongside groups
    fn original_rules(permissions: &Value) -> Vec<Value> {
        vec![
            json!({ "rule": "default", "permissions": permissions, "groups": ["a"] }),
            json!({ "rule": "email_address", "email": "a@example.com", "permissions": permissions, "groups": ["a"] }),
            json!({ "rule": "email_domain", "domain": "example.com", "permissions": permissions, "groups": ["a"] }),
            json!({ "rule": "github_username", "github_username": "a", "permissions": permissions, "groups": ["a"] }),
        ]
    }

    /// Rules stored before mappers were limited to groups keep only their groups
    #[test]
    fn reads_rules_in_the_original_shape() {
        let permissions = serde_json::to_value(Permissions::<VPermission>::from(vec![
            VPermission::CreateGroup,
        ]))
        .unwrap();

        for rule in original_rules(&permissions) {
            let grants = create(rule.clone());
            assert_eq!(vec!["a".to_string()], grants.groups, "{rule}");
        }
    }

    /// In the original shape a rule could leave out its groups entirely
    #[test]
    fn reads_original_rules_without_groups() {
        let permissions = serde_json::to_value(Permissions::<VPermission>::from(vec![
            VPermission::CreateGroup,
        ]))
        .unwrap();
        let grants = create(json!({ "rule": "default", "permissions": permissions }));

        assert!(grants.groups.is_empty());

        let grants = create(json!({ "rule": "email_domain", "domain": "example.com" }));
        assert!(grants.groups.is_empty());
    }

    /// A rule in the current shape grants only groups
    #[test]
    fn current_rules_grant_no_permissions() {
        let grants = create(json!({ "rule": "default", "groups": ["a"] }));

        assert_eq!(vec!["a".to_string()], grants.groups);
    }

    #[test]
    fn all_rules_should_validate() {
        let engine = DefaultMappingEngine;
        let permissions = serde_json::to_value(Permissions::<VPermission>::from(vec![
            VPermission::CreateGroup,
        ]))
        .unwrap();

        assert!(engine.validate_mapping_data(&json!({ "rule": "default", "groups": ["a"] })));

        for rule in original_rules(&permissions) {
            assert!(engine.validate_mapping_data(&rule), "{rule}");
        }
        assert!(engine.validate_mapping_data(&json!({ "rule": "default" })));
        assert!(
            engine
                .validate_mapping_data(&json!({ "rule": "email_domain", "domain": "example.com" }))
        );
    }

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
