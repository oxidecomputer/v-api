// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::endpoints::login::{ExternalUserId, UserInfo};

use super::{MapperRule, MappingGrants};

/// Adds a user with a specific GitHub username to a set of groups.
pub struct GitHubUsernameMapper {
    github_username: String,
    grants: MappingGrants,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GitHubUsernameMapperData {
    github_username: String,
    groups: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GitHubUsernameMapperDataV1 {
    github_username: String,
    permissions: Option<Value>,
    #[serde(default)]
    groups: Vec<String>,
}

impl GitHubUsernameMapper {
    pub fn new(data: GitHubUsernameMapperData) -> Self {
        Self {
            github_username: data.github_username,
            grants: MappingGrants {
                groups: data.groups,
            },
        }
    }

    pub fn from_v1(data: GitHubUsernameMapperDataV1) -> Self {
        Self {
            github_username: data.github_username,
            grants: MappingGrants {
                groups: data.groups,
            },
        }
    }
}

#[async_trait]
impl MapperRule for GitHubUsernameMapper {
    fn grants(&self) -> &MappingGrants {
        &self.grants
    }

    /// Only a GitHub login can match. Display names from other providers are freely editable by
    /// their owners, so they say nothing about who holds a GitHub username.
    async fn matches(&self, user: &UserInfo) -> bool {
        matches!(user.external_id, ExternalUserId::GitHub(_))
            && user
                .display_name
                .as_ref()
                .map(|name| name == &self.github_username)
                .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        endpoints::login::{ExternalUserId, UserInfo},
        mapper::MapperRule,
    };

    use super::{GitHubUsernameMapper, GitHubUsernameMapperData};

    /// A mapper configured to trust the GitHub username "trusted-dev", granting the
    /// `GetMappersAll` permission and membership in the "contributors" group.
    fn trusted_dev_mapper() -> GitHubUsernameMapper {
        GitHubUsernameMapper::new(GitHubUsernameMapperData {
            github_username: "trusted-dev".to_string(),
            groups: vec!["contributors".to_string()],
        })
    }

    fn user(external_id: ExternalUserId) -> UserInfo {
        UserInfo {
            external_id,
            verified_emails: vec!["trusted-dev@example.com".to_string()],
            display_name: Some("trusted-dev".to_string()),
            idp_token: None,
        }
    }

    /// As a sanity check, a genuine GitHub login whose login or display name is "trusted-dev"
    /// matches and is handed the mapped permissions and groups. This is the intended behavior.
    #[tokio::test]
    async fn matches_genuine_github_user() {
        let mapper = trusted_dev_mapper();

        assert!(
            mapper
                .matches(&user(ExternalUserId::GitHub("trusted-dev".to_string())))
                .await
        );
        assert_eq!(vec!["contributors".to_string()], mapper.grants().groups);
    }

    /// An attacker with a free Google account sets the account's freely editable
    /// profile display name to "trusted-dev" and logs in via the Google OAuth flow. Comparing
    /// only the display name without checking the provider would let them impersonate the
    /// trusted GitHub contributor.
    #[tokio::test]
    async fn google_login_must_not_impersonate_github_user() {
        let attacker = user(ExternalUserId::Google("attacker-google-id".to_string()));

        assert!(
            !trusted_dev_mapper().matches(&attacker).await,
            "authorization bypass: a Google login with a spoofed display name 'trusted-dev' \
             matched the GitHub username rule",
        );
    }

    /// The same bypass applies to Zendesk, whose `user.name` is self editable.
    #[tokio::test]
    async fn zendesk_login_must_not_impersonate_github_user() {
        let attacker = user(ExternalUserId::Zendesk("attacker-zendesk-id".to_string()));

        assert!(
            !trusted_dev_mapper().matches(&attacker).await,
            "authorization bypass: a Zendesk login with a spoofed display name 'trusted-dev' \
             matched the GitHub username rule",
        );
    }
}
