// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::endpoints::login::UserInfo;

use super::{MapperRule, MappingGrants};

/// Adds a user with a verified email address in a specific domain to a set of groups.
pub struct EmailDomainMapper {
    domain: String,
    grants: MappingGrants,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailDomainMapperData {
    domain: String,
    groups: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct EmailDomainMapperDataV1 {
    domain: String,
    permissions: Option<Value>,
    #[serde(default)]
    groups: Vec<String>,
}

impl EmailDomainMapper {
    pub fn new(data: EmailDomainMapperData) -> Self {
        Self {
            domain: data.domain,
            grants: MappingGrants {
                groups: data.groups,
            },
        }
    }

    pub fn from_v1(data: EmailDomainMapperDataV1) -> Self {
        Self {
            domain: data.domain,
            grants: MappingGrants {
                groups: data.groups,
            },
        }
    }
}

#[async_trait]
impl MapperRule for EmailDomainMapper {
    fn grants(&self) -> &MappingGrants {
        &self.grants
    }

    async fn matches(&self, user: &UserInfo) -> bool {
        user.verified_emails.iter().any(|email| {
            let mut parts = email.split('@');
            parts
                .nth(1)
                .map(|domain| domain == self.domain)
                .unwrap_or(false)
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::{
        endpoints::login::{ExternalUserId, UserInfo},
        mapper::MapperRule,
    };

    use super::{EmailDomainMapper, EmailDomainMapperData};

    fn employees_mapper() -> EmailDomainMapper {
        EmailDomainMapper::new(
            serde_json::from_value::<EmailDomainMapperData>(json!({
                "domain": "example.com",
                "groups": ["employees"],
            }))
            .unwrap(),
        )
    }

    fn user_with_email(email: &str) -> UserInfo {
        UserInfo {
            external_id: ExternalUserId::MagicLink(email.to_string()),
            verified_emails: vec![email.to_string()],
            display_name: None,
            idp_token: None,
        }
    }

    /// As a sanity check, a genuine member of the configured domain matches and is handed the
    /// reserved group. This is the intended behavior.
    #[tokio::test]
    async fn matches_legitimate_domain_member() {
        let mapper = employees_mapper();

        assert!(mapper.matches(&user_with_email("alice@example.com")).await);
        assert_eq!(vec!["employees".to_string()], mapper.grants().groups);
    }

    /// An attacker who owns a lookalike domain whose name merely *ends with* the
    /// configured domain (`evilexample.com` vs `example.com`) must not match. An `ends_with`
    /// check without an `@` boundary would treat `a@evilexample.com` as a member.
    #[tokio::test]
    async fn lookalike_domain_must_not_match() {
        let attacker = user_with_email("a@evilexample.com");

        assert!(
            !employees_mapper().matches(&attacker).await,
            "authorization bypass: an attacker owning the lookalike domain 'evilexample.com' \
             matched a rule intended only for 'example.com' members",
        );
    }

    /// In a related boundary case, a bare suffix match without any `@` separator
    /// (`notexample.com`) must also be rejected.
    #[tokio::test]
    async fn suffix_only_domain_must_not_match() {
        let attacker = user_with_email("user@notexample.com");

        assert!(
            !employees_mapper().matches(&attacker).await,
            "authorization bypass: 'notexample.com' was treated as a member of 'example.com'",
        );
    }
}
