// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::collections::BTreeSet;

use async_trait::async_trait;
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tap::TapFallible;
use v_model::{
    permissions::{Permission, Permissions},
    storage::StoreError,
    AccessGroupId, Mapper, MapperId,
};

use crate::{
    context::VContext,
    endpoints::login::UserInfo,
    permissions::{AsScope, PermissionStorage, VPermission},
    util::response::ResourceResult,
};

use self::{
    default::DefaultMapper, email_address::EmailAddressMapper, email_domain::EmailDomainMapper,
    github_username::GitHubUsernameMapper,
};

pub mod default;
pub mod email_address;
pub mod email_domain;
pub mod github_username;

#[async_trait]
pub trait MapperRule<T>: Send + Sync
where
    T: Permission + From<VPermission> + AsScope + PermissionStorage,
{
    async fn permissions_for(
        &self,
        ctx: &VContext<T>,
        user: &UserInfo,
    ) -> Result<Permissions<T>, StoreError>;
    async fn groups_for(
        &self,
        ctx: &VContext<T>,
        user: &UserInfo,
    ) -> ResourceResult<BTreeSet<TypedUuid<AccessGroupId>>, StoreError>;
}

#[derive(Debug, Serialize)]
pub struct Mapping<T> {
    pub id: TypedUuid<MapperId>,
    pub name: String,
    pub rule: MappingRules<T>,
    pub activations: Option<i32>,
    pub max_activations: Option<i32>,
}

impl<T> TryFrom<Mapper> for Mapping<T>
where
    T: DeserializeOwned,
{
    type Error = serde_json::Error;

    fn try_from(value: Mapper) -> Result<Self, Self::Error> {
        serde_json::from_value::<MappingRules<T>>(value.rule)
            .tap_err(|err| {
                tracing::error!(?err, "Failed to translate stored rule to mapper");
            })
            .map(|rule| Mapping {
                id: value.id,
                name: value.name,
                rule,
                activations: value.activations,
                max_activations: value.max_activations,
            })
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum MappingRules<T> {
    Default(DefaultMapper<T>),
    EmailAddress(EmailAddressMapper<T>),
    EmailDomain(EmailDomainMapper<T>),
    GitHubUsername(GitHubUsernameMapper<T>),
}

#[async_trait]
impl<T> MapperRule<T> for MappingRules<T>
where
    T: Permission + From<VPermission> + AsScope + PermissionStorage,
{
    async fn permissions_for(
        &self,
        ctx: &VContext<T>,
        user: &UserInfo,
    ) -> Result<Permissions<T>, StoreError> {
        match self {
            Self::Default(rule) => rule.permissions_for(ctx, user).await,
            Self::EmailAddress(rule) => rule.permissions_for(ctx, user).await,
            Self::EmailDomain(rule) => rule.permissions_for(ctx, user).await,
            Self::GitHubUsername(rule) => rule.permissions_for(ctx, user).await,
        }
    }

    async fn groups_for(
        &self,
        ctx: &VContext<T>,
        user: &UserInfo,
    ) -> ResourceResult<BTreeSet<TypedUuid<AccessGroupId>>, StoreError> {
        match self {
            Self::Default(rule) => rule.groups_for(ctx, user).await,
            Self::EmailAddress(rule) => rule.groups_for(ctx, user).await,
            Self::EmailDomain(rule) => rule.groups_for(ctx, user).await,
            Self::GitHubUsername(rule) => rule.groups_for(ctx, user).await,
        }
    }
}
