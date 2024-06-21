// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use newtype_uuid::TypedUuid;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, error::Error as StdError, fmt::Debug};
use thiserror::Error;
use v_model::{permissions::Permissions, storage::StoreError, AccessGroupId, Mapper};

use crate::{
    context::VContext, endpoints::login::UserInfo, permissions::VAppPermission,
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
    T: VAppPermission,
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

#[derive(Debug, Error)]
pub enum MappingEngineError {
    #[error("Not mapping rules have been configured")]
    NotRulesConfigured,
    #[error("Mapping engine failed to create mapping")]
    Other(Box<dyn StdError>),
}

pub trait MappingEngine<T> {
    fn create_mapping(&self, value: Mapper) -> Result<Box<dyn MapperRule<T>>, MappingEngineError>;
}

pub struct DefaultMappingEngine;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum MappingRules<T> {
    Default(DefaultMapper<T>),
    EmailAddress(EmailAddressMapper<T>),
    EmailDomain(EmailDomainMapper<T>),
    GitHubUsername(GitHubUsernameMapper<T>),
}

impl<T> MappingEngine<T> for DefaultMappingEngine
where
    T: VAppPermission,
{
    fn create_mapping(&self, value: Mapper) -> Result<Box<dyn MapperRule<T>>, MappingEngineError> {
        serde_json::from_value::<MappingRules<T>>(value.rule)
            .map_err(|err| {
                tracing::error!(?err, "Failed to translate stored rule to mapper");
                MappingEngineError::Other(Box::new(err))
            })
            .map(|rule| match rule {
                MappingRules::Default(rule) => {
                    let res: Box<dyn MapperRule<T>> = Box::new(rule);
                    res
                }
                MappingRules::EmailAddress(rule) => {
                    let res: Box<dyn MapperRule<T>> = Box::new(rule);
                    res
                }
                MappingRules::EmailDomain(rule) => {
                    let res: Box<dyn MapperRule<T>> = Box::new(rule);
                    res
                }
                MappingRules::GitHubUsername(rule) => {
                    let res: Box<dyn MapperRule<T>> = Box::new(rule);
                    res
                }
            })
    }
}
