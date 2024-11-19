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
use thiserror::Error;
use v_model::{
    permissions::{Caller, Permissions},
    storage::StoreError,
    AccessGroupId, Mapper,
};

use crate::{
    context::group::GroupContext, endpoints::login::UserInfo, permissions::VAppPermission,
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
/// Mapping rules that determine permissions and groups for users
pub trait MapperRule<T>: Send + Sync
where
    T: VAppPermission,
{
    /// Determines the permissions for a given user.
    async fn permissions_for(&self, user: &UserInfo) -> Result<Permissions<T>, StoreError>;
    /// Determines the access groups for a given user.
    async fn groups_for(
        &self,
        user: &UserInfo,
    ) -> ResourceResult<BTreeSet<TypedUuid<AccessGroupId>>, StoreError>;
}

#[derive(Debug, Error)]
pub enum MappingEngineError {
    #[error("Not mapping rules have been configured")]
    NotRulesConfigured,
    #[error("Mapping engine failed to create mapping")]
    Other(Box<dyn StdError + Send + Sync + 'static>),
}

/// Interface for generating mapping rules from mapper configurations
pub trait MappingEngine<T>: Send + Sync + 'static {
    /// Creates a new mapping rule from a Mapper configuration
    fn create_mapping(&self, value: Mapper) -> Result<Box<dyn MapperRule<T>>, MappingEngineError>;
    /// Validates whether the provided data represents a known mapping rule
    fn validate_mapping_data(&self, value: &Value) -> bool;
}

/// Default implementation of the MappingEngine trait
pub struct DefaultMappingEngine<T> {
    caller: Caller<T>,
    group: GroupContext<T>,
}

impl<T> DefaultMappingEngine<T>
where
    T: VAppPermission,
{
    pub fn new(caller: Caller<T>, group: GroupContext<T>) -> Self {
        Self { caller, group }
    }
}

/// The default mapping rule configurations that are supported by the default mapping engine
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "rule", rename_all = "snake_case")]
pub enum MappingRulesData<T> {
    Default(DefaultMapperData<T>),
    EmailAddress(EmailAddressMapperData<T>),
    EmailDomain(EmailDomainMapperData<T>),
    #[serde(rename = "github_username")]
    GitHubUsername(GitHubUsernameMapperData<T>),
}

impl<T> MappingEngine<T> for DefaultMappingEngine<T>
where
    T: VAppPermission,
{
    fn create_mapping(&self, value: Mapper) -> Result<Box<dyn MapperRule<T>>, MappingEngineError> {
        serde_json::from_value::<MappingRulesData<T>>(value.rule)
            .map_err(|err| {
                tracing::error!(?err, "Failed to translate stored rule to mapper");
                MappingEngineError::Other(Box::new(err))
            })
            .map(move |rule| match rule {
                MappingRulesData::Default(data) => {
                    let res: Box<dyn MapperRule<T>> = Box::new(DefaultMapper::new(
                        self.caller.clone(),
                        self.group.clone(),
                        data,
                    ));
                    res
                }
                MappingRulesData::EmailAddress(data) => {
                    let res: Box<dyn MapperRule<T>> = Box::new(EmailAddressMapper::new(
                        self.caller.clone(),
                        self.group.clone(),
                        data,
                    ));
                    res
                }
                MappingRulesData::EmailDomain(data) => {
                    let res: Box<dyn MapperRule<T>> = Box::new(EmailDomainMapper::new(
                        self.caller.clone(),
                        self.group.clone(),
                        data,
                    ));
                    res
                }
                MappingRulesData::GitHubUsername(data) => {
                    let res: Box<dyn MapperRule<T>> = Box::new(GitHubUsernameMapper::new(
                        self.caller.clone(),
                        self.group.clone(),
                        data,
                    ));
                    res
                }
            })
    }

    fn validate_mapping_data(&self, value: &Value) -> bool {
        serde_json::from_value::<MappingRulesData<T>>(value.clone()).is_ok()
    }
}
