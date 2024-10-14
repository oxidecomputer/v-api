// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use dropshot::HttpError;
use schemars::JsonSchema;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use thiserror::Error;

use crate::{
    permissions::VPermission,
    util::response::{bad_request, internal_error},
};

#[cfg(feature = "local-dev")]
pub mod local;
pub mod magic_link;
pub mod oauth;

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub enum LoginPermissions {
    All,
    Specific(Vec<VPermission>),
}

#[derive(Debug, Error)]
pub enum LoginError {
    #[error("Requested token lifetime exceeds maximum configuration duration")]
    ExcessTokenExpiration,
    #[error("Failed to parse access token {0}")]
    FailedToParseToken(#[from] serde_json::Error),
    #[error("Unsupported provider specified")]
    InvalidProvider,
    #[error("Failed to fetch user info {0}")]
    UserInfo(#[from] UserInfoError),
}

impl From<LoginError> for HttpError {
    fn from(err: LoginError) -> Self {
        match err {
            LoginError::ExcessTokenExpiration => {
                let mut err =
                    bad_request("Requested expiration exceeds maximum allowed token duration");
                err.error_code = Some("INVALID_TOKEN_EXPIRATION".to_string());

                err
            }
            LoginError::FailedToParseToken(_) => internal_error("Failed to get access token"),
            LoginError::InvalidProvider => bad_request("Unsupported provider"),
            LoginError::UserInfo(_) => internal_error("Failed to fetch user info"),
        }
    }
}

#[derive(Debug)]
pub enum ExternalUserId {
    GitHub(String),
    Google(String),
    #[cfg(feature = "local-dev")]
    Local(String),
    MagicLink(String),
}

impl ExternalUserId {
    pub fn id(&self) -> &str {
        match self {
            Self::GitHub(id) => id,
            Self::Google(id) => id,
            #[cfg(feature = "local-dev")]
            Self::Local(id) => id,
            Self::MagicLink(id) => id,
        }
    }

    pub fn provider(&self) -> &str {
        match self {
            Self::GitHub(_) => "github",
            Self::Google(_) => "google",
            #[cfg(feature = "local-dev")]
            Self::Local(_) => "local",
            Self::MagicLink(_) => "magic-link",
        }
    }
}

#[derive(Debug, Error)]
pub enum ExternalUserIdDeserializeError {
    #[error("External identifier is empty")]
    Empty,
    #[error("External identifier did not have a valid prefix")]
    InvalidPrefix,
}

impl Serialize for ExternalUserId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            ExternalUserId::GitHub(id) => serializer.serialize_str(&format!("github-{}", id)),
            ExternalUserId::Google(id) => serializer.serialize_str(&format!("google-{}", id)),
            #[cfg(feature = "local-dev")]
            ExternalUserId::Local(id) => serializer.serialize_str(&format!("local-{}", id)),
            ExternalUserId::MagicLink(id) => {
                serializer.serialize_str(&format!("magic-link-{}", id))
            }
        }
    }
}

impl<'de> Deserialize<'de> for ExternalUserId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ExternalId;

        impl<'de> Visitor<'de> for ExternalId {
            type Value = ExternalUserId;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if let Some(("", id)) = value.split_once("github-") {
                    if !id.is_empty() {
                        Ok(ExternalUserId::GitHub(id.to_string()))
                    } else {
                        Err(de::Error::custom(ExternalUserIdDeserializeError::Empty))
                    }
                } else if let Some(("", id)) = value.split_once("google-") {
                    if !id.is_empty() {
                        Ok(ExternalUserId::Google(id.to_string()))
                    } else {
                        Err(de::Error::custom(ExternalUserIdDeserializeError::Empty))
                    }
                } else if let Some(("", id)) = value.split_once("local-") {
                    #[cfg(feature = "local-dev")]
                    {
                        if !id.is_empty() {
                            Ok(ExternalUserId::Local(id.to_string()))
                        } else {
                            Err(de::Error::custom(ExternalUserIdDeserializeError::Empty))
                        }
                    }
                    #[cfg(not(feature = "local-dev"))]
                    {
                        tracing::info!(id, "Attempted to authenticate with local token");
                        Err(de::Error::custom(
                            ExternalUserIdDeserializeError::InvalidPrefix,
                        ))
                    }
                } else if let Some(("", id)) = value.split_once("magic-link-") {
                    if !id.is_empty() {
                        Ok(ExternalUserId::MagicLink(id.to_string()))
                    } else {
                        Err(de::Error::custom(ExternalUserIdDeserializeError::Empty))
                    }
                } else {
                    Err(de::Error::custom(
                        ExternalUserIdDeserializeError::InvalidPrefix,
                    ))
                }
            }
        }

        deserializer.deserialize_any(ExternalId)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserInfo {
    pub external_id: ExternalUserId,
    pub verified_emails: Vec<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Error)]
pub enum UserInfoError {
    #[error("Failed to send user info request {0}")]
    Client(#[from] reqwest::Error),
    #[error("Failed to deserialize user info {0}")]
    Deserialize(#[from] serde_json::Error),
    #[error("Failed to create user info request {0}")]
    Http(#[from] http::Error),
    #[error("User information is missing")]
    MissingUserInfoData(String),
}

#[async_trait]
pub trait UserInfoProvider {
    async fn get_user_info(&self, token: &str) -> Result<UserInfo, UserInfoError>;
}
