// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::path::PathBuf;

use secrecy::SecretString;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppConfigError {
    #[error("Encountered invalid log format.")]
    InvalidLogFormatVariant,
}

#[derive(Debug)]
pub enum ServerLogFormat {
    Json,
    Pretty,
}

impl<'de> Deserialize<'de> for ServerLogFormat {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ExternalId;

        impl<'de> Visitor<'de> for ExternalId {
            type Value = ServerLogFormat;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match value {
                    "json" => Ok(Self::Value::Json),
                    "pretty" => Ok(Self::Value::Pretty),
                    _ => Err(de::Error::custom(AppConfigError::InvalidLogFormatVariant)),
                }
            }
        }

        deserializer.deserialize_any(ExternalId)
    }
}

#[derive(Debug, Deserialize)]
pub struct JwtConfig {
    pub default_expiration: i64,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            default_expiration: 3600,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AsymmetricKey {
    Local {
        kid: String,
        // #[serde(with = "serde_bytes")]
        private: String,
        public: String,
    },
    // Kms {
    //     id: String,
    // },
    Ckms {
        kid: String,
        version: u16,
        key: String,
        keyring: String,
        location: String,
        project: String,
    },
}

impl AsymmetricKey {
    pub fn kid(&self) -> &str {
        match self {
            Self::Local { kid, .. } => kid,
            Self::Ckms { kid, .. } => kid,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct SpecConfig {
    pub title: String,
    pub description: String,
    pub contact_url: String,
    pub contact_email: String,
    pub output_path: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct AuthnProviders {
    pub oauth: OAuthProviders,
}

#[derive(Debug, Deserialize)]
pub struct SendGridConfig {
    pub from: String,
    pub key: String,
}

#[derive(Debug, Deserialize)]
pub struct OAuthProviders {
    pub github: Option<OAuthConfig>,
    pub google: Option<OAuthConfig>,
}

#[derive(Debug, Deserialize)]
pub struct OAuthConfig {
    pub device: OAuthDeviceConfig,
    pub web: OAuthWebConfig,
}

#[derive(Debug, Deserialize)]
pub struct OAuthDeviceConfig {
    pub client_id: String,
    pub client_secret: SecretString,
}

#[derive(Debug, Deserialize)]
pub struct OAuthWebConfig {
    pub client_id: String,
    pub client_secret: SecretString,
    pub redirect_uri: String,
}
