// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures::executor::block_on;
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, KeyAlgorithm, PublicKeyUse, RSAKeyParameters,
    RSAKeyType,
};
use rsa::{
    pkcs1v15::{SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    traits::PublicKeyParts,
    RsaPrivateKey, RsaPublicKey,
};
use secrecy::ExposeSecret;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer,
};
use std::path::PathBuf;
use thiserror::Error;
use v_api_param::StringParam;

use crate::{
    authn::{
        jwt::JwtSignerError, CloudKmsError, CloudKmsSigningKey, CloudKmsVerifyingKey,
        LocalSigningKey, LocalVerifyingKey, Signer, SignerKey, SigningKeyError, Verifier,
    },
    util::cloud_kms_client,
};

#[derive(Debug, Error)]
pub enum AppConfigError {
    #[error("Encountered invalid log format.")]
    InvalidLogFormatVariant,
}

#[derive(Debug, Default)]
pub enum ServerLogFormat {
    #[default]
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
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AsymmetricKey {
    LocalVerifier {
        kid: String,
        public: StringParam,
    },
    LocalSigner {
        kid: String,
        private: StringParam,
    },
    CkmsVerifier {
        kid: String,
        version: u16,
        key: String,
        keyring: String,
        location: String,
        project: String,
    },
    CkmsSigner {
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
            Self::LocalVerifier { kid, .. } => kid,
            Self::LocalSigner { kid, .. } => kid,
            Self::CkmsVerifier { kid, .. } => kid,
            Self::CkmsSigner { kid, .. } => kid,
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
    pub key: StringParam,
}

#[derive(Debug, Deserialize)]
pub struct OAuthProviders {
    pub github: Option<OAuthConfig>,
    pub google: Option<OAuthConfig>,
    pub zendesk: Option<OAuthConfig>,
}

#[derive(Debug, Deserialize)]
pub struct OAuthConfig {
    pub device: OAuthDeviceConfig,
    pub web: OAuthWebConfig,
}

#[derive(Debug, Deserialize)]
pub struct OAuthDeviceConfig {
    pub client_id: String,
    pub client_secret: StringParam,
}

#[derive(Debug, Deserialize)]
pub struct OAuthWebConfig {
    pub client_id: String,
    pub client_secret: StringParam,
    pub redirect_uri: String,
}

impl AsymmetricKey {
    pub fn resolve_signer(&self, path: Option<PathBuf>) -> Result<Signer, SigningKeyError> {
        Ok(Signer::new(
            self.kid().to_string(),
            match self {
                AsymmetricKey::LocalSigner { private, .. } => {
                    let private_key =
                        RsaPrivateKey::from_pkcs8_pem(private.resolve(path)?.expose_secret())
                            .unwrap();
                    let signing_key = SigningKey::new(private_key);
                    SignerKey::Local(LocalSigningKey::new(signing_key))
                }
                AsymmetricKey::CkmsSigner { .. } => SignerKey::Ckms(CloudKmsSigningKey::new(
                    block_on(cloud_kms_client())?,
                    self.cloud_kms_key_name().unwrap(),
                )),
                _ => Err(SigningKeyError::KeyDoesNotSupportFunction)?,
            },
        ))
    }

    pub async fn resolve_verifier(
        &self,
        path: Option<PathBuf>,
    ) -> Result<Verifier, SigningKeyError> {
        Ok(match self {
            AsymmetricKey::LocalVerifier { .. } => Verifier::Local(LocalVerifyingKey::new(
                VerifyingKey::new(self.public_key(path)?),
            )),
            AsymmetricKey::CkmsVerifier { .. } => Verifier::Ckms(CloudKmsVerifyingKey::new(
                VerifyingKey::new(self.public_key(path)?),
            )),
            _ => Err(SigningKeyError::KeyDoesNotSupportFunction)?,
        })
    }

    pub fn resolve_jwk(&self, path: Option<PathBuf>) -> Result<Jwk, JwtSignerError> {
        let key_id = self.kid();
        let public_key = self.public_key(path).map_err(JwtSignerError::InvalidKey)?;

        Ok(Jwk {
            common: CommonParameters {
                public_key_use: Some(PublicKeyUse::Signature),
                key_operations: None,
                key_algorithm: Some(KeyAlgorithm::RS256),
                key_id: Some(key_id.to_string()),
                x509_chain: None,
                x509_sha1_fingerprint: None,
                x509_sha256_fingerprint: None,
                x509_url: None,
            },
            algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                key_type: RSAKeyType::RSA,
                n: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                e: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
            }),
        })
    }

    fn public_key(&self, path: Option<PathBuf>) -> Result<RsaPublicKey, SigningKeyError> {
        Ok(match self {
            AsymmetricKey::LocalVerifier { public, .. } => {
                RsaPublicKey::from_public_key_pem(public.resolve(path)?.expose_secret())?
            }
            AsymmetricKey::CkmsVerifier { .. } => {
                let public_key = block_on(async {
                    let kms_client = cloud_kms_client().await?;

                    Ok::<_, SigningKeyError>(
                        kms_client
                            .projects()
                            .locations_key_rings_crypto_keys_crypto_key_versions_get_public_key(
                                &self.cloud_kms_key_name().unwrap(),
                            )
                            .doit()
                            .await
                            .map_err(CloudKmsError::from)
                            .map_err(Box::new)?
                            .1,
                    )
                })?;

                let pem = public_key
                    .pem
                    .ok_or(CloudKmsError::MissingPem)
                    .map_err(Box::new)?;
                RsaPublicKey::from_public_key_pem(&pem)?
            }
            _ => Err(SigningKeyError::KeyDoesNotSupportFunction)?,
        })
    }

    fn cloud_kms_key_name(&self) -> Option<String> {
        match self {
            AsymmetricKey::CkmsSigner {
                version,
                key,
                keyring,
                location,
                project,
                ..
            } => Some(format!(
                "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}/cryptoKeyVersions/{}",
                project, location, keyring, key, version
            )),
            AsymmetricKey::CkmsVerifier {
                version,
                key,
                keyring,
                location,
                project,
                ..
            } => Some(format!(
                "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}/cryptoKeyVersions/{}",
                project, location, keyring, key, version
            )),
            _ => None,
        }
    }
}
