// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use base64::{prelude::BASE64_STANDARD, Engine};
use crc32c::crc32c;
use dropshot::{HttpError, RequestContext, SharedExtractor};
use dropshot_authorization_header::bearer::BearerAuth;
use google_cloudkms1::{
    api::AsymmetricSignRequest, hyper_rustls::HttpsConnector,
    hyper_util::client::legacy::connect::HttpConnector, CloudKMS,
};
use rsa::{
    pkcs1v15::Signature,
    pkcs1v15::{SigningKey, VerifyingKey},
    signature::{RandomizedSigner, SignatureEncoding, Verifier as RsaVerifier},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Debug;
use thiserror::Error;
use v_api_param::ParamResolutionError;
use v_model::permissions::PermissionStorage;

use crate::{
    authn::key::RawKey, context::ApiContext, permissions::VAppPermission,
    util::response::unauthorized,
};

use self::jwt::Jwt;

pub mod jwt;
pub mod key;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Failed to extract token")]
    FailedToExtract,
    #[error("Request does not have a token")]
    NoToken,
}

// A token that provides authentication and optionally (JWT) authorization claims
pub enum AuthToken {
    ApiKey(RawKey),
    Jwt(Jwt),
}

impl Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_struct("AuthToken").finish(),
            Self::Jwt(jwt) => f.debug_struct("AuthToken").field("jwt", jwt).finish(),
        }
    }
}

impl AuthToken {
    // Extract an AuthToken from a Dropshot request
    pub async fn extract<T>(
        rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    ) -> Result<AuthToken, AuthError>
    where
        T: VAppPermission + PermissionStorage,
    {
        // Ensure there is a bearer, without it there is nothing else to do
        let bearer = BearerAuth::from_request(rqctx).await.map_err(|err| {
            tracing::info!(?err, "Failed to extract bearer auth");
            AuthError::NoToken
        })?;

        // Check that the extracted token actually contains a value
        let token = bearer.consume().ok_or_else(|| {
            tracing::debug!("Bearer auth is empty");
            AuthError::NoToken
        })?;

        let ctx = rqctx.context();

        // Attempt to decode an API key from the token. If that fails then attempt to verify the
        // token as a JWT
        let jwt = Jwt::new(ctx.v_ctx(), &token).await;

        match jwt {
            Ok(token) => {
                tracing::trace!("Extracted auth token");
                Ok(AuthToken::Jwt(token))
            }
            Err(err) => {
                tracing::debug!(
                    ?err,
                    token_size = token.len(),
                    "Token is not a JWT, falling back to API key"
                );

                Ok(AuthToken::ApiKey(
                    RawKey::try_from(token.as_str()).map_err(|err| {
                        tracing::info!(?err, "Failed to parse API key");
                        AuthError::FailedToExtract
                    })?,
                ))
            }
        }
    }
}

impl From<AuthError> for HttpError {
    fn from(err: AuthError) -> Self {
        tracing::trace!(?err, "Failed to extract auth token");
        unauthorized()
    }
}

#[derive(Debug, Error)]
pub enum SigningKeyError {
    #[error("Cloud signing failed: {0}")]
    CloudKmsError(#[from] Box<CloudKmsError>),
    #[error("Failed to immediately verify generated signature")]
    GeneratedInvalidSignature,
    #[error("Failed to parse public key: {0}")]
    InvalidPublicKey(#[from] rsa::pkcs8::spki::Error),
    #[error("Key does not support the requested function")]
    KeyDoesNotSupportFunction,
    #[error("Failed to resolve parameter")]
    Param(#[from] ParamResolutionError),
    #[error("Invalid signature: {0}")]
    Signature(#[from] rsa::signature::Error),
}

#[derive(Debug, Default)]
pub struct VerificationResult {
    pub verified: bool,
    pub errors: Vec<Option<SigningKeyError>>,
}

#[async_trait]
pub trait Sign: Send + Sync {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningKeyError>;
}

#[async_trait]
pub trait Verify: Send + Sync {
    fn verify(&self, message: &[u8], signature: &[u8]) -> VerificationResult;
}

// A signer that stores a local in memory key for signing new JWTs
pub struct LocalSigningKey {
    signing_key: SigningKey<Sha256>,
}

impl LocalSigningKey {
    pub fn new(signing_key: SigningKey<Sha256>) -> Self {
        Self { signing_key }
    }
}

// A signer that stores a local in memory key for verifying JWTs
pub struct LocalVerifyingKey {
    verifying_key: VerifyingKey<Sha256>,
}

impl LocalVerifyingKey {
    pub fn new(verifying_key: VerifyingKey<Sha256>) -> Self {
        Self { verifying_key }
    }
}

#[derive(Debug, Error)]
pub enum CloudKmsError {
    #[error(transparent)]
    ClientError(#[from] google_cloudkms1::Error),
    #[error("Signature received failed CRC check")]
    CorruptedSignature,
    #[error("Failed to decode signature: {0}")]
    FailedToDecodeSignature(#[from] base64::DecodeError),
    #[error("Failed to deserialize response: {0}")]
    FailedToDeserialize(serde_json::error::Error),
    #[error("CloudKMS returned an invalid public key: {0}")]
    InvalidPem(#[from] rsa::pkcs8::spki::Error),
    #[error("CloudKMS did not return a public key")]
    MissingPem,
    #[error("CloudKMS signing request did not return a signature")]
    MissingSignature,
    #[error("Failed to find remote key")]
    RemoteKeyAuthMissing(#[from] std::io::Error),
}

// Signer that relies on a private key stored in GCP. This signer never
// has direct access to the private key
pub struct CloudKmsSigningKey {
    client: CloudKMS<HttpsConnector<HttpConnector>>,
    key_name: String,
}

impl CloudKmsSigningKey {
    pub fn new(client: CloudKMS<HttpsConnector<HttpConnector>>, key_name: String) -> Self {
        Self { client, key_name }
    }
}

// Verifier that fetches and stores a public key from Cloud KMS.
pub struct CloudKmsVerifyingKey {
    verifying_key: VerifyingKey<Sha256>,
}

impl CloudKmsVerifyingKey {
    pub fn new(verifying_key: VerifyingKey<Sha256>) -> Self {
        Self { verifying_key }
    }
}

// A fallback type for deserializing signature responses. google-cloudkms1 currently fails to decode
// the base64 signature due to assuming it to be url safe
#[derive(Debug, Serialize, Deserialize)]
pub struct CloudKmsSignatureResponse {
    pub name: String,
    // #[serde(with = "serde_bytes")]
    pub signature: String,
    #[serde(rename = "signatureCrc32c")]
    pub signature_crc32c: String,
}

pub struct Signer {
    pub kid: String,
    pub key: SignerKey,
}

impl Signer {
    pub fn new(kid: String, key: SignerKey) -> Self {
        Self { kid, key }
    }
}

pub enum SignerKey {
    Local(LocalSigningKey),
    Ckms(CloudKmsSigningKey),
}

impl Signer {
    pub async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningKeyError> {
        match &self.key {
            SignerKey::Local(local) => {
                tracing::trace!("Signing message");
                let mut rng = rand::thread_rng();
                let signature = local.signing_key.sign_with_rng(&mut rng, message).to_vec();

                Ok(signature)
            }
            SignerKey::Ckms(ckms) => {
                let mut hasher = Sha256::new();
                hasher.update(message);
                let digest = hasher.finalize();

                let check = crc32c(&digest);

                let response = ckms
                    .client
                    .projects()
                    .locations_key_rings_crypto_keys_crypto_key_versions_asymmetric_sign(
                        AsymmetricSignRequest {
                            data: None,
                            data_crc32c: None,
                            digest: Some(google_cloudkms1::api::Digest {
                                sha256: Some(digest.to_vec()),
                                sha384: None,
                                sha512: None,
                            }),
                            digest_crc32c: Some(check as i64),
                        },
                        &ckms.key_name,
                    )
                    .doit()
                    .await;

                tracing::info!("Received response from remote signer");

                let signature = match response {
                    Ok((_, response)) => {
                        tracing::info!("Library deserialization succeeded");
                        response
                            .signature
                            .ok_or_else(|| Box::new(CloudKmsError::MissingSignature))
                    }
                    Err(google_cloudkms1::Error::JsonDecodeError(body, _)) => {
                        tracing::info!("Using fallback deserialization");
                        serde_json::from_str::<CloudKmsSignatureResponse>(&body)
                            .map_err(CloudKmsError::FailedToDeserialize)
                            .map_err(Box::new)
                            .and_then(|resp| {
                                BASE64_STANDARD
                                    .decode(&resp.signature)
                                    .map_err(CloudKmsError::FailedToDecodeSignature)
                                    .map_err(Box::new)
                                    .and_then(|decoded| {
                                        let check = crc32c(&decoded);
                                        let check_valid = resp
                                            .signature_crc32c
                                            .parse::<u32>()
                                            .map(|resp_check| resp_check == check)
                                            .unwrap_or(false);

                                        if check_valid {
                                            Ok(decoded)
                                        } else {
                                            Err(Box::new(CloudKmsError::CorruptedSignature))
                                        }
                                    })
                            })
                    }
                    Err(err) => Err(Box::new(CloudKmsError::from(err))),
                }?;

                Ok(signature)
            }
        }
    }
}

#[async_trait]
impl Sign for Signer {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SigningKeyError> {
        Signer::sign(self, message).await
    }
}

pub enum Verifier {
    Local(LocalVerifyingKey),
    Ckms(CloudKmsVerifyingKey),
}

impl Verifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> VerificationResult {
        match self {
            Verifier::Local(local) => {
                let signature = Signature::try_from(signature);
                tracing::trace!("Verifying message");
                match signature {
                    Ok(signature) => {
                        let verification_result = local.verifying_key.verify(message, &signature);
                        match verification_result {
                            Ok(()) => VerificationResult {
                                verified: true,
                                errors: vec![None],
                            },
                            Err(err) => VerificationResult {
                                verified: false,
                                errors: vec![Some(SigningKeyError::from(err))],
                            },
                        }
                    }
                    Err(err) => VerificationResult {
                        verified: false,
                        errors: vec![Some(SigningKeyError::from(err))],
                    },
                }
            }
            Verifier::Ckms(ckms) => {
                let signature = Signature::try_from(signature);
                tracing::trace!("Verifying message");
                match signature {
                    Ok(signature) => {
                        let verification_result = ckms.verifying_key.verify(message, &signature);
                        match verification_result {
                            Ok(()) => VerificationResult {
                                verified: true,
                                errors: vec![None],
                            },
                            Err(err) => VerificationResult {
                                verified: false,
                                errors: vec![Some(SigningKeyError::from(err))],
                            },
                        }
                    }
                    Err(err) => VerificationResult {
                        verified: false,
                        errors: vec![Some(SigningKeyError::from(err))],
                    },
                }
            }
        }
    }
}

impl Verify for Verifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> VerificationResult {
        Verifier::verify(&self, message, signature)
    }
}

// impl AsymmetricKey {
//     fn cloud_kms_key_name(&self) -> Option<String> {
//         match self {
//             AsymmetricKey::CkmsSigner {
//                 version,
//                 key,
//                 keyring,
//                 location,
//                 project,
//                 ..
//             } => Some(format!(
//                 "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}/cryptoKeyVersions/{}",
//                 project, location, keyring, key, version
//             )),
//             AsymmetricKey::CkmsVerifier {
//                 version,
//                 key,
//                 keyring,
//                 location,
//                 project,
//                 ..
//             } => Some(format!(
//                 "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}/cryptoKeyVersions/{}",
//                 project, location, keyring, key, version
//             )),
//             _ => None,
//         }
//     }

//     pub async fn private_key(&self) -> Result<RsaPrivateKey, SigningKeyError> {
//         Ok(match self {
//             AsymmetricKey::LocalSigner { private, .. } => {
//                 RsaPrivateKey::from_pkcs8_pem(private.resolve()?.expose_secret()).unwrap()
//             }
//             _ => unimplemented!(),
//         })
//     }

//     pub fn public_key(&self) -> Result<RsaPublicKey, SigningKeyError> {
//         Ok(match self {
//             AsymmetricKey::LocalVerifier { public, .. } => {
//                 RsaPublicKey::from_public_key_pem(public)?
//             }
//             AsymmetricKey::LocalSigner { .. } => Err(SigningKeyError::KeyDoesNotSupportFunction)?,
//             AsymmetricKey::CkmsVerifier { .. } => {
//                 let public_key = block_on(async {
//                     let kms_client = cloud_kms_client().await?;

//                     Ok::<_, SigningKeyError>(
//                         kms_client
//                             .projects()
//                             .locations_key_rings_crypto_keys_crypto_key_versions_get_public_key(
//                                 &self.cloud_kms_key_name().unwrap(),
//                             )
//                             .doit()
//                             .await
//                             .map_err(CloudKmsError::from)
//                             .map_err(Box::new)?
//                             .1,
//                     )
//                 })?;

//                 let pem = public_key
//                     .pem
//                     .ok_or(CloudKmsError::MissingPem)
//                     .map_err(Box::new)?;
//                 RsaPublicKey::from_public_key_pem(&pem)?
//             }
//             AsymmetricKey::CkmsSigner { .. } => Err(SigningKeyError::KeyDoesNotSupportFunction)?,
//         })
//     }

//     pub fn as_signer(&self) -> Result<Arc<dyn Signer>, SigningKeyError> {
//         Ok(match self {
//             AsymmetricKey::LocalSigner { private, .. } => {
//                 let private_key =
//                     RsaPrivateKey::from_pkcs8_pem(private.resolve()?.expose_secret()).unwrap();
//                 let signing_key = SigningKey::new(private_key);

//                 Arc::new(LocalSigningKey { signing_key })
//             }
//             AsymmetricKey::CkmsSigner { .. } => Arc::new(CloudKmsSigningKey {
//                 client: block_on(cloud_kms_client())?,
//                 key_name: self.cloud_kms_key_name().unwrap(),
//             }),
//             _ => Err(SigningKeyError::KeyDoesNotSupportFunction)?,
//         })
//     }

//     pub fn as_verifier(&self) -> Result<Arc<dyn Verifier>, SigningKeyError> {
//         Ok(match self {
//             AsymmetricKey::LocalVerifier { public, .. } => {
//                 let verifying_key = VerifyingKey::new(RsaPublicKey::from_public_key_pem(public)?);

//                 Arc::new(LocalVerifyingKey { verifying_key })
//             }
//             AsymmetricKey::CkmsVerifier { .. } => {
//                 let verifying_key = VerifyingKey::new(self.public_key()?);
//                 Arc::new(CloudKmsVerifyingKey { verifying_key })
//             }
//             _ => Err(SigningKeyError::KeyDoesNotSupportFunction)?,
//         })
//     }
// }
