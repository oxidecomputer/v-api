// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use hex::FromHexError;
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretSlice, SecretString};
use thiserror::Error;
use uuid::Uuid;

use crate::authn::Verifier;

use super::{Signer, SigningKeyError};

pub struct RawKey {
    clear: SecretSlice<u8>,
}

#[derive(Debug, Error)]
pub enum ApiKeyError {
    #[error("Failed to decode component: {0}")]
    Decode(#[from] FromHexError),
    #[error("Failed to parse API key")]
    FailedToParse,
    #[error("Signature is malformed: {0}")]
    MalformedSignature(#[from] rsa::signature::Error),
    #[error("Failed to sign API key: {0}")]
    Signing(SigningKeyError),
    #[error("Failed to verify API key")]
    Verify,
}

impl RawKey {
    // Generate a new API key
    pub fn generate<const N: usize>(id: &Uuid) -> Self {
        // Generate random data to extend the token id with
        let mut token_raw = [0; N];
        OsRng.fill_bytes(&mut token_raw);

        let mut clear = id.as_bytes().to_vec();
        clear.append(&mut token_raw.to_vec());

        Self {
            clear: clear.into(),
        }
    }

    pub fn id(&self) -> &[u8] {
        &self.clear.expose_secret()[0..16]
    }

    pub async fn sign(self, signer: &dyn Signer) -> Result<SignedKey, ApiKeyError> {
        let signature = hex::encode(
            signer
                .sign(&self.clear.expose_secret())
                .await
                .map_err(ApiKeyError::Signing)?,
        );
        Ok(SignedKey::new(
            hex::encode(self.clear.expose_secret()).into(),
            signature,
        ))
    }

    pub fn verify<T>(&self, verifier: &T, signature: &[u8]) -> Result<(), ApiKeyError>
    where
        T: Verifier,
    {
        let signature = hex::decode(signature)?;
        if verifier
            .verify(&self.clear.expose_secret(), &signature)
            .verified
        {
            return Ok(());
        }

        Err(ApiKeyError::Verify)
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.clear.expose_secret()
    }
}

impl TryFrom<&str> for RawKey {
    type Error = ApiKeyError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let decoded = hex::decode(value)?;

        if decoded.len() > 16 {
            Ok(RawKey {
                clear: decoded.into(),
            })
        } else {
            tracing::debug!(len = ?decoded.len(), "API key is too short");
            Err(ApiKeyError::FailedToParse)
        }
    }
}

impl TryFrom<&SecretString> for RawKey {
    type Error = ApiKeyError;

    fn try_from(value: &SecretString) -> Result<Self, Self::Error> {
        let decoded = hex::decode(value.expose_secret())?;

        if decoded.len() > 16 {
            Ok(RawKey {
                clear: decoded.into(),
            })
        } else {
            tracing::debug!(len = ?decoded.len(), "API key is too short");
            Err(ApiKeyError::FailedToParse)
        }
    }
}

pub struct SignedKey {
    key: SecretString,
    signature: String,
}

impl SignedKey {
    fn new(key: SecretString, signature: String) -> Self {
        Self { key, signature }
    }

    pub fn key(self) -> SecretString {
        self.key
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;
    use std::sync::Arc;
    use uuid::Uuid;

    use super::RawKey;
    use crate::{
        authn::{VerificationResult, Verifier},
        util::tests::{mock_key, MockKey},
    };

    struct TestVerifier {
        verifier: Arc<dyn Verifier>,
    }

    impl Verifier for TestVerifier {
        fn verify(&self, message: &[u8], signature: &[u8]) -> VerificationResult {
            self.verifier.verify(message, signature)
        }
    }

    #[tokio::test]
    async fn test_verifies_signature() {
        let id = Uuid::new_v4();
        let MockKey { signer, verifier } = mock_key("test");
        let signer = signer.as_signer().unwrap();
        let verifier = TestVerifier {
            verifier: verifier.as_verifier().unwrap(),
        };

        let raw = RawKey::generate::<8>(&id);
        let signed = raw.sign(&*signer).await.unwrap();

        let raw2 = RawKey::try_from(signed.key.expose_secret()).unwrap();

        assert_eq!(
            (),
            raw2.verify(&verifier, signed.signature.as_bytes()).unwrap()
        )
    }

    #[tokio::test]
    async fn test_generates_signatures() {
        let id = Uuid::new_v4();
        let MockKey { signer, .. } = mock_key("test");
        let signer = signer.as_signer().unwrap();

        let raw1 = RawKey::generate::<8>(&id);
        let signed1 = raw1.sign(&*signer).await.unwrap();

        let raw2 = RawKey::generate::<8>(&id);
        let signed2 = raw2.sign(&*signer).await.unwrap();

        assert_ne!(signed1.signature(), signed2.signature())
    }
}
