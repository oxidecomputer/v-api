// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, de::Error as _};
use sha2::{Digest, Sha256};
use thiserror::Error;
use v_model::jwk::{OkpPublicKey, PublicJwk};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClientKeyError {
    #[error("Only Ed25519 keys are accepted")]
    UnsupportedKey,
}

/// A public key in JWK form.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct SubmittedJwk {
    kty: KeyType,
    crv: Curve,
    /// The 32 byte Ed25519 public key in unpadded base64url
    #[serde(with = "v_model::jwk::base64url_bytes")]
    #[schemars(with = "String")]
    x: [u8; 32],
    #[serde(rename = "use")]
    key_use: KeyUse,
    /// Optional, as RFC 7517 §4.3 advises against using it alongside `use`. When it is present it
    /// must agree with `use`, which for a public signing key means exactly `["verify"]`.
    key_ops: Option<[KeyOperation; 1]>,
    alg: KeyAlgorithm,

    // These are fields that are strictly rejected. Per RFC 7517 §4 we understand their contents,
    // but we are not willing to accept them. A caller sending them implies that they are
    // misunderstanding the intent of this key pair.
    #[serde(rename = "d")]
    #[schemars(skip)]
    _private_key: Option<PrivateKeyMember>,
    #[serde(rename = "x5c")]
    #[schemars(skip)]
    _x5c: Option<CertificateMember>,
    #[serde(rename = "x5u")]
    #[schemars(skip)]
    _x5u: Option<CertificateMember>,
    #[serde(rename = "x5t")]
    #[schemars(skip)]
    _x5t: Option<CertificateMember>,
    #[serde(rename = "x5t#S256")]
    #[schemars(skip)]
    _x5t_s256: Option<CertificateMember>,
}

/// The Octet Key Pair key type from RFC 8037 §2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
pub enum KeyType {
    #[serde(rename = "OKP")]
    Okp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
pub enum Curve {
    Ed25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
pub enum KeyUse {
    #[serde(rename = "sig")]
    Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
pub enum KeyOperation {
    #[serde(rename = "verify")]
    Verify,
}

/// The algorithm a key is used with. RFC 9864 §2.2 registers `Ed25519` as the fully specified
/// identifier. We support EdDSA for compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
pub enum KeyAlgorithm {
    EdDSA,
    Ed25519,
}

/// Stands in for the `d` member (private key material). It is not allowed.
#[derive(Debug, Clone)]
struct PrivateKeyMember;

impl<'de> Deserialize<'de> for PrivateKeyMember {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Err(D::Error::custom(
            "private key material must never be submitted",
        ))
    }
}

/// Stands in for the certificate members. None of them are allowed.
#[derive(Debug, Clone)]
struct CertificateMember;

impl<'de> Deserialize<'de> for CertificateMember {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Err(D::Error::custom("certificate members are not supported"))
    }
}

impl SubmittedJwk {
    pub fn into_public_jwk(self) -> PublicJwk {
        // These fields have been verified during deserialization, ensuring that the key is of a
        // supported form and can be transformed into a PublicJwk
        let SubmittedJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x,
            key_use: KeyUse::Signature,
            key_ops: None | Some([KeyOperation::Verify]),
            alg: KeyAlgorithm::EdDSA | KeyAlgorithm::Ed25519,
            ..
        } = self;

        PublicJwk::ed25519(x)
    }
}

/// The RFC 7638 §3 thumbprint of a public key.
pub trait JwkThumbprint {
    fn thumbprint(&self) -> Result<String, ClientKeyError>;
}

impl JwkThumbprint for PublicJwk {
    fn thumbprint(&self) -> Result<String, ClientKeyError> {
        // RFC 7638 §3 hashes the required members of a key in lexicographic order with no
        // whitespace. RFC 8037 §2 defines the required members of an OKP key as crv, kty, and x.
        match self {
            PublicJwk::Okp(OkpPublicKey::Ed25519 { x, .. }) => {
                let canonical = format!(
                    r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
                    URL_SAFE_NO_PAD.encode(x)
                );
                Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
            }
            _ => Err(ClientKeyError::UnsupportedKey),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{JwkThumbprint, SubmittedJwk};

    /// The example Ed25519 public key from RFC 8037 Appendix A.2
    const RFC_8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    fn valid() -> Value {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": RFC_8037_X,
            "use": "sig",
            "key_ops": ["verify"],
            "alg": "EdDSA",
        })
    }

    fn submit(jwk: Value) -> Result<SubmittedJwk, serde_json::Error> {
        serde_json::from_value(jwk)
    }

    fn with(member: &str, value: Value) -> Value {
        let mut jwk = valid();
        jwk[member] = value;
        jwk
    }

    #[test]
    fn accepts_an_ed25519_signing_key() {
        assert!(submit(valid()).is_ok());
        assert!(submit(with("alg", json!("Ed25519"))).is_ok());
    }

    /// `key_ops` may be left out, since `use` already says the key verifies signatures
    #[test]
    fn accepts_a_key_without_key_ops() {
        let mut jwk = valid();
        jwk.as_object_mut().unwrap().remove("key_ops");

        assert_eq!(
            submit(valid()).unwrap().into_public_jwk(),
            submit(jwk).unwrap().into_public_jwk()
        );
    }

    /// Every member the policy describes must be present
    #[test]
    fn refuses_keys_missing_a_required_member() {
        for member in ["kty", "crv", "x", "use", "alg"] {
            let mut jwk = valid();
            jwk.as_object_mut().unwrap().remove(member);
            assert!(submit(jwk).is_err(), "accepted a key without {member}");
        }
    }

    #[test]
    fn refuses_values_outside_the_policy() {
        for (member, value) in [
            ("kty", json!("EC")),
            ("kty", json!("okp")),
            ("crv", json!("Ed448")),
            ("crv", json!("X25519")),
            ("use", json!("enc")),
            ("key_ops", json!(["sign"])),
            ("key_ops", json!(["verify", "sign"])),
            ("key_ops", json!([])),
            ("alg", json!("RS256")),
            ("alg", json!("ES256")),
        ] {
            assert!(
                submit(with(member, value.clone())).is_err(),
                "accepted {member} {value}"
            );
        }
    }

    /// A client supplied key id and members without rules are ignored rather than refused
    #[test]
    fn ignores_kid_and_unknown_members() {
        let mut jwk = with("kid", json!("chosen-by-client"));
        jwk["ext"] = json!(true);

        assert_eq!(
            submit(valid()).unwrap().into_public_jwk(),
            submit(jwk).unwrap().into_public_jwk()
        );
    }

    /// A submitted private key is refused, and the refusal says why
    #[test]
    fn refuses_private_key_material() {
        let err = submit(with("d", json!(RFC_8037_X))).unwrap_err();
        assert!(err.to_string().contains("private key"), "{err}");
    }

    #[test]
    fn refuses_certificate_members() {
        for member in ["x5c", "x5u", "x5t", "x5t#S256"] {
            let err = submit(with(member, json!("value"))).unwrap_err();
            assert!(err.to_string().contains("certificate"), "{member} {err}");
        }
    }

    #[test]
    fn refuses_public_keys_that_are_not_32_bytes_of_unpadded_base64url() {
        for x in [
            json!(format!("{RFC_8037_X}=")),
            json!("AAAA"),
            json!("not base64!"),
        ] {
            assert!(submit(with("x", x.clone())).is_err(), "accepted x {x}");
        }
    }

    /// The thumbprint RFC 8037 Appendix A.3 gives for its example key
    #[test]
    fn computes_the_rfc_7638_thumbprint() {
        assert_eq!(
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
            submit(valid())
                .unwrap()
                .into_public_jwk()
                .thumbprint()
                .unwrap()
        );
    }
}
