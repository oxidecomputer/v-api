// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Assertions are parsed and checked here rather than through `jsonwebtoken::decode`. The crate
//! types the header `alg` as its own enum, which does not know the RFC 9864 §2.2 `Ed25519` identifier,
//! so an assertion using it would be refused before its signature was ever checked. Once support
//! hsa been added we will consider using the crates implementation. For now only the signature
//! check itself is delegated to the crate.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, crypto::verify};
use newtype_uuid::TypedUuid;
use serde::{Deserialize, Deserializer, de::DeserializeOwned, de::Error as _};
use thiserror::Error;
use v_model::{
    OAuthClientId,
    jwk::{OkpPublicKey, PublicJwk},
};

/// The `client_assertion_type` that identifies a JWT assertion (RFC 7523 §2.2)
pub const JWT_BEARER_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// How far the clocks of a client and v-api may disagree, in seconds
pub const CLOCK_SKEW: i64 = 30;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AssertionError {
    #[error("Assertion is not a compact JWS")]
    Malformed,
    #[error("Assertion header is not acceptable: {0}")]
    Header(String),
    #[error("Assertion claims are not acceptable: {0}")]
    Claims(String),
    #[error("Assertion was signed with a key that is not supported")]
    UnsupportedKey,
    #[error("Assertion signature is invalid")]
    Signature,
    #[error("Assertion subject does not match its issuer")]
    SubjectMismatch,
    #[error("Assertion audience is not this service")]
    Audience,
    #[error("Assertion has expired")]
    Expired,
    #[error("Assertion lives longer than is allowed")]
    TooLongLived,
    #[error("Assertion is not yet valid")]
    NotYetValid,
    #[error("Assertion was issued in the future")]
    IssuedInFuture,
    #[error("Assertion has an empty jti")]
    MissingJti,
}

/// The header of an assertion. Unknown parameters are ignored as JWS requires. Parameters that
/// would change which key is trusted or how the assertion is processed are strictly rejected during
/// deserialization.
#[derive(Debug, Deserialize)]
struct AssertionHeader {
    alg: AssertionAlgorithm,
    kid: String,

    // typ is not required, but if it is specified it must comply to the limited types we support.
    #[serde(default, rename = "typ")]
    _typ: Option<AssertionType>,

    // A key embedded in or referenced by the header is the classic way to make a verifier trust
    // a key chosen by an attacker. Assertions are only ever verified against stored keys, so these
    // parameters are refused outright.
    #[serde(default, rename = "jwk")]
    _jwk: Option<RefusedParameter>,
    #[serde(default, rename = "jku")]
    _jku: Option<RefusedParameter>,
    #[serde(default, rename = "x5c")]
    _x5c: Option<RefusedParameter>,
    #[serde(default, rename = "x5u")]
    _x5u: Option<RefusedParameter>,

    // No JWS extensions are supported.
    #[serde(default, rename = "crit")]
    _crit: Option<RefusedParameter>,
}

/// RFC 9864 §2.2 registers `Ed25519` as the fully specified identifier and §4.1.2 deprecates the
/// polymorphic `EdDSA`. Both are accepted currently for compatibility. We only support Ed25519 and
/// therefore for our use case they are equivalent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum AssertionAlgorithm {
    EdDSA,
    Ed25519,
}

/// RFC 7523 §3 does not require `typ`, so it may be absent. When present it must say the
/// assertion is a JWT, or use the explicit type proposed in draft-ietf-oauth-rfc7523bis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
enum AssertionType {
    #[serde(rename = "JWT")]
    Jwt,
    #[serde(rename = "client-authentication+jwt")]
    ClientAuthentication,
}

/// Stands in for a header parameter that must never be present
#[derive(Debug)]
struct RefusedParameter;

impl<'de> Deserialize<'de> for RefusedParameter {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Err(D::Error::custom(
            "header parameters that supply keys or extensions are not accepted",
        ))
    }
}

/// The claims of an assertion. The audience must be a single string. RFC 7519 §4.1.3 also allows
/// an array, but we do not support multiple audiences for a single claim and therefore specialize
/// to the string case.
#[derive(Debug, Clone, Deserialize)]
pub struct AssertionClaims {
    pub iss: TypedUuid<OAuthClientId>,
    pub sub: TypedUuid<OAuthClientId>,
    pub aud: String,
    pub exp: i64,
    pub jti: String,
    pub nbf: Option<i64>,
    pub iat: Option<i64>,
}

/// An assertion whose structure has been checked but whose signature and claims have not. All data
/// carried here is strictly untrusted.
#[derive(Debug)]
pub struct UnverifiedAssertion {
    header: AssertionHeader,
    claims: AssertionClaims,
    signing_input: String,
    signature: String,
}

/// The rules an assertion's claims are checked against.
#[derive(Debug, Clone)]
pub struct AssertionPolicy {
    /// Must be the v-api issuer identifier
    pub audience: String,
    /// The current time as a unix timestamp
    pub now: i64,
    /// The largest allowed number of seconds between now and the assertion's expiration
    pub max_lifetime: i64,
}

fn decode_segment<T>(segment: &str) -> Result<T, AssertionError>
where
    T: DeserializeOwned,
{
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| AssertionError::Malformed)?;
    serde_json::from_slice(&bytes).map_err(|err| AssertionError::Claims(err.to_string()))
}

impl UnverifiedAssertion {
    /// Splits a compact JWS and checks its header against the header policy
    pub fn parse(assertion: &str) -> Result<Self, AssertionError> {
        let segments = assertion.split('.').collect::<Vec<_>>();

        match segments.as_slice() {
            [header, claims, signature] => {
                let header_bytes = URL_SAFE_NO_PAD
                    .decode(header)
                    .map_err(|_| AssertionError::Malformed)?;
                let header = serde_json::from_slice::<AssertionHeader>(&header_bytes)
                    .map_err(|err| AssertionError::Header(err.to_string()))?;

                Ok(Self {
                    header,
                    claims: decode_segment(claims)?,
                    signing_input: format!(
                        "{header_segment}.{claims}",
                        header_segment = segments[0]
                    ),
                    signature: signature.to_string(),
                })
            }
            _ => Err(AssertionError::Malformed),
        }
    }

    /// The key id the assertion claims to be signed with
    pub fn untrusted_kid(&self) -> &str {
        &self.header.kid
    }

    /// Verifies the signature against a key and then checks the claims against the policy. This
    /// MUST be the only way for a caller to extract the claims from the token.
    pub fn verify(
        self,
        key: &PublicJwk,
        policy: &AssertionPolicy,
    ) -> Result<AssertionClaims, AssertionError> {
        let decoding_key = match key {
            PublicJwk::Okp(OkpPublicKey::Ed25519 { x, .. }) => {
                DecodingKey::from_ed_components(&URL_SAFE_NO_PAD.encode(x))
                    .map_err(|_| AssertionError::UnsupportedKey)
            }
            _ => Err(AssertionError::UnsupportedKey),
        }?;

        // Both accepted identifiers name the same Ed25519 signature check
        let algorithm = match self.header.alg {
            AssertionAlgorithm::EdDSA | AssertionAlgorithm::Ed25519 => Algorithm::EdDSA,
        };

        let valid = verify(
            &self.signature,
            self.signing_input.as_bytes(),
            &decoding_key,
            algorithm,
        )
        .map_err(|_| AssertionError::Signature)?;

        if !valid {
            Err(AssertionError::Signature)
        } else {
            Self::check_claims(self.claims, policy)
        }
    }

    fn check_claims(
        claims: AssertionClaims,
        policy: &AssertionPolicy,
    ) -> Result<AssertionClaims, AssertionError> {
        let now = policy.now;

        if claims.sub != claims.iss {
            Err(AssertionError::SubjectMismatch)
        } else if claims.aud != policy.audience {
            Err(AssertionError::Audience)
        } else if claims.exp.saturating_add(CLOCK_SKEW) <= now {
            Err(AssertionError::Expired)
        } else if claims.exp.saturating_sub(now) > policy.max_lifetime + CLOCK_SKEW {
            Err(AssertionError::TooLongLived)
        } else if claims.nbf.is_some_and(|nbf| nbf > now + CLOCK_SKEW) {
            Err(AssertionError::NotYetValid)
        } else if claims.iat.is_some_and(|iat| iat > now + CLOCK_SKEW) {
            Err(AssertionError::IssuedInFuture)
        } else if claims.jti.is_empty() {
            Err(AssertionError::MissingJti)
        } else {
            Ok(claims)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use aws_lc_rs::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::Utc;
    use newtype_uuid::TypedUuid;
    use serde_json::{Value, json};
    use v_model::{OAuthClientId, jwk::PublicJwk};

    use super::{AssertionError, AssertionPolicy, CLOCK_SKEW, UnverifiedAssertion};

    pub const AUDIENCE: &str = "https://test_public_url";
    pub const MAX_LIFETIME: i64 = 300;

    /// A client key pair for signing test assertions with
    pub struct TestKey {
        pair: Ed25519KeyPair,
    }

    impl TestKey {
        pub fn new() -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            Self {
                pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
            }
        }

        pub fn public_jwk(&self) -> PublicJwk {
            PublicJwk::ed25519(self.pair.public_key().as_ref().try_into().unwrap())
        }

        /// Signs an arbitrary header and claims
        pub fn sign(&self, header: &Value, claims: &Value) -> String {
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header.to_string()),
                URL_SAFE_NO_PAD.encode(claims.to_string())
            );
            let signature = self.pair.sign(input.as_bytes());
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
        }

        /// Signs a valid assertion for the client
        pub fn assertion(&self, client_id: TypedUuid<OAuthClientId>, kid: &str) -> String {
            self.sign(&header(kid), &claims(client_id))
        }
    }

    pub fn header(kid: &str) -> Value {
        json!({ "alg": "EdDSA", "kid": kid, "typ": "JWT" })
    }

    pub fn claims(client_id: TypedUuid<OAuthClientId>) -> Value {
        let now = Utc::now().timestamp();
        json!({
            "iss": client_id,
            "sub": client_id,
            "aud": AUDIENCE,
            "exp": now + 120,
            "iat": now,
            "jti": TypedUuid::<OAuthClientId>::new_v4().to_string(),
        })
    }

    fn policy() -> AssertionPolicy {
        AssertionPolicy {
            audience: AUDIENCE.to_string(),
            now: Utc::now().timestamp(),
            max_lifetime: MAX_LIFETIME,
        }
    }

    fn check(key: &TestKey, assertion: &str) -> Result<(), AssertionError> {
        UnverifiedAssertion::parse(assertion)?
            .verify(&key.public_jwk(), &policy())
            .map(|_| ())
    }

    fn with(base: Value, member: &str, value: Value) -> Value {
        let mut base = base;
        base[member] = value;
        base
    }

    fn without(base: Value, member: &str) -> Value {
        let mut base = base;
        base.as_object_mut().unwrap().remove(member);
        base
    }

    #[test]
    fn accepts_both_ed25519_identifiers() {
        let key = TestKey::new();
        let client = TypedUuid::new_v4();

        for alg in ["EdDSA", "Ed25519"] {
            let assertion = key.sign(&with(header("kid"), "alg", json!(alg)), &claims(client));
            assert_eq!(Ok(()), check(&key, &assertion), "{alg}");
        }
    }

    #[test]
    fn accepts_the_allowed_types() {
        let key = TestKey::new();
        let client = TypedUuid::new_v4();

        for header in [
            without(header("kid"), "typ"),
            with(header("kid"), "typ", json!("client-authentication+jwt")),
        ] {
            assert_eq!(Ok(()), check(&key, &key.sign(&header, &claims(client))));
        }

        let other = with(header("kid"), "typ", json!("at+jwt"));
        assert!(matches!(
            check(&key, &key.sign(&other, &claims(client))),
            Err(AssertionError::Header(_))
        ));
    }

    #[test]
    fn exposes_the_kid_before_verification() {
        let key = TestKey::new();
        let client = TypedUuid::new_v4();
        let assertion = UnverifiedAssertion::parse(&key.assertion(client, "the-kid")).unwrap();

        assert_eq!("the-kid", assertion.untrusted_kid());
    }

    /// Every algorithm other than Ed25519 is refused, whatever the signature
    #[test]
    fn refuses_other_algorithms() {
        let key = TestKey::new();
        let client = TypedUuid::new_v4();

        for alg in ["none", "HS256", "RS256", "PS256", "ES256", "Ed448"] {
            let assertion = key.sign(&with(header("kid"), "alg", json!(alg)), &claims(client));
            assert!(
                matches!(check(&key, &assertion), Err(AssertionError::Header(_))),
                "{alg}"
            );
        }
    }

    #[test]
    fn refuses_a_missing_kid() {
        let key = TestKey::new();
        let assertion = key.sign(&without(header("kid"), "kid"), &claims(TypedUuid::new_v4()));
        assert!(matches!(
            check(&key, &assertion),
            Err(AssertionError::Header(_))
        ));
    }

    /// Header parameters that supply a key or demand an extension are refused
    #[test]
    fn refuses_key_and_extension_headers() {
        let key = TestKey::new();
        let client = TypedUuid::new_v4();

        for parameter in ["jwk", "jku", "x5c", "x5u", "crit"] {
            let assertion = key.sign(
                &with(header("kid"), parameter, json!("value")),
                &claims(client),
            );
            assert!(
                matches!(check(&key, &assertion), Err(AssertionError::Header(_))),
                "{parameter}"
            );
        }
    }

    #[test]
    fn refuses_a_signature_from_another_key() {
        let key = TestKey::new();
        let assertion = TestKey::new().assertion(TypedUuid::new_v4(), "kid");
        assert_eq!(Err(AssertionError::Signature), check(&key, &assertion));
    }

    #[test]
    fn refuses_tampered_claims() {
        let key = TestKey::new();
        let assertion = key.assertion(TypedUuid::new_v4(), "kid");
        let segments = assertion.split('.').collect::<Vec<_>>();
        let forged = URL_SAFE_NO_PAD.encode(claims(TypedUuid::new_v4()).to_string());
        let tampered = format!("{}.{forged}.{}", segments[0], segments[2]);

        assert_eq!(Err(AssertionError::Signature), check(&key, &tampered));
    }

    #[test]
    fn refuses_malformed_assertions() {
        let key = TestKey::new();
        for assertion in ["", "a.b", "a.b.c.d", "!!.!!.!!"] {
            assert!(check(&key, assertion).is_err(), "{assertion}");
        }
    }

    #[test]
    fn refuses_a_subject_that_is_not_the_issuer() {
        let key = TestKey::new();
        let assertion = key.sign(
            &header("kid"),
            &with(
                claims(TypedUuid::new_v4()),
                "sub",
                json!(TypedUuid::<OAuthClientId>::new_v4()),
            ),
        );
        assert_eq!(
            Err(AssertionError::SubjectMismatch),
            check(&key, &assertion)
        );
    }

    /// Only the issuer identifier is an accepted audience. The token endpoint URL and arrays are
    /// refused.
    #[test]
    fn refuses_other_audiences() {
        let key = TestKey::new();
        let client = TypedUuid::new_v4();

        let endpoint = with(
            claims(client),
            "aud",
            json!(format!("{AUDIENCE}/oauth/token")),
        );
        assert_eq!(
            Err(AssertionError::Audience),
            check(&key, &key.sign(&header("kid"), &endpoint))
        );

        let array = with(claims(client), "aud", json!([AUDIENCE]));
        assert!(matches!(
            check(&key, &key.sign(&header("kid"), &array)),
            Err(AssertionError::Claims(_))
        ));
    }

    #[test]
    fn refuses_missing_required_claims() {
        let key = TestKey::new();
        for claim in ["iss", "sub", "aud", "exp", "jti"] {
            let assertion = key.sign(&header("kid"), &without(claims(TypedUuid::new_v4()), claim));
            assert!(
                matches!(check(&key, &assertion), Err(AssertionError::Claims(_))),
                "{claim}"
            );
        }
    }

    #[test]
    fn refuses_assertions_outside_their_lifetime() {
        let key = TestKey::new();
        let client = TypedUuid::new_v4();
        let now = Utc::now().timestamp();

        for (member, value, expected) in [
            ("exp", now - CLOCK_SKEW - 1, AssertionError::Expired),
            (
                "exp",
                now + MAX_LIFETIME + CLOCK_SKEW + 60,
                AssertionError::TooLongLived,
            ),
            ("nbf", now + CLOCK_SKEW + 60, AssertionError::NotYetValid),
            ("iat", now + CLOCK_SKEW + 60, AssertionError::IssuedInFuture),
        ] {
            let assertion = key.sign(&header("kid"), &with(claims(client), member, json!(value)));
            assert_eq!(Err(expected), check(&key, &assertion), "{member}");
        }
    }

    /// Small disagreements between clocks are tolerated
    #[test]
    fn tolerates_clock_skew() {
        let key = TestKey::new();
        let client = TypedUuid::new_v4();
        let now = Utc::now().timestamp();

        for (member, value) in [
            ("exp", now - CLOCK_SKEW + 5),
            ("nbf", now + CLOCK_SKEW - 5),
            ("iat", now + CLOCK_SKEW - 5),
        ] {
            let assertion = key.sign(&header("kid"), &with(claims(client), member, json!(value)));
            assert_eq!(Ok(()), check(&key, &assertion), "{member}");
        }
    }

    /// An expiration at either end of the representable range is refused without the arithmetic
    /// around it overflowing
    #[test]
    fn refuses_extreme_expirations_without_panicking() {
        let key = TestKey::new();
        let client = TypedUuid::new_v4();

        for (exp, expected) in [
            (i64::MAX, AssertionError::TooLongLived),
            (i64::MIN, AssertionError::Expired),
        ] {
            let assertion = key.sign(&header("kid"), &with(claims(client), "exp", json!(exp)));
            assert_eq!(Err(expected), check(&key, &assertion), "{exp}");
        }
    }

    #[test]
    fn refuses_an_empty_jti() {
        let key = TestKey::new();
        let assertion = key.sign(
            &header("kid"),
            &with(claims(TypedUuid::new_v4()), "jti", json!("")),
        );
        assert_eq!(Err(AssertionError::MissingJti), check(&key, &assertion));
    }
}
