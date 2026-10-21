// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use diesel::{
    AsExpression, FromSqlRow,
    backend::Backend,
    deserialize::{self, FromSql},
    pg::Pg,
    serialize::{self, Output, ToSql},
    sql_types::Jsonb,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A public key in JWK form.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, AsExpression, FromSqlRow,
)]
#[diesel(sql_type = Jsonb)]
#[serde(tag = "kty")]
#[non_exhaustive]
pub enum PublicJwk {
    /// An Octet Key Pair key as defined by RFC 8037
    #[serde(rename = "OKP")]
    Okp(OkpPublicKey),
}

impl PublicJwk {
    /// An Ed25519 public key
    pub fn ed25519(public_key: [u8; 32]) -> Self {
        Self::Okp(OkpPublicKey::Ed25519 { x: public_key })
    }
}

/// The public half of an Octet Key Pair key, selected by its `crv` member
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "crv", deny_unknown_fields)]
#[non_exhaustive]
pub enum OkpPublicKey {
    #[non_exhaustive]
    Ed25519 {
        /// The 32 byte public key
        #[serde(with = "base64url_bytes")]
        #[schemars(with = "String")]
        x: [u8; 32],
    },
}

/// RFC 7515: Encodes fixed size key material as unpadded base64url.
mod base64url_bytes {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(D::Error::custom)?;

        <[u8; N]>::try_from(decoded.as_slice()).map_err(|_| {
            D::Error::invalid_length(
                decoded.len(),
                &format!("{N} bytes of key material").as_str(),
            )
        })
    }
}

impl ToSql<Jsonb, Pg> for PublicJwk {
    fn to_sql(&self, out: &mut Output<Pg>) -> serialize::Result {
        let value = serde_json::to_value(self)?;
        <serde_json::Value as ToSql<Jsonb, Pg>>::to_sql(&value, &mut out.reborrow())
    }
}

impl FromSql<Jsonb, Pg> for PublicJwk {
    fn from_sql(bytes: <Pg as Backend>::RawValue<'_>) -> deserialize::Result<Self> {
        let value = <serde_json::Value as FromSql<Jsonb, Pg>>::from_sql(bytes)?;
        Ok(serde_json::from_value(value)?)
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::{Value, json};

    use super::{OkpPublicKey, PublicJwk};

    const KEY: [u8; 32] = [7; 32];

    fn parse(value: Value) -> Result<PublicJwk, serde_json::Error> {
        serde_json::from_value(value)
    }

    #[test]
    fn serializes_as_an_rfc_8037_jwk() {
        let jwk = serde_json::to_value(PublicJwk::ed25519(KEY)).unwrap();

        assert_eq!(
            json!({ "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(KEY) }),
            jwk
        );
        assert_eq!(PublicJwk::ed25519(KEY), parse(jwk).unwrap());
    }

    /// Members may arrive in any order, as JSON objects are unordered
    #[test]
    fn selects_the_key_by_type_and_curve() {
        let jwk =
            parse(json!({ "x": URL_SAFE_NO_PAD.encode(KEY), "crv": "Ed25519", "kty": "OKP" }))
                .unwrap();

        match jwk {
            PublicJwk::Okp(OkpPublicKey::Ed25519 { x }) => assert_eq!(KEY, x),
        }
    }

    /// Unknown members are refused, which is what keeps a private key out of storage
    #[test]
    fn refuses_unknown_members() {
        for (member, value) in [
            ("d", json!(URL_SAFE_NO_PAD.encode(KEY))),
            ("x5c", json!(["certificate"])),
            ("use", json!("sig")),
        ] {
            let mut jwk =
                json!({ "kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(KEY) });
            jwk[member] = value;
            assert!(parse(jwk).is_err(), "accepted a key with {member}");
        }
    }

    #[test]
    fn refuses_unsupported_key_types_and_curves() {
        for (kty, crv) in [
            ("EC", "P-256"),
            ("RSA", "Ed25519"),
            ("OKP", "Ed448"),
            ("OKP", "X25519"),
        ] {
            let jwk = json!({ "kty": kty, "crv": crv, "x": URL_SAFE_NO_PAD.encode(KEY) });
            assert!(parse(jwk).is_err(), "accepted kty {kty} with crv {crv}");
        }

        assert!(parse(json!({ "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(KEY) })).is_err());
        assert!(parse(json!({ "kty": "OKP", "x": URL_SAFE_NO_PAD.encode(KEY) })).is_err());
    }

    #[test]
    fn refuses_ed25519_keys_that_are_not_32_bytes() {
        for length in [31, 33, 57] {
            let x = URL_SAFE_NO_PAD.encode(vec![7; length]);
            let jwk = json!({ "kty": "OKP", "crv": "Ed25519", "x": x });
            assert!(parse(jwk).is_err(), "accepted a {length} byte key");
        }
    }

    /// JWK members are unpadded base64url, so padded or standard base64 is refused
    #[test]
    fn refuses_other_base64_encodings() {
        let padded = format!("{}=", URL_SAFE_NO_PAD.encode(KEY));
        let standard = base64::engine::general_purpose::STANDARD.encode([0xfb; 32]);

        for x in [padded, standard] {
            let jwk = json!({ "kty": "OKP", "crv": "Ed25519", "x": x });
            assert!(parse(jwk).is_err(), "accepted {x}");
        }
    }
}
