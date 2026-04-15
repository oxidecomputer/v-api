// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use dropshot::{RequestContext, SharedExtractor};
use dropshot_authorization_header::bearer::BearerAuth;
use jsonwebtoken::{
    decode, decode_header,
    jwk::{AlgorithmParameters, Jwk},
    Algorithm, DecodingKey, Header, Validation,
};
use newtype_uuid::TypedUuid;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{fmt::Debug, sync::Arc};
use thiserror::Error;
use tracing::instrument;
use v_model::{AccessTokenId, UserId, UserProviderId};

use crate::{authn::Signer, context::VContext, permissions::VAppPermission, ApiContext};

use super::SigningKeyError;

pub static DEFAULT_JWT_EXPIRATION: i64 = 3600;

#[derive(Debug, Error)]
pub enum JwtError {
    #[error("Failed to decode token: {0}")]
    Decode(jsonwebtoken::errors::Error),
    #[error("Header is not well formed")]
    MalformedHeader(jsonwebtoken::errors::Error),
    #[error("Failed to construct decoding key: {0}")]
    InvalidJwk(jsonwebtoken::errors::Error),
    #[error("Header does not have a defined kid")]
    MissingKid,
    #[error("Failed to find a matching key as requested by token")]
    NoMatchingKey,
    #[error("No token found")]
    NoToken,
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Jwt<T> {
    pub claims: T,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: TypedUuid<UserId>,
    pub prv: TypedUuid<UserProviderId>,
    pub scp: Option<Vec<String>>,
    pub exp: i64,
    pub nbf: i64,
    pub jti: TypedUuid<AccessTokenId>,
}

impl Claims {
    pub fn new<T>(
        ctx: &VContext<T>,
        id: Option<TypedUuid<AccessTokenId>>,
        user: &TypedUuid<UserId>,
        provider: &TypedUuid<UserProviderId>,
        scope: Option<Vec<String>>,
        expires_at: DateTime<Utc>,
    ) -> Self
    where
        T: VAppPermission,
    {
        Claims {
            iss: ctx.public_url().to_string(),
            aud: ctx.public_url().to_string(),
            sub: *user,
            prv: *provider,
            scp: scope,
            exp: expires_at.timestamp(),
            nbf: Utc::now().timestamp(),
            jti: id.unwrap_or_else(TypedUuid::new_v4),
        }
    }
}

impl<C> Jwt<C>
where
    C: Debug + DeserializeOwned + Serialize,
{
    pub async fn new<T>(ctx: &VContext<T>, token: &str) -> Result<Self, JwtError>
    where
        T: VAppPermission,
    {
        tracing::trace!("Decode JWT from headers");

        let header = decode_header(token).map_err(|err| {
            tracing::warn!(?err, "Token header is malformed");
            JwtError::MalformedHeader(err)
        })?;

        tracing::trace!("Found header containing JWT");

        // We require that the header contains a kid attribute for determining which decoding key
        // to use, even in the case that we are using a single key
        let kid = header.kid.ok_or(JwtError::MissingKid)?;

        tracing::trace!(?kid, "JWT with kid present");

        // The only JWKs supported are those that are available in the server context
        let jwk = ctx.jwks().await.find(&kid).ok_or(JwtError::NoMatchingKey)?;
        let (key, algorithm) = DecodingKey::from_jwk(jwk)
            .map(|key| (key, Jwt::<C>::algo(jwk)))
            .map_err(JwtError::InvalidJwk)?;

        tracing::trace!(?jwk, ?algorithm, "Kid matched known decoding key");

        let mut validation = Validation::new(algorithm?);
        validation.set_audience(&[ctx.public_url()]);
        validation.set_issuer(&[ctx.public_url()]);

        let data = decode(token, &key, &validation).map_err(JwtError::Decode)?;

        tracing::trace!("Decoded JWT claims from request");

        Ok(Jwt {
            claims: data.claims,
        })
    }

    // Check the algorithm defined in the JWK. Ensure that it is an RSA variant.
    pub fn algo(key: &Jwk) -> Result<Algorithm, JwtError> {
        match &key.algorithm {
            AlgorithmParameters::RSA(_) => Ok(Algorithm::RS256),
            algo => {
                tracing::warn!(?algo, "Encountered unsupported algorithm");
                Err(JwtError::UnsupportedAlgorithm)
            }
        }
    }

    // Extract an JWT from a Dropshot request
    pub async fn extract<T>(
        rqctx: &RequestContext<impl ApiContext<AppPermissions = T>>,
    ) -> Result<Self, JwtError>
    where
        T: VAppPermission,
    {
        // Ensure there is a bearer, without it there is nothing else to do
        let bearer = BearerAuth::from_request(rqctx).await.map_err(|err| {
            tracing::info!(?err, "Failed to extract bearer auth");
            JwtError::NoToken
        })?;

        // Check that the extracted token actually contains a value
        let token = bearer.consume().ok_or_else(|| {
            tracing::debug!("Bearer auth is empty");
            JwtError::NoToken
        })?;

        Self::new(rqctx.v_ctx(), &token).await
    }
}

#[derive(Debug, Error)]
pub enum JwtSignerError {
    #[error("Failed to encode header")]
    Header(serde_json::Error),
    #[error("Failed to generate signer: {0}")]
    InvalidKey(SigningKeyError),
    #[error("Failed to serialize claims: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("Failed to generate signature: {0}")]
    Signature(SigningKeyError),
}

pub struct JwtSigner {
    #[allow(dead_code)]
    header: Header,
    encoded_header: String,
    signer: Arc<Signer>,
}

impl JwtSigner {
    pub fn new(signer: Arc<Signer>) -> Result<Self, JwtSignerError> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(signer.kid.clone());
        let encoded_header = to_base64_json(&header)?;

        Ok(Self {
            header,
            encoded_header,
            signer,
        })
    }

    #[instrument(skip(self, claims))]
    pub async fn sign<C>(&self, claims: &C) -> Result<String, JwtSignerError>
    where
        C: Serialize + Debug,
    {
        tracing::debug!(?claims, "Signing claims");

        let encoded_claims = to_base64_json(claims)?;

        tracing::debug!("Serialized claims to sign");

        let message = format!("{}.{}", self.encoded_header, encoded_claims);

        tracing::debug!("Generating signature");

        let signature = self
            .signer
            .sign(message.as_bytes())
            .await
            .map_err(JwtSignerError::Signature)?;

        let enc_signature = URL_SAFE_NO_PAD.encode(signature);
        Ok(format!("{}.{}", message, enc_signature))
    }
}

fn to_base64_json<T>(value: &T) -> Result<String, serde_json::error::Error>
where
    T: Serialize,
{
    let json = serde_json::to_vec(value)?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}
