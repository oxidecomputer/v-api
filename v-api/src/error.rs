// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::HttpError;
use thiserror::Error;
use v_model::storage::StoreError;

use crate::{
    authn::{jwt::JwtSignerError, SigningKeyError},
    endpoints::login::{oauth::OAuthProviderError, LoginError},
    response::conflict,
    util::response::{forbidden, internal_error, not_found},
};

#[derive(Debug, Error)]
pub enum AppError {
    #[error("At least one JWT signing key must be configured")]
    NoConfiguredJwtKeys,
    #[error("Configured jwt key is invalid")]
    JwtSigner(#[from] JwtSignerError),
    #[error(transparent)]
    Signer(#[from] SigningKeyError),
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Resource operation conflicts with existing system state")]
    Conflict,
    #[error("Caller does not have the required permissions")]
    Forbidden,
    #[error("JWT credential failed: {0}")]
    Jwt(#[from] JwtSignerError),
    #[error("Invalid signing key: {0}")]
    Key(#[from] SigningKeyError),
    #[error(transparent)]
    Login(#[from] LoginError),
    #[error("Resource could not be found")]
    NotFound,
    #[error("Internal OAuth provider failed {0}")]
    OAuth(#[from] OAuthProviderError),
    #[error("Internal storage failed {0}")]
    Storage(#[from] StoreError),
}

impl From<ApiError> for HttpError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::Conflict => conflict(),
            ApiError::Forbidden => forbidden(),
            ApiError::Jwt(_) => internal_error("JWT operation failed"),
            ApiError::Key(_) => internal_error("User credential signing failed"),
            ApiError::Login(inner) => inner.into(),
            ApiError::NotFound => not_found(""),
            ApiError::OAuth(_) => internal_error("OAuth provider failed"),
            ApiError::Storage(_) => internal_error("Internal storage failed"),
        }
    }
}
