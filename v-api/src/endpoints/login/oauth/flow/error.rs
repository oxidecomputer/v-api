// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::{ErrorStatusCode, HttpError, HttpResponseError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

use crate::{endpoints::login::LoginError, error::ApiError};

/// An error response as described by RFC 6749 §5.2
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct OAuthErrorResponse {
    pub error: OAuthErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
    #[serde(skip)]
    #[schemars(skip)]
    status: ErrorStatusCode,
}

/// The error codes of RFC 6749 §4.1.2.1 and §5.2, and those added for the device flow by RFC 8628
/// §3.5
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OAuthErrorCode {
    AccessDenied,
    ExpiredToken,
    InvalidClient,
    InvalidGrant,
    InvalidRequest,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
    UnauthorizedClient,
    UnsupportedGrantType,
    UnsupportedResponseType,
}

impl OAuthErrorCode {
    /// The status an error with this code is answered with unless another is chosen. RFC 6749
    /// §5.2 answers client errors with 400.
    fn default_status(&self) -> ErrorStatusCode {
        match self {
            Self::ServerError => ErrorStatusCode::INTERNAL_SERVER_ERROR,
            Self::TemporarilyUnavailable => ErrorStatusCode::SERVICE_UNAVAILABLE,
            _ => ErrorStatusCode::BAD_REQUEST,
        }
    }
}

impl OAuthErrorResponse {
    pub fn new(error: OAuthErrorCode, error_description: Option<&str>) -> Self {
        Self {
            error,
            error_description: error_description.map(|description| description.to_string()),
            error_uri: None,
            status: error.default_status(),
        }
    }

    /// Answers the error with a different status. RFC 6749 §5.2 allows `invalid_client` to be
    /// answered with 401.
    pub fn with_status(mut self, status: ErrorStatusCode) -> Self {
        self.status = status;
        self
    }
}

impl Display for OAuthErrorResponse {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let code = serde_json::to_value(self.error)
            .ok()
            .and_then(|code| code.as_str().map(|code| code.to_string()))
            .unwrap_or_default();

        match &self.error_description {
            Some(description) => write!(f, "{code}: {description}"),
            None => write!(f, "{code}"),
        }
    }
}

impl HttpResponseError for OAuthErrorResponse {
    fn status_code(&self) -> ErrorStatusCode {
        self.status
    }
}

impl From<HttpError> for OAuthErrorResponse {
    fn from(error: HttpError) -> Self {
        if error.status_code.is_server_error() {
            tracing::error!(?error, "OAuth flow failed with a server error");
            Self::new(OAuthErrorCode::ServerError, None).with_status(error.status_code)
        } else {
            Self::new(
                OAuthErrorCode::InvalidRequest,
                Some(error.external_message.as_str()),
            )
            .with_status(error.status_code)
        }
    }
}

impl From<ApiError> for OAuthErrorResponse {
    fn from(error: ApiError) -> Self {
        HttpError::from(error).into()
    }
}

impl From<http::Error> for OAuthErrorResponse {
    fn from(error: http::Error) -> Self {
        HttpError::from(error).into()
    }
}

impl From<LoginError> for OAuthErrorResponse {
    fn from(error: LoginError) -> Self {
        HttpError::from(error).into()
    }
}

#[cfg(test)]
mod tests {
    use dropshot::{ErrorStatusCode, HttpError, HttpResponseError};
    use serde_json::json;

    use super::{OAuthErrorCode, OAuthErrorResponse};

    /// The response body is the bare RFC 6749 §5.2 object, without the status
    #[test]
    fn serializes_as_an_rfc_6749_error_response() {
        let error =
            OAuthErrorResponse::new(OAuthErrorCode::InvalidGrant, Some("Grant has expired"));
        assert_eq!(
            json!({ "error": "invalid_grant", "error_description": "Grant has expired" }),
            serde_json::to_value(&error).unwrap()
        );

        let bare = OAuthErrorResponse::new(OAuthErrorCode::ExpiredToken, None);
        assert_eq!(
            json!({ "error": "expired_token" }),
            serde_json::to_value(&bare).unwrap()
        );
    }

    #[test]
    fn chooses_a_status_for_each_code() {
        let status = |code| OAuthErrorResponse::new(code, None).status_code();

        assert_eq!(
            ErrorStatusCode::BAD_REQUEST,
            status(OAuthErrorCode::InvalidClient)
        );
        assert_eq!(
            ErrorStatusCode::INTERNAL_SERVER_ERROR,
            status(OAuthErrorCode::ServerError)
        );
        assert_eq!(
            ErrorStatusCode::SERVICE_UNAVAILABLE,
            status(OAuthErrorCode::TemporarilyUnavailable)
        );
        assert_eq!(
            ErrorStatusCode::UNAUTHORIZED,
            OAuthErrorResponse::new(OAuthErrorCode::InvalidClient, None)
                .with_status(ErrorStatusCode::UNAUTHORIZED)
                .status_code()
        );
    }

    /// Server errors never carry their message to the client, while client errors keep the message
    /// that was meant for it
    #[test]
    fn converts_http_errors() {
        let server: OAuthErrorResponse =
            HttpError::for_internal_error("database exploded".to_string()).into();
        assert_eq!(OAuthErrorCode::ServerError, server.error);
        assert_eq!(None, server.error_description);
        assert_eq!(ErrorStatusCode::INTERNAL_SERVER_ERROR, server.status_code());

        let client: OAuthErrorResponse =
            HttpError::for_bad_request(None, "Missing client credentials".to_string()).into();
        assert_eq!(OAuthErrorCode::InvalidRequest, client.error);
        assert_eq!(
            Some("Missing client credentials".to_string()),
            client.error_description
        );
        assert_eq!(ErrorStatusCode::BAD_REQUEST, client.status_code());
    }

    #[test]
    fn displays_the_code_and_description() {
        assert_eq!(
            "invalid_scope: Invalid scope: nope",
            OAuthErrorResponse::new(OAuthErrorCode::InvalidScope, Some("Invalid scope: nope"))
                .to_string()
        );
    }
}
