// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use async_trait::async_trait;
use dropshot::{
    ApiEndpointBodyContentType, ClientErrorStatusCode, ExtensionMode, ExtractorMetadata, HttpError,
    RequestContext, ServerContext, SharedExtractor,
};
use http::{HeaderValue, header::AUTHORIZATION};

/// A token used for bearer authentication
pub struct BearerAuth(Option<String>);

impl BearerAuth {
    pub fn new(token: String) -> Self {
        Self(Some(token))
    }

    pub fn key(&self) -> Option<&str> {
        self.0.as_deref()
    }

    pub fn consume(self) -> Option<String> {
        self.0
    }
}

fn bearer_from_header(header: Option<&HeaderValue>) -> Result<BearerAuth, HttpError> {
    let token = header
        .map(|header| {
            header
                .to_str()
                .ok()
                .and_then(|value| value.strip_prefix("Bearer "))
                .map(|token| token.to_string())
                .ok_or_else(|| {
                    tracing::info!("Authorization header is not a bearer token");
                    HttpError::for_client_error(
                        None,
                        ClientErrorStatusCode::UNAUTHORIZED,
                        "Authorization header is not a bearer token".to_string(),
                    )
                })
        })
        .transpose()?;

    Ok(BearerAuth(token))
}

/// A request without an Authorization header extracts as `BearerAuth(None)`. A request whose
/// Authorization header is not a readable bearer token is rejected as unauthorized. This extractor
/// is not responsible for checking the value of the token.
#[async_trait]
impl SharedExtractor for BearerAuth {
    async fn from_request<Context: ServerContext>(
        rqctx: &RequestContext<Context>,
    ) -> Result<BearerAuth, HttpError> {
        bearer_from_header(rqctx.request.headers().get(AUTHORIZATION))
    }

    fn metadata(_body_content_type: ApiEndpointBodyContentType) -> ExtractorMetadata {
        ExtractorMetadata {
            parameters: vec![],
            extension_mode: ExtensionMode::None,
        }
    }
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::bearer_from_header;

    #[test]
    fn missing_header_has_no_token() {
        assert_eq!(None, bearer_from_header(None).unwrap().consume());
    }

    #[test]
    fn bearer_header_yields_token() {
        let header = HeaderValue::from_static("Bearer token");

        assert_eq!(
            Some("token".to_string()),
            bearer_from_header(Some(&header)).unwrap().consume()
        );
    }

    /// A header that is present but is not a bearer token must not be mistaken for a missing one
    #[test]
    fn other_schemes_are_rejected() {
        let header = HeaderValue::from_static("Basic dXNlcjpwYXNz");

        assert_eq!(
            401,
            bearer_from_header(Some(&header))
                .err()
                .unwrap()
                .status_code
                .as_u16()
        );
    }

    #[test]
    fn unreadable_header_is_rejected() {
        let header = HeaderValue::from_bytes(b"Bearer \xff").unwrap();

        assert!(bearer_from_header(Some(&header)).is_err());
    }
}
