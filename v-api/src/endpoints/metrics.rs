// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dropshot::{Body, HttpError, RequestContext};
use http::{Response, StatusCode, header};
use tracing::instrument;

/// The content type Prometheus uses for the text exposition format.
const EXPOSITION_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

#[instrument(skip(_rqctx), err(Debug))]
pub async fn metrics_op<T>(_rqctx: &RequestContext<T>) -> Result<Response<Body>, HttpError>
where
    T: Send + Sync + 'static,
{
    let exposition = v_api_telemetry::prometheus::render().ok_or_else(|| {
        // The service registered this endpoint without installing the recorder so there is nothing
        // to report.
        HttpError::for_internal_error(
            "no prometheus recorder has been installed for this service".to_string(),
        )
    })?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, EXPOSITION_CONTENT_TYPE)
        .body(exposition.into())
        .map_err(|e| HttpError::for_internal_error(e.to_string()))
}
