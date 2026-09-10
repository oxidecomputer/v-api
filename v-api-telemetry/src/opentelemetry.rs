// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use opentelemetry::trace::TracerProvider;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{ExporterBuildError, WithExportConfig};
use opentelemetry_sdk::{
    logs::{SdkLogger, SdkLoggerProvider},
    trace::{SdkTracerProvider, Tracer},
};
use thiserror::Error;
use tracing::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::registry::LookupSpan;

pub struct VApiOpenTelemetryLayers {
    service_name: &'static str,
    endpoint: String,
}

#[derive(Debug, Error)]
pub enum VApiOpenTelemetryError {
    #[error("failed to build otlp exporter")]
    ExporterBuild(#[from] ExporterBuildError),
}

impl VApiOpenTelemetryLayers {
    pub fn new(service_name: &'static str, endpoint: &str) -> Self {
        Self {
            service_name,
            endpoint: endpoint.to_string(),
        }
    }

    pub fn trace_layer<T>(&self) -> Result<OpenTelemetryLayer<T, Tracer>, VApiOpenTelemetryError>
    where
        T: Subscriber + for<'span> LookupSpan<'span>,
    {
        let span_exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_endpoint(format!("{}/v1/traces", self.endpoint.trim_end_matches('/')))
            .build()?;
        let tracer_provider = SdkTracerProvider::builder()
            .with_batch_exporter(span_exporter)
            .build();
        let trace_layer =
            tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer(self.service_name));
        Ok(trace_layer)
    }

    pub fn log_layer(
        &self,
    ) -> Result<OpenTelemetryTracingBridge<SdkLoggerProvider, SdkLogger>, VApiOpenTelemetryError>
    {
        let log_exporter = opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_endpoint(format!("{}/v1/logs", self.endpoint.trim_end_matches('/')))
            .build()?;
        let logger_provider = SdkLoggerProvider::builder()
            .with_batch_exporter(log_exporter)
            .build();
        let log_layer = OpenTelemetryTracingBridge::new(&logger_provider);
        Ok(log_layer)
    }
}
