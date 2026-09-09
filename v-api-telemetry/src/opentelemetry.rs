// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg(feature = "experimental")]

use opentelemetry::trace::{TraceError, TracerProvider};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    logs::{LogError, Logger, LoggerProvider},
    runtime,
    trace::{Tracer, TracerProvider as SdkTracerProvider},
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
    #[error("trace error")]
    Trace(#[from] TraceError),
    #[error("log error")]
    Log(#[from] LogError),
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
            .with_batch_exporter(span_exporter, runtime::Tokio)
            .build();
        let trace_layer =
            tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer(self.service_name));
        Ok(trace_layer)
    }

    pub fn log_layer(
        &self,
    ) -> Result<OpenTelemetryTracingBridge<LoggerProvider, Logger>, VApiOpenTelemetryError> {
        let log_exporter = opentelemetry_otlp::LogExporter::builder()
            .with_http()
            .with_endpoint(format!("{}/v1/logs", self.endpoint.trim_end_matches('/')))
            .build()?;
        let logger_provider = LoggerProvider::builder()
            .with_batch_exporter(log_exporter, runtime::Tokio)
            .build();
        let log_layer = OpenTelemetryTracingBridge::new(&logger_provider);
        Ok(log_layer)
    }
}
