// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![cfg(feature = "otel")]

use opentelemetry::{Key, KeyValue, Value, trace::TracerProvider};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{ExporterBuildError, WithExportConfig};
use opentelemetry_sdk::{
    Resource,
    logs::{SdkLogger, SdkLoggerProvider},
    trace::{SdkTracerProvider, Tracer},
};
use thiserror::Error;
use tracing::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::registry::LookupSpan;

/// The semantic convention key for a service's version.
const SERVICE_VERSION: &str = "service.version";

pub struct VApiOpenTelemetryLayers {
    service_name: String,
    endpoint: String,
    version: Option<Value>,
    attributes: Vec<KeyValue>,
}

#[derive(Debug, Error)]
pub enum VApiOpenTelemetryError {
    #[error("failed to build otlp exporter")]
    ExporterBuild(#[from] ExporterBuildError),
}

impl VApiOpenTelemetryLayers {
    pub fn new(service_name: &str, endpoint: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
            endpoint: endpoint.to_string(),
            version: None,
            attributes: Vec::new(),
        }
    }

    /// Report a service version.
    pub fn with_version(mut self, version: impl Into<Value>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Report an additional resource attribute.
    pub fn with_attribute(mut self, key: impl Into<Key>, value: impl Into<Value>) -> Self {
        self.attributes.push(KeyValue::new(key, value));
        self
    }

    /// Report additional resource attributes.
    pub fn with_attributes<K, V>(mut self, attributes: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<Key>,
        V: Into<Value>,
    {
        self.attributes.extend(
            attributes
                .into_iter()
                .map(|(key, value)| KeyValue::new(key, value)),
        );
        self
    }

    fn resource(&self) -> Resource {
        let mut builder = Resource::builder().with_service_name(self.service_name.clone());

        if let Some(version) = &self.version {
            builder = builder.with_attribute(KeyValue::new(SERVICE_VERSION, version.clone()));
        }

        builder
            .with_attributes(self.attributes.iter().cloned())
            .build()
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
            .with_resource(self.resource())
            .with_batch_exporter(span_exporter)
            .build();
        let trace_layer =
            tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer(self.service_name.clone()));
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
            .with_resource(self.resource())
            .with_batch_exporter(log_exporter)
            .build();
        let log_layer = OpenTelemetryTracingBridge::new(&logger_provider);
        Ok(log_layer)
    }
}
