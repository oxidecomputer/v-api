// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use metrics_exporter_prometheus::{BuildError, PrometheusBuilder, PrometheusHandle};
use std::{net::SocketAddr, sync::OnceLock, thread, time::Duration};
use thiserror::Error;

/// Matches the interval the crate's own exporter uses when it serves the endpoint itself.
const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Set by [`VApiPrometheus::install_handler`], read by [`render`].
///
/// This is a process global recorder.
static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

#[derive(Debug, Error)]
pub enum VApiPrometheusError {
    #[error("failed to install prometheus exporter")]
    Install(#[from] BuildError),
    #[error("a prometheus exporter has already been installed")]
    AlreadyInstalled,
}

pub struct VApiPrometheus {
    labels: Vec<(String, String)>,
}

impl VApiPrometheus {
    pub fn new(service_name: &str) -> Self {
        Self {
            // To coincide with the OTLP resource attributes we attach the service name here.
            labels: vec![("service".to_string(), service_name.to_string())],
        }
    }

    /// Report a version on every metric.
    pub fn with_version(self, version: impl Into<String>) -> Self {
        self.with_label("version", version)
    }

    /// Report an additional label on every metric.
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.push((key.into(), value.into()));
        self
    }

    /// Install the global recorder and make the exposition available to [`render`].
    pub fn install_handler(self) -> Result<(), VApiPrometheusError> {
        let handle = self.builder().install_recorder()?;

        // Add a thread for running the update loop. Each iteration through the loop drains data
        // from the recorder.
        let upkeep = handle.clone();
        thread::Builder::new()
            .name("prometheus-upkeep".to_string())
            .spawn(move || {
                loop {
                    thread::sleep(UPKEEP_INTERVAL);
                    upkeep.run_upkeep();
                }
            })
            .map_err(|e| BuildError::FailedToCreateRuntime(e.to_string()))?;

        HANDLE
            .set(handle)
            .map_err(|_| VApiPrometheusError::AlreadyInstalled)
    }

    pub fn install_listener(self, address: SocketAddr) -> Result<(), VApiPrometheusError> {
        self.builder().with_http_listener(address).install()?;
        Ok(())
    }

    fn builder(self) -> PrometheusBuilder {
        self.labels
            .into_iter()
            .fold(PrometheusBuilder::new(), |builder, (key, value)| {
                builder.add_global_label(key, value)
            })
    }
}

/// The current exposition, or `None` if [`VApiPrometheus::install_handler`] has not run.
pub fn render() -> Option<String> {
    HANDLE.get().map(|handle| handle.render())
}
