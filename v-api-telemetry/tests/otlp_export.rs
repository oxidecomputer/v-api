// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Proves that the layers actually export, against a listener standing in for a collector.

#![cfg(feature = "otel")]

use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc,
    time::Duration,
};

use tracing_subscriber::prelude::*;
use v_api_telemetry::opentelemetry::VApiOpenTelemetryLayers;

/// Accepts one request, reports its start line, and answers with an empty OTLP success.
fn collector() -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut buf = [0u8; 4096];
        let read = stream.read(&mut buf).unwrap_or(0);
        let request = String::from_utf8_lossy(&buf[..read]).to_string();

        // 200 with an empty protobuf body: enough for the exporter to call it a success.
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: 0\r\n\r\n",
        );
        let _ = stream.flush();
        let _ = tx.send(request);
    });

    (endpoint, rx)
}

#[test]
fn log_layer_exports_to_the_endpoint() {
    let (endpoint, requests) = collector();
    let telemetry = VApiOpenTelemetryLayers::new("test-service", &endpoint);
    let layer = telemetry.log_layer().expect("build log layer");

    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tracing::error!("event that should reach the collector");

    // Longer than the batch processor's scheduled delay, which is what triggers the export.
    let request = requests
        .recv_timeout(Duration::from_secs(30))
        .expect("no request reached the collector: the export thread is not running");

    assert!(
        request.starts_with("POST /v1/logs "),
        "unexpected request line: {}",
        request.lines().next().unwrap_or_default()
    );
}

#[test]
fn trace_layer_exports_to_the_endpoint() {
    let (endpoint, requests) = collector();
    let telemetry = VApiOpenTelemetryLayers::new("test-service", &endpoint);
    let layer = telemetry.trace_layer().expect("build trace layer");

    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tracing::info_span!("span that should reach the collector").in_scope(|| {});

    let request = requests
        .recv_timeout(Duration::from_secs(30))
        .expect("no request reached the collector: the export thread is not running");

    assert!(
        request.starts_with("POST /v1/traces "),
        "unexpected request line: {}",
        request.lines().next().unwrap_or_default()
    );
}
