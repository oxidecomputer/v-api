// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Proves that the layers actually export, against a listener standing in for a collector.

#![cfg(feature = "experimental")]

use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc,
    time::Duration,
};

use tracing_subscriber::prelude::*;
use v_api_telemetry::opentelemetry::VApiOpenTelemetryLayers;

const SERVICE_NAME: &str = "test-service";

struct Request {
    start_line: String,
    body: String,
}

/// Accepts one request, reports it, and answers with an empty OTLP success.
fn collector() -> (String, mpsc::Receiver<Request>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };

        // Read headers, then however much body Content-Length promises. A single read is not
        // enough: the assertions below are about what is in the body.
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        let body_at = loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => raw.extend_from_slice(&buf[..n]),
            }
            if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                break at + 4;
            }
        };

        let head = String::from_utf8_lossy(&raw[..body_at]).to_string();
        let length: usize = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())?
            })
            .unwrap_or(0);

        while raw.len() - body_at < length {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => raw.extend_from_slice(&buf[..n]),
            }
        }

        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let _ = stream.flush();

        let _ = tx.send(Request {
            start_line: head.lines().next().unwrap_or_default().to_string(),
            // Lossy on purpose: this holds whichever encoding is configured, and the assertions
            // only look for strings that survive either one.
            body: String::from_utf8_lossy(&raw[body_at..]).to_string(),
        });
    });

    (endpoint, rx)
}

fn receive(requests: &mpsc::Receiver<Request>) -> Request {
    // Longer than the batch processor's scheduled delay, which is what triggers the export.
    requests
        .recv_timeout(Duration::from_secs(30))
        .expect("no request reached the collector: the export thread is not running")
}

/// The service name has to reach the collector as a resource attribute. Passing it to `tracer`
/// only names the instrumentation scope, which leaves the SDK reporting the resource as
/// `unknown_service:<process name>`.
///
/// The absence of `unknown_service` is the load-bearing half. A trace payload contains the service
/// name as its scope name whether or not the resource is set, and contains the string
/// `service.name` as the key of the fallback attribute, so looking only for those passes even with
/// no resource at all.
fn assert_carries_service_name(body: &str) {
    assert!(
        !body.contains("unknown_service"),
        "exported payload fell back to the default resource: {body}"
    );
    assert!(
        body.contains("service.name") && body.contains(SERVICE_NAME),
        "exported payload does not carry the service name as a resource attribute: {body}"
    );
}

#[test]
fn optional_resource_attributes_reach_the_collector() {
    let (endpoint, requests) = collector();
    let telemetry = VApiOpenTelemetryLayers::new(SERVICE_NAME, &endpoint)
        .with_version("1.2.3")
        .with_attribute("deployment.environment.name", "staging")
        .with_attributes([("tenant", "oxide"), ("region", "us-west1")]);
    let layer = telemetry.log_layer().expect("build log layer");

    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tracing::error!("event that should reach the collector");

    let body = receive(&requests).body;
    assert_carries_service_name(&body);
    for expected in [
        "service.version",
        "1.2.3",
        "deployment.environment.name",
        "staging",
        "tenant",
        "oxide",
        "region",
        "us-west1",
    ] {
        assert!(
            body.contains(expected),
            "exported payload is missing {expected}: {body}"
        );
    }
}

#[test]
fn log_layer_exports_to_the_endpoint() {
    let (endpoint, requests) = collector();
    let telemetry = VApiOpenTelemetryLayers::new(SERVICE_NAME, &endpoint);
    let layer = telemetry.log_layer().expect("build log layer");

    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tracing::error!("event that should reach the collector");

    let request = receive(&requests);
    assert!(
        request.start_line.starts_with("POST /v1/logs "),
        "unexpected request line: {}",
        request.start_line
    );
    assert_carries_service_name(&request.body);
}

#[test]
fn trace_layer_exports_to_the_endpoint() {
    let (endpoint, requests) = collector();
    let telemetry = VApiOpenTelemetryLayers::new(SERVICE_NAME, &endpoint);
    let layer = telemetry.trace_layer().expect("build trace layer");

    let subscriber = tracing_subscriber::registry().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    tracing::info_span!("span that should reach the collector").in_scope(|| {});

    let request = receive(&requests);
    assert!(
        request.start_line.starts_with("POST /v1/traces "),
        "unexpected request line: {}",
        request.start_line
    );
    assert_carries_service_name(&request.body);
}
