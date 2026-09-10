// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Scrapes the exposition endpoint the way Vector's prometheus_scrape source would.

#![cfg(feature = "prometheus")]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    time::{Duration, Instant},
};

use v_api_telemetry::prometheus::VApiPrometheus;

/// A free port, found by binding one and letting it go. Racy in principle, but the alternative is
/// a hardcoded port that collides with whatever else is on the machine.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

fn scrape(address: SocketAddr) -> String {
    // The listener is spawned asynchronously by install(), so it may not be accepting yet.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(mut stream) = TcpStream::connect(address) {
            stream
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .expect("write request");
            let mut response = String::new();
            stream.read_to_string(&mut response).expect("read response");
            return response;
        }
        assert!(
            Instant::now() < deadline,
            "exporter never started listening on {address}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

// One test, not several: install() sets a process-global recorder, so a second one in the same
// binary would fail regardless of ordering.
#[test]
fn exposition_carries_metrics_and_labels() {
    let address: SocketAddr = ([127, 0, 0, 1], free_port()).into();

    VApiPrometheus::new("test-service")
        .with_version("1.2.3")
        .with_label("environment", "staging")
        .install_listener(address)
        .expect("install exporter");

    metrics::counter!("requests_total", "route" => "/api/user").increment(3);
    metrics::gauge!("queue_depth").set(7.0);

    let response = scrape(address);

    assert!(
        response.starts_with("HTTP/1.1 200"),
        "unexpected response: {response}"
    );

    for expected in [
        "requests_total",
        "queue_depth",
        // Global labels stand in for OTLP resource attributes.
        "service=\"test-service\"",
        "version=\"1.2.3\"",
        "environment=\"staging\"",
        // Per-metric labels survive alongside them.
        "route=\"/api/user\"",
    ] {
        assert!(
            response.contains(expected),
            "exposition is missing {expected}: {response}"
        );
    }
}
