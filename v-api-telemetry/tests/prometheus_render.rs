// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Covers the path `v_api::endpoints::metrics::metrics_op` serves from.
//!
//! A separate test binary from prometheus_scrape.rs on purpose: installing sets a process-global
//! recorder, so only one install can succeed per process.

#![cfg(feature = "prometheus")]

use v_api_telemetry::prometheus::{VApiPrometheus, render};

#[test]
fn render_reports_metrics_and_labels() {
    assert!(
        render().is_none(),
        "render should report nothing before a recorder is installed"
    );

    VApiPrometheus::new("test-service")
        .with_version("1.2.3")
        .with_label("environment", "staging")
        .install_handler()
        .expect("install recorder");

    metrics::counter!("requests_total", "route" => "/api/user").increment(3);
    metrics::histogram!("request_duration_seconds").record(0.25);

    let exposition = render().expect("render after install");

    for expected in [
        "requests_total",
        // Global labels stand in for OTLP resource attributes.
        "service=\"test-service\"",
        "version=\"1.2.3\"",
        "environment=\"staging\"",
        // Per-metric labels survive alongside them.
        "route=\"/api/user\"",
    ] {
        assert!(
            exposition.contains(expected),
            "exposition is missing {expected}: {exposition}"
        );
    }

    // render() drains histograms into distributions on its way through, so this does not depend on
    // the upkeep thread and does not exercise it. Nothing here covers upkeep: its job is to bound
    // recorder growth while nobody is scraping, which a test would have to wait out to observe.
    assert!(
        exposition.contains("request_duration_seconds"),
        "exposition is missing the histogram: {exposition}"
    );

    // Checked here rather than as its own test: tests in a binary run concurrently, and a second
    // test installing a recorder would race the assertions above.
    assert!(
        VApiPrometheus::new("test-service")
            .install_handler()
            .is_err(),
        "a second install should be refused rather than silently replacing the first"
    );
}
