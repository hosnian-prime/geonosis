//! Prometheus `/metrics` endpoint + lightweight request counters.
//!
//! Per `docs/13-observability.md` v0.1 ships a `geonosis_*`-namespaced
//! Prometheus endpoint alongside the OTel traces / logs. The doc lists
//! a small starter set (HTTP requests, audit events, build info); we
//! keep the implementation hand-rolled atop `AtomicU64` so the
//! workspace doesn't grow a `prometheus`-crate dependency before
//! anyone consumes it. The text-format the endpoint emits is the
//! Prometheus exposition format v0.0.4 — Grafana / Prometheus parse
//! it directly, and the `geonosis-cli` `keys/audit/spi` subcommands
//! land later without retooling the metrics layer.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// Per-process metric counters. Cloneable handle so the middleware
/// can bump from inside the request future and the `/metrics` handler
/// can read from outside.
#[derive(Default)]
pub struct MetricsState {
    /// Total HTTP requests served, including the metrics endpoint
    /// itself (Prometheus operators expect self-observation).
    pub http_requests_total: AtomicU64,
    /// Responses that returned a 4xx status — useful as an SLO
    /// signal independent of the 5xx error rate.
    pub http_4xx_total: AtomicU64,
    /// Responses that returned a 5xx status.
    pub http_5xx_total: AtomicU64,
    /// Audit events emitted to any sink. Bumped by the audit publisher
    /// once it grows a hook (v0.1.x). Kept here so the metric is
    /// declared in one place.
    pub audit_events_total: AtomicU64,
    /// Process start time in seconds since the Unix epoch — derived
    /// for `process_start_time_seconds`, the standard Prometheus
    /// process metric.
    pub process_start_time_seconds: u64,
}

impl MetricsState {
    pub fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            http_requests_total: AtomicU64::new(0),
            http_4xx_total: AtomicU64::new(0),
            http_5xx_total: AtomicU64::new(0),
            audit_events_total: AtomicU64::new(0),
            process_start_time_seconds: now,
        }
    }
}

pub type SharedMetrics = Arc<MetricsState>;

/// Tower middleware that bumps `http_requests_total` and the
/// 4xx/5xx counters for every served response. Mount it as
/// `axum::middleware::from_fn_with_state(metrics, count_requests)`.
pub async fn count_requests(
    State(metrics): State<SharedMetrics>,
    req: Request,
    next: Next,
) -> Response {
    let response = next.run(req).await;
    metrics.http_requests_total.fetch_add(1, Ordering::Relaxed);
    let status = response.status().as_u16();
    if (400..500).contains(&status) {
        metrics.http_4xx_total.fetch_add(1, Ordering::Relaxed);
    } else if (500..600).contains(&status) {
        metrics.http_5xx_total.fetch_add(1, Ordering::Relaxed);
    }
    response
}

/// `GET /metrics` handler. Emits the Prometheus text exposition
/// format with a `geonosis_build_info{version="..."}` gauge so
/// dashboards can correlate metric series with deploys.
pub async fn metrics_handler(State(metrics): State<SharedMetrics>) -> Response {
    let body = render(&metrics);
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

fn render(m: &MetricsState) -> String {
    let mut out = String::with_capacity(1024);
    out.push_str("# HELP geonosis_build_info Build identifiers as labels; value is always 1.\n");
    out.push_str("# TYPE geonosis_build_info gauge\n");
    out.push_str(&format!(
        "geonosis_build_info{{version=\"{}\"}} 1\n",
        env!("CARGO_PKG_VERSION")
    ));

    out.push_str("# HELP geonosis_process_start_time_seconds Start time of the process since unix epoch in seconds.\n");
    out.push_str("# TYPE geonosis_process_start_time_seconds gauge\n");
    out.push_str(&format!(
        "geonosis_process_start_time_seconds {}\n",
        m.process_start_time_seconds
    ));

    out.push_str("# HELP geonosis_http_requests_total Total HTTP requests served.\n");
    out.push_str("# TYPE geonosis_http_requests_total counter\n");
    out.push_str(&format!(
        "geonosis_http_requests_total {}\n",
        m.http_requests_total.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP geonosis_http_responses_total HTTP responses bucketed by status class.\n");
    out.push_str("# TYPE geonosis_http_responses_total counter\n");
    out.push_str(&format!(
        "geonosis_http_responses_total{{class=\"4xx\"}} {}\n",
        m.http_4xx_total.load(Ordering::Relaxed)
    ));
    out.push_str(&format!(
        "geonosis_http_responses_total{{class=\"5xx\"}} {}\n",
        m.http_5xx_total.load(Ordering::Relaxed)
    ));

    out.push_str("# HELP geonosis_audit_events_total Total audit events emitted.\n");
    out.push_str("# TYPE geonosis_audit_events_total counter\n");
    out.push_str(&format!(
        "geonosis_audit_events_total {}\n",
        m.audit_events_total.load(Ordering::Relaxed)
    ));

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_emits_build_info_and_counters() {
        let m = MetricsState::new();
        m.http_requests_total.store(7, Ordering::Relaxed);
        m.http_4xx_total.store(3, Ordering::Relaxed);
        let body = render(&m);
        assert!(body.contains("geonosis_build_info{version=\""));
        assert!(body.contains("geonosis_http_requests_total 7"));
        assert!(body.contains("geonosis_http_responses_total{class=\"4xx\"} 3"));
        assert!(body.contains("geonosis_process_start_time_seconds"));
        // Each metric MUST have its HELP + TYPE preamble.
        let help_count = body.matches("# HELP").count();
        let type_count = body.matches("# TYPE").count();
        assert_eq!(help_count, type_count);
        assert!(help_count >= 4);
    }
}
