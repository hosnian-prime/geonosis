//! Prometheus `/metrics` endpoint + lightweight request counters.
//!
//! Per `docs/13-observability.md` v0.1 ships a `geonosis_*`-namespaced
//! Prometheus endpoint alongside the OTel traces / logs. We keep the
//! implementation hand-rolled atop `AtomicU64` + `HashMap` so the
//! workspace doesn't grow a `prometheus`-crate dependency before
//! anyone consumes it. The text-format the endpoint emits is the
//! Prometheus exposition format v0.0.4 — Grafana / Prometheus parse
//! it directly.
//!
//! Two metric kinds are wired today:
//!
//! - **Process-wide counters** (HTTP RPS, response class, audit
//!   pipeline ingest) live as bare `AtomicU64`s.
//! - **Labeled counters** (per-realm OIDC throughput, login failures
//!   by reason, token reuse) use [`LabeledCounter`], a thin
//!   `HashMap<Vec<String>, u64>` behind a `parking_lot::Mutex`.
//!   Hot paths take a single mutex per increment; cardinality
//!   stays bounded because every label dimension is either a realm
//!   slug or a small enumeration (`grant_type`, `outcome`,
//!   `reason`).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use parking_lot::Mutex;

/// Per-process metric counters. Cloneable handle so the middleware
/// can bump from inside the request future and the `/metrics`
/// handler can read from outside.
pub struct MetricsState {
    /// Total HTTP requests served, including the metrics endpoint
    /// itself (Prometheus operators expect self-observation).
    pub http_requests_total: AtomicU64,
    /// Responses that returned a 4xx status — useful as an SLO
    /// signal independent of the 5xx error rate.
    pub http_4xx_total: AtomicU64,
    /// Responses that returned a 5xx status.
    pub http_5xx_total: AtomicU64,
    /// Audit events emitted to any sink. Bumped by the audit
    /// publisher once it grows a hook (v0.1.x).
    pub audit_events_total: AtomicU64,
    /// Process start time in seconds since the Unix epoch — derived
    /// for `process_start_time_seconds`, the standard Prometheus
    /// process metric.
    pub process_start_time_seconds: u64,

    /// `geonosis_oidc_authorize_total{realm, outcome}` — every entry
    /// to the `/authorize` endpoint exits through here.
    pub oidc_authorize: LabeledCounter,
    /// `geonosis_oidc_token_total{realm, grant_type, outcome}` —
    /// dispatched by the `/token` endpoint per resolved grant type.
    pub oidc_token: LabeledCounter,
    /// `geonosis_oidc_login_failures_total{realm, reason}` —
    /// recorded for password / device-code / token-exchange paths
    /// that resolve to `invalid_grant`.
    pub oidc_login_failures: LabeledCounter,
    /// `geonosis_session_created_total{realm}` and
    /// `geonosis_session_revoked_total{realm, reason}` — wired into
    /// the session-create + admin-revoke paths.
    pub session_created: LabeledCounter,
    pub session_revoked: LabeledCounter,
    /// `geonosis_token_reuse_detected_total{realm}` — security
    /// signal raised when `validate_refresh` returns `Reuse` and
    /// the family is burned. Doc 13's alert rule
    /// `GeonosisTokenReuse` reads this directly.
    pub token_reuse_detected: LabeledCounter,
}

impl Default for MetricsState {
    fn default() -> Self {
        Self::new()
    }
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
            oidc_authorize: LabeledCounter::new(
                "geonosis_oidc_authorize_total",
                "OIDC /authorize attempts bucketed by outcome.",
                &["realm", "outcome"],
            ),
            oidc_token: LabeledCounter::new(
                "geonosis_oidc_token_total",
                "OIDC /token attempts bucketed by grant type + outcome.",
                &["realm", "grant_type", "outcome"],
            ),
            oidc_login_failures: LabeledCounter::new(
                "geonosis_oidc_login_failures_total",
                "OIDC login failures bucketed by reason.",
                &["realm", "reason"],
            ),
            session_created: LabeledCounter::new(
                "geonosis_session_created_total",
                "Sessions persisted after a successful interactive login.",
                &["realm"],
            ),
            session_revoked: LabeledCounter::new(
                "geonosis_session_revoked_total",
                "Sessions revoked, bucketed by reason.",
                &["realm", "reason"],
            ),
            token_reuse_detected: LabeledCounter::new(
                "geonosis_token_reuse_detected_total",
                "Refresh-token reuse events — burning the entire token family.",
                &["realm"],
            ),
        }
    }
}

pub type SharedMetrics = Arc<MetricsState>;

/// Labeled monotonic counter rendered into Prometheus text format.
///
/// Cardinality is the operator's responsibility: every label value
/// passed to [`inc`] becomes a permanent series until process
/// restart, so callers must keep label dimensions bounded (realm
/// slug + small enumerations only — never raw user input).
pub struct LabeledCounter {
    name: &'static str,
    help: &'static str,
    label_names: &'static [&'static str],
    series: Mutex<HashMap<Vec<String>, u64>>,
}

impl LabeledCounter {
    pub fn new(
        name: &'static str,
        help: &'static str,
        label_names: &'static [&'static str],
    ) -> Self {
        Self {
            name,
            help,
            label_names,
            series: Mutex::new(HashMap::new()),
        }
    }

    /// Increment the series identified by `label_values`. The slice
    /// must match `label_names` in arity and order.
    pub fn inc(&self, label_values: &[&str]) {
        debug_assert_eq!(
            label_values.len(),
            self.label_names.len(),
            "label arity mismatch for {}: expected {:?}, got {:?}",
            self.name,
            self.label_names,
            label_values
        );
        let key: Vec<String> = label_values.iter().map(|s| (*s).to_string()).collect();
        let mut series = self.series.lock();
        *series.entry(key).or_insert(0) += 1;
    }

    /// Append the metric's HELP / TYPE preamble and one line per
    /// series to `out`. Series ordering is unspecified — Prometheus
    /// doesn't require a stable order inside the exposition format.
    pub fn render(&self, out: &mut String) {
        writeln!(out, "# HELP {} {}", self.name, self.help).unwrap();
        writeln!(out, "# TYPE {} counter", self.name).unwrap();
        let series = self.series.lock();
        for (values, count) in series.iter() {
            let labels = self
                .label_names
                .iter()
                .zip(values.iter())
                .map(|(n, v)| format!("{n}=\"{}\"", escape(v)))
                .collect::<Vec<_>>()
                .join(",");
            if labels.is_empty() {
                writeln!(out, "{} {}", self.name, count).unwrap();
            } else {
                writeln!(out, "{}{{{}}} {}", self.name, labels, count).unwrap();
            }
        }
    }
}

fn escape(value: &str) -> String {
    // Prometheus exposition format escapes backslash, double-quote,
    // and newline in label values. Every label value we produce is a
    // realm slug or a controlled enum, but escaping defensively
    // costs nothing.
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

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
    let mut out = String::with_capacity(2048);
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

    // Labeled OIDC + security counters.
    m.oidc_authorize.render(&mut out);
    m.oidc_token.render(&mut out);
    m.oidc_login_failures.render(&mut out);
    m.session_created.render(&mut out);
    m.session_revoked.render(&mut out);
    m.token_reuse_detected.render(&mut out);

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
        assert!(help_count >= 10);
    }

    #[test]
    fn labeled_counter_records_one_series_per_label_tuple() {
        let m = MetricsState::new();
        m.oidc_authorize.inc(&["acme", "success"]);
        m.oidc_authorize.inc(&["acme", "success"]);
        m.oidc_authorize.inc(&["acme", "invalid_client"]);
        m.oidc_authorize.inc(&["other", "success"]);

        let body = render(&m);
        assert!(body.contains("geonosis_oidc_authorize_total{realm=\"acme\",outcome=\"success\"} 2"));
        assert!(body.contains("geonosis_oidc_authorize_total{realm=\"acme\",outcome=\"invalid_client\"} 1"));
        assert!(body.contains("geonosis_oidc_authorize_total{realm=\"other\",outcome=\"success\"} 1"));
    }

    #[test]
    fn token_reuse_counter_renders_with_realm_label() {
        let m = MetricsState::new();
        m.token_reuse_detected.inc(&["acme"]);
        m.token_reuse_detected.inc(&["acme"]);
        let body = render(&m);
        assert!(body.contains("geonosis_token_reuse_detected_total{realm=\"acme\"} 2"));
    }

    #[test]
    fn escape_handles_quote_and_backslash_in_label_value() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape(r#"with "quote""#), r#"with \"quote\""#);
        assert_eq!(escape(r"with \back"), r"with \\back");
    }
}
