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

    /// `geonosis_http_request_duration_seconds_bucket{method, path, le}`
    /// + `_sum` + `_count` — Prometheus-style histogram for request
    /// latencies. Powers the `p99_authorize_latency` alert rule
    /// (`histogram_quantile(0.99, ...)` over the 10m window).
    pub http_latency: LabeledHistogram,

    /// `geonosis_db_pool_in_use{}` + `geonosis_db_pool_size{}` —
    /// gauges read from a `sqlx::PgPool` at scrape time. The
    /// Postgres pool registers itself here at server boot via
    /// [`MetricsState::install_db_pool`]; in-memory deployments
    /// leave the slot empty and the gauges are omitted.
    pub db_pool: parking_lot::RwLock<Option<sqlx::PgPool>>,

    /// `geonosis_cache_hits_total{cache}` / `geonosis_cache_misses_total{cache}`
    /// — per-cache-layer hit/miss counters. Bumped by the cache
    /// runtime; the `cache` label is `l1` / `redis` / `local` /
    /// `noop` to split the hit-rate per backend in dashboards.
    pub cache_hits: LabeledCounter,
    pub cache_misses: LabeledCounter,

    /// `geonosis_spi_quarantined_total{interface, urn, reason}` —
    /// bumped by the SPI host when a plugin gets quarantined.
    /// Feeds the `GeonosisSpiQuarantined` alert rule.
    pub spi_quarantined: LabeledCounter,

    /// `geonosis_listener_lag_seconds{channel}` — last observed
    /// staleness of the Postgres LISTEN/NOTIFY cache-invalidation
    /// listener (seconds since the most recent successful
    /// notification). Feeds the `GeonosisListenerLag` alert.
    /// Updated by [`MetricsState::record_listener_lag`].
    pub listener_lag: parking_lot::Mutex<std::collections::HashMap<String, f64>>,
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
            http_latency: LabeledHistogram::new(
                "geonosis_http_request_duration_seconds",
                "HTTP request latency in seconds.",
                &["method", "path"],
                // Power-of-2-in-milliseconds buckets per
                // docs/13-observability.md §"Metrics". Covers the
                // 1ms→16s span that captures everything from a
                // cached JWKS hit to an LDAP-federated login.
                &[0.001, 0.002, 0.004, 0.008, 0.016, 0.032, 0.064, 0.125, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0],
            ),
            db_pool: parking_lot::RwLock::new(None),
            cache_hits: LabeledCounter::new(
                "geonosis_cache_hits_total",
                "Cache hits bucketed by backend layer.",
                &["cache"],
            ),
            cache_misses: LabeledCounter::new(
                "geonosis_cache_misses_total",
                "Cache misses bucketed by backend layer.",
                &["cache"],
            ),
            spi_quarantined: LabeledCounter::new(
                "geonosis_spi_quarantined_total",
                "SPI plugins quarantined by the host (fault threshold / timeout / signature failure).",
                &["interface", "urn", "reason"],
            ),
            listener_lag: parking_lot::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Record the current cache-invalidation listener lag for a
    /// channel. v0.1 has one channel (`geonosis_invalidate`); the
    /// label keeps cardinality bounded and extensible.
    pub fn record_listener_lag(&self, channel: &str, seconds: f64) {
        self.listener_lag
            .lock()
            .insert(channel.to_string(), seconds);
    }

    /// Hand the metrics layer a Postgres pool so `/metrics` can emit
    /// `geonosis_db_pool_in_use` + `geonosis_db_pool_size` at scrape
    /// time. Idempotent; the second call overwrites the first
    /// (operators rotating credentials see the new pool).
    pub fn install_db_pool(&self, pool: sqlx::PgPool) {
        *self.db_pool.write() = Some(pool);
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

/// Labeled Prometheus-style histogram. Keeps per-series bucket
/// counts + `_sum` + `_count` under a single mutex so a single
/// observation is one lock take. Cardinality discipline is the
/// same as [`LabeledCounter`] — label values stay bounded.
pub struct LabeledHistogram {
    name: &'static str,
    help: &'static str,
    label_names: &'static [&'static str],
    buckets: &'static [f64],
    series: Mutex<HashMap<Vec<String>, HistogramSeries>>,
}

#[derive(Default)]
struct HistogramSeries {
    /// `bucket_counts[i]` = count of observations ≤ `buckets[i]`.
    bucket_counts: Vec<u64>,
    sum_seconds: f64,
    count: u64,
}

impl LabeledHistogram {
    pub fn new(
        name: &'static str,
        help: &'static str,
        label_names: &'static [&'static str],
        buckets: &'static [f64],
    ) -> Self {
        debug_assert!(
            buckets.windows(2).all(|w| w[0] < w[1]),
            "histogram buckets must be strictly increasing: {name} got {buckets:?}",
        );
        Self {
            name,
            help,
            label_names,
            buckets,
            series: Mutex::new(HashMap::new()),
        }
    }

    /// Record an observation in seconds. The series is keyed by
    /// `(label_values...)`; matching is `==` on the value vector.
    pub fn observe(&self, label_values: &[&str], seconds: f64) {
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
        let entry = series.entry(key).or_insert_with(|| HistogramSeries {
            bucket_counts: vec![0; self.buckets.len()],
            sum_seconds: 0.0,
            count: 0,
        });
        entry.count += 1;
        entry.sum_seconds += seconds;
        for (i, &threshold) in self.buckets.iter().enumerate() {
            if seconds <= threshold {
                entry.bucket_counts[i] += 1;
            }
        }
    }

    pub fn render(&self, out: &mut String) {
        writeln!(out, "# HELP {} {}", self.name, self.help).unwrap();
        writeln!(out, "# TYPE {} histogram", self.name).unwrap();
        let series = self.series.lock();
        for (values, s) in series.iter() {
            let labels_prefix = self
                .label_names
                .iter()
                .zip(values.iter())
                .map(|(n, v)| format!("{n}=\"{}\"", escape(v)))
                .collect::<Vec<_>>()
                .join(",");
            let comma = if labels_prefix.is_empty() { "" } else { "," };
            for (i, &threshold) in self.buckets.iter().enumerate() {
                writeln!(
                    out,
                    "{}_bucket{{{}{}le=\"{}\"}} {}",
                    self.name, labels_prefix, comma, threshold, s.bucket_counts[i]
                )
                .unwrap();
            }
            writeln!(
                out,
                "{}_bucket{{{}{}le=\"+Inf\"}} {}",
                self.name, labels_prefix, comma, s.count
            )
            .unwrap();
            writeln!(
                out,
                "{}_sum{{{}}} {}",
                self.name, labels_prefix, s.sum_seconds
            )
            .unwrap();
            writeln!(out, "{}_count{{{}}} {}", self.name, labels_prefix, s.count).unwrap();
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

/// Tower middleware that bumps `http_requests_total`, the
/// 4xx/5xx response-class counters, and records the request
/// latency into the `http_latency` histogram. Mount it as
/// `axum::middleware::from_fn_with_state(metrics, count_requests)`.
///
/// The `path` label uses the matched route template (so
/// `/realms/:slug/protocol/saml/sso` instead of the resolved
/// `/realms/acme/protocol/saml/sso`) to keep cardinality bounded
/// — every realm slug would otherwise spawn its own series.
pub async fn count_requests(
    State(metrics): State<SharedMetrics>,
    req: Request,
    next: Next,
) -> Response {
    let started = std::time::Instant::now();
    let method = req.method().clone();
    // `MatchedPath` extension is set by axum's router before our
    // middleware runs; falling back to the raw URI keeps the
    // counter useful for routes the matcher doesn't cover yet.
    let path = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let response = next.run(req).await;
    let elapsed = started.elapsed().as_secs_f64();
    metrics.http_requests_total.fetch_add(1, Ordering::Relaxed);
    let status = response.status().as_u16();
    if (400..500).contains(&status) {
        metrics.http_4xx_total.fetch_add(1, Ordering::Relaxed);
    } else if (500..600).contains(&status) {
        metrics.http_5xx_total.fetch_add(1, Ordering::Relaxed);
    }
    metrics
        .http_latency
        .observe(&[method.as_str(), &path], elapsed);
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
    m.http_latency.render(&mut out);
    m.cache_hits.render(&mut out);
    m.cache_misses.render(&mut out);
    m.spi_quarantined.render(&mut out);

    // Listener-lag gauge — emit once per channel currently tracked.
    let lag = m.listener_lag.lock().clone();
    if !lag.is_empty() {
        out.push_str(
            "# HELP geonosis_listener_lag_seconds Time since the last successful cache-invalidation notification, per channel.\n# TYPE geonosis_listener_lag_seconds gauge\n",
        );
        for (channel, secs) in lag.iter() {
            out.push_str(&format!(
                "geonosis_listener_lag_seconds{{channel=\"{}\"}} {}\n",
                escape(channel),
                secs
            ));
        }
    }

    // DB pool gauges: read live from sqlx::Pool stats so a scrape
    // always sees the current depth. Skipped when the in-memory
    // backend is in use.
    if let Some(pool) = m.db_pool.read().clone() {
        let size = pool.size() as u64;
        let idle = pool.num_idle() as u64;
        let in_use = size.saturating_sub(idle);
        out.push_str(
            "# HELP geonosis_db_pool_size Total connections held by the Postgres pool.\n# TYPE geonosis_db_pool_size gauge\n",
        );
        out.push_str(&format!("geonosis_db_pool_size {}\n", size));
        out.push_str(
            "# HELP geonosis_db_pool_in_use Connections currently checked out from the Postgres pool.\n# TYPE geonosis_db_pool_in_use gauge\n",
        );
        out.push_str(&format!("geonosis_db_pool_in_use {}\n", in_use));
    }

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

    #[test]
    fn histogram_buckets_count_observations_at_or_below_threshold() {
        let m = MetricsState::new();
        // Three observations at 5ms, 50ms, 500ms.
        m.http_latency.observe(&["GET", "/x"], 0.005);
        m.http_latency.observe(&["GET", "/x"], 0.050);
        m.http_latency.observe(&["GET", "/x"], 0.500);

        let body = render(&m);
        // 0.008 bucket sees the 5ms hit only → count 1.
        assert!(body.contains("geonosis_http_request_duration_seconds_bucket{method=\"GET\",path=\"/x\",le=\"0.008\"} 1"));
        // 0.064 bucket sees 5ms + 50ms → count 2.
        assert!(body.contains("geonosis_http_request_duration_seconds_bucket{method=\"GET\",path=\"/x\",le=\"0.064\"} 2"));
        // +Inf MUST equal count.
        assert!(body.contains("geonosis_http_request_duration_seconds_bucket{method=\"GET\",path=\"/x\",le=\"+Inf\"} 3"));
        // Sum + count rendered.
        assert!(body.contains("geonosis_http_request_duration_seconds_count"));
        assert!(body.contains("geonosis_http_request_duration_seconds_sum"));
    }

    #[test]
    fn histogram_label_arity_mismatch_debug_panics() {
        // The debug_assert! catches the most common operator
        // mistake — adding an unrelated label to an existing
        // counter. We only assert the contract here; the production
        // path is debug_assert so release builds drop the check.
        let h = LabeledHistogram::new("test", "test", &["a", "b"], &[1.0]);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            h.observe(&["only-one"], 0.1)
        }));
        // Under debug_assertions the call panics; the test runs in
        // debug profile so this is the expected outcome.
        if cfg!(debug_assertions) {
            assert!(result.is_err());
        }
    }

    #[test]
    fn cache_hit_miss_counters_render_with_cache_label() {
        let m = MetricsState::new();
        m.cache_hits.inc(&["l1"]);
        m.cache_hits.inc(&["l1"]);
        m.cache_misses.inc(&["l1"]);
        m.cache_hits.inc(&["redis"]);
        let body = render(&m);
        assert!(body.contains("geonosis_cache_hits_total{cache=\"l1\"} 2"));
        assert!(body.contains("geonosis_cache_misses_total{cache=\"l1\"} 1"));
        assert!(body.contains("geonosis_cache_hits_total{cache=\"redis\"} 1"));
    }

    #[test]
    fn spi_quarantined_carries_interface_urn_reason_labels() {
        let m = MetricsState::new();
        m.spi_quarantined
            .inc(&["geonosis:authn@0.1.0", "wasm:custom:authn", "timeout"]);
        let body = render(&m);
        assert!(body.contains(
            "geonosis_spi_quarantined_total{interface=\"geonosis:authn@0.1.0\",urn=\"wasm:custom:authn\",reason=\"timeout\"} 1"
        ));
    }

    #[test]
    fn listener_lag_renders_per_channel_when_set() {
        let m = MetricsState::new();
        m.record_listener_lag("geonosis_invalidate", 3.5);
        let body = render(&m);
        assert!(body.contains("# TYPE geonosis_listener_lag_seconds gauge"));
        assert!(body.contains(
            "geonosis_listener_lag_seconds{channel=\"geonosis_invalidate\"} 3.5"
        ));
    }

    #[test]
    fn listener_lag_omits_block_when_no_channels_tracked() {
        // When the listener hasn't reported yet the body shouldn't
        // carry a no-data preamble; alert rules tolerate no-data
        // by design.
        let m = MetricsState::new();
        let body = render(&m);
        assert!(!body.contains("geonosis_listener_lag_seconds"));
    }
}
