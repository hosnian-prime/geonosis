//! HTTP webhook audit sink.
//!
//! POSTs each `AuditEvent` as JSON to a configured URL. Retries
//! transient failures (network errors, 5xx, 429) with capped
//! exponential backoff; gives up after the configured `max_attempts`
//! and logs the event to the warn-level tracing target as a
//! dead-letter record so operators can audit the loss off-band.
//!
//! Per doc 13 §"Audit sinks": the sink must never block the producing
//! request. The `Publisher` already runs sinks off the request hot
//! path; we additionally enforce a per-attempt timeout so a stuck
//! peer can't queue retries forever.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{AuditError, AuditEvent, AuditSink};

/// Configuration for one webhook sink instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSinkConfig {
    /// Absolute URL the events POST to.
    pub url: String,
    /// Optional bearer token sent as `Authorization: Bearer <token>`.
    #[serde(default)]
    pub auth_bearer: Option<String>,
    /// Extra HTTP headers (e.g. signing headers, vendor secrets).
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    /// Per-attempt timeout. Defaults to 5 seconds.
    #[serde(default = "default_attempt_timeout")]
    pub attempt_timeout: Duration,
    /// Maximum retry attempts including the first. Defaults to 4.
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    /// Initial backoff between retries; doubles each attempt up to the
    /// configured maximum. Defaults to 250ms.
    #[serde(default = "default_initial_backoff")]
    pub initial_backoff: Duration,
    /// Cap on the per-retry backoff. Defaults to 8 seconds.
    #[serde(default = "default_max_backoff")]
    pub max_backoff: Duration,
}

fn default_attempt_timeout() -> Duration {
    Duration::from_secs(5)
}
fn default_max_attempts() -> u32 {
    4
}
fn default_initial_backoff() -> Duration {
    Duration::from_millis(250)
}
fn default_max_backoff() -> Duration {
    Duration::from_secs(8)
}

impl WebhookSinkConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            auth_bearer: None,
            headers: vec![],
            attempt_timeout: default_attempt_timeout(),
            max_attempts: default_max_attempts(),
            initial_backoff: default_initial_backoff(),
            max_backoff: default_max_backoff(),
        }
    }
}

pub struct WebhookSink {
    config: WebhookSinkConfig,
    client: reqwest::Client,
}

impl WebhookSink {
    /// Build a sink. Reuses a single `reqwest::Client` (connection
    /// pool, HTTP/2) across events so a busy realm doesn't churn
    /// sockets.
    pub fn new(config: WebhookSinkConfig) -> Result<Self, AuditError> {
        let client = reqwest::Client::builder()
            // The attempt-level timeout below is the real bound; this
            // is a defensive floor for DNS / TLS handshake stages.
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| AuditError::Backend(format!("reqwest client: {e}")))?;
        Ok(Self { config, client })
    }

    /// Calculate the backoff for attempt N (0-indexed). Doubles each
    /// time, capped at `max_backoff`.
    fn backoff_for(&self, attempt: u32) -> Duration {
        let factor = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
        let scaled = self
            .config
            .initial_backoff
            .checked_mul(factor.min(u32::MAX as u64) as u32)
            .unwrap_or(self.config.max_backoff);
        scaled.min(self.config.max_backoff)
    }

    async fn try_post(&self, event: &AuditEvent) -> Result<(), reqwest::Error> {
        let mut req = self
            .client
            .post(&self.config.url)
            .timeout(self.config.attempt_timeout)
            .json(event);
        if let Some(token) = &self.config.auth_bearer {
            req = req.bearer_auth(token);
        }
        for (k, v) in &self.config.headers {
            req = req.header(k, v);
        }
        let resp = req.send().await?;
        // 2xx and 3xx accepted; 4xx (except 429) are caller errors and
        // not retried; 5xx + 429 surface as `error_for_status` so the
        // retry loop sees them as `Err`.
        let status = resp.status();
        if status.is_success() || status.is_redirection() {
            return Ok(());
        }
        if status.as_u16() == 429 || status.is_server_error() {
            resp.error_for_status().map(|_| ())
        } else {
            // 4xx that aren't 429 — treat as permanent. We surface the
            // error so the retry loop drops it as a dead letter.
            resp.error_for_status().map(|_| ())
        }
    }
}

#[async_trait]
impl AuditSink for WebhookSink {
    async fn ingest(&self, event: AuditEvent) -> Result<(), AuditError> {
        for attempt in 0..self.config.max_attempts {
            match self.try_post(&event).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let permanent = e
                        .status()
                        .map(|s| s.is_client_error() && s.as_u16() != 429 && s.as_u16() != 408)
                        .unwrap_or(false);
                    if permanent {
                        // 4xx (except 429/408) — won't change on retry.
                        // Log + drop. Dead-letter logging is the v0.1
                        // mechanism; v0.2 promotes to a sidecar table.
                        tracing::warn!(
                            error = %e,
                            event_id = %event.id,
                            event_action = %event.action,
                            "audit webhook permanent failure; dropping event",
                        );
                        return Err(AuditError::Backend(format!("permanent: {e}")));
                    }
                    if attempt + 1 == self.config.max_attempts {
                        tracing::warn!(
                            error = %e,
                            attempts = self.config.max_attempts,
                            event_id = %event.id,
                            event_action = %event.action,
                            "audit webhook retries exhausted; dropping event",
                        );
                        return Err(AuditError::Backend(format!("retries exhausted: {e}")));
                    }
                    let wait = self.backoff_for(attempt);
                    tracing::debug!(
                        attempt = attempt + 1,
                        backoff_ms = wait.as_millis() as u64,
                        error = %e,
                        "audit webhook attempt failed, backing off",
                    );
                    tokio::time::sleep(wait).await;
                }
            }
        }
        Err(AuditError::Backend("max_attempts is zero".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_then_caps() {
        let sink = WebhookSink::new(WebhookSinkConfig {
            url: "http://localhost".into(),
            auth_bearer: None,
            headers: vec![],
            attempt_timeout: Duration::from_secs(1),
            max_attempts: 5,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(800),
        })
        .unwrap();
        assert_eq!(sink.backoff_for(0), Duration::from_millis(100));
        assert_eq!(sink.backoff_for(1), Duration::from_millis(200));
        assert_eq!(sink.backoff_for(2), Duration::from_millis(400));
        // Capped at 800ms.
        assert_eq!(sink.backoff_for(3), Duration::from_millis(800));
        assert_eq!(sink.backoff_for(10), Duration::from_millis(800));
    }

    #[test]
    fn config_defaults_match_doc_13() {
        let c = WebhookSinkConfig::new("https://hooks.example/audit");
        assert_eq!(c.max_attempts, 4);
        assert_eq!(c.initial_backoff, Duration::from_millis(250));
        assert_eq!(c.max_backoff, Duration::from_secs(8));
        assert_eq!(c.attempt_timeout, Duration::from_secs(5));
    }

    #[test]
    fn config_round_trips_through_json() {
        let c = WebhookSinkConfig {
            url: "https://hooks.example/audit".into(),
            auth_bearer: Some("t-1".into()),
            headers: vec![("x-tenant".into(), "acme".into())],
            attempt_timeout: Duration::from_secs(3),
            max_attempts: 6,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(4),
        };
        let j = serde_json::to_string(&c).unwrap();
        let back: WebhookSinkConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(back.url, c.url);
        assert_eq!(back.auth_bearer, c.auth_bearer);
        assert_eq!(back.headers, c.headers);
        assert_eq!(back.max_attempts, c.max_attempts);
    }
}
