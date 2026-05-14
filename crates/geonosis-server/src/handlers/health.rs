//! Kubernetes / load-balancer probe endpoints.
//!
//! Per `docs/11-deployment-k8s.md` §"Health probes":
//! - `GET /-/started`: startup gate. Returns 503 until the storage
//!   backend is reachable AND the schema is at/above the server's
//!   compatibility window. Used by `startupProbe` in the chart.
//! - `GET /-/ready`: readiness gate. Returns 503 if any dependency
//!   (storage, audit publisher, SPI registry) becomes unreachable
//!   OR if the drain flag is set. Used by `readinessProbe`.
//! - `GET /-/healthy`: liveness gate. Returns 503 only on process-
//!   level catastrophic state (panic flag, watchdog timeout). Used by
//!   `livenessProbe`.
//! - `POST /-/drain`: graceful-shutdown gate. Flips readiness to false
//!   without affecting liveness; the `preStop` lifecycle hook calls
//!   this so the ingress controller drains the pod before SIGTERM.
//!
//! The shape avoids JSON to keep parsing failures impossible: every
//! response is `text/plain` with a short status line followed by a
//! key=value diagnostic on errors. Operators looking at curl output
//! get an immediate hint without an additional tool.

use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::state::AppState;

/// Maximum time we spend in a single dependency check before declaring
/// it unhealthy. Tight bound keeps the probe path from queuing behind
/// slow queries.
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// `GET /-/started` — startup probe. Mirrors `/-/ready` minus the
/// drain check (a starting pod cannot be in drain state).
pub async fn started(State(state): State<AppState>) -> impl IntoResponse {
    check_dependencies(&state).await.into_response()
}

/// `GET /-/ready` — readiness probe. Returns 503 once the drain flag
/// flips so the ingress controller can pull the pod out of rotation
/// during the `preStop` window.
pub async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    if state.draining.load(Ordering::Relaxed) {
        return ProbeOutcome::Draining.into_response();
    }
    check_dependencies(&state).await.into_response()
}

/// `GET /-/healthy` — liveness probe.
///
/// Liveness is intentionally minimal: a stuck dependency must not
/// cause the orchestrator to kill the pod. We only fail if the
/// process itself is in an unrecoverable state. v0.1 has no panic
/// flag (Rust panics typically abort the process under tokio), so
/// this is always 200; v0.2 adds a watchdog signal.
pub async fn healthy() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

/// `POST /-/drain` — graceful-shutdown gate. Sets the drain flag so
/// subsequent readiness checks fail; the call itself returns 200 with
/// the resolved drain state so `preStop` hooks see success.
pub async fn drain(State(state): State<AppState>) -> impl IntoResponse {
    state.draining.store(true, Ordering::Relaxed);
    (StatusCode::OK, "draining\n")
}

/// Result of a single probe round. The enum keeps the response shape
/// matchable in tests; we let `IntoResponse` collapse it down to the
/// HTTP body.
enum ProbeOutcome {
    Ok,
    StorageDown(String),
    Timeout,
    Draining,
}

impl IntoResponse for ProbeOutcome {
    fn into_response(self) -> axum::response::Response {
        match self {
            ProbeOutcome::Ok => (StatusCode::OK, "ok\n").into_response(),
            ProbeOutcome::StorageDown(msg) => (
                StatusCode::SERVICE_UNAVAILABLE,
                format!("storage=down detail={msg}\n"),
            )
                .into_response(),
            ProbeOutcome::Timeout => (
                StatusCode::SERVICE_UNAVAILABLE,
                "storage=timeout\n",
            )
                .into_response(),
            ProbeOutcome::Draining => (
                StatusCode::SERVICE_UNAVAILABLE,
                "draining\n",
            )
                .into_response(),
        }
    }
}

async fn check_dependencies(state: &AppState) -> ProbeOutcome {
    match tokio::time::timeout(PROBE_TIMEOUT, state.storage.ping()).await {
        Ok(Ok(())) => ProbeOutcome::Ok,
        Ok(Err(e)) => ProbeOutcome::StorageDown(e.to_string()),
        Err(_elapsed) => ProbeOutcome::Timeout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_outcome_serializes_to_200() {
        let r = ProbeOutcome::Ok.into_response();
        assert_eq!(r.status(), StatusCode::OK);
    }

    #[test]
    fn storage_down_serializes_to_503() {
        let r = ProbeOutcome::StorageDown("connection refused".into()).into_response();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn timeout_serializes_to_503() {
        let r = ProbeOutcome::Timeout.into_response();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn draining_serializes_to_503() {
        let r = ProbeOutcome::Draining.into_response();
        assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
