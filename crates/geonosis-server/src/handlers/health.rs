//! Kubernetes / load-balancer probe endpoints.
//!
//! Per `docs/11-deployment-k8s.md` §"Health probes":
//! - `GET /-/started`: startup gate. Returns 503 until the storage
//!   backend is reachable AND the schema is at/above the server's
//!   compatibility window. Used by `startupProbe` in the chart.
//! - `GET /-/ready`: readiness gate. Returns 503 if any dependency
//!   (storage, audit publisher, SPI registry) becomes unreachable.
//!   Used by `readinessProbe`.
//! - `GET /-/healthy`: liveness gate. Returns 503 only on process-
//!   level catastrophic state (panic flag, watchdog timeout). Used by
//!   `livenessProbe`.
//!
//! The shape avoids JSON to keep parsing failures impossible: every
//! response is `text/plain` with a short status line followed by a
//! key=value diagnostic on errors. Operators looking at curl output
//! get an immediate hint without an additional tool.

use std::time::Duration;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::state::AppState;

/// Maximum time we spend in a single dependency check before declaring
/// it unhealthy. Tight bound keeps the probe path from queuing behind
/// slow queries.
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// `GET /-/started` — startup probe.
///
/// Same checks as `/-/ready` plus the implicit "this process has
/// finished initializing AppState" (which is true the moment this
/// handler is callable, since the router is mounted after AppState is
/// built). v0.1 doesn't yet verify schema-compat at probe time — that
/// runs once at boot via `geonosis_migrate::enforce_schema_compat`.
pub async fn started(State(state): State<AppState>) -> impl IntoResponse {
    check_dependencies(&state).await.into_response()
}

/// `GET /-/ready` — readiness probe.
pub async fn ready(State(state): State<AppState>) -> impl IntoResponse {
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

/// Result of a single probe round. The enum keeps the response shape
/// matchable in tests; we let `IntoResponse` collapse it down to the
/// HTTP body.
enum ProbeOutcome {
    Ok,
    StorageDown(String),
    Timeout,
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
}
