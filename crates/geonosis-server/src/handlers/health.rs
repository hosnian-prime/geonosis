use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::state::AppState;

/// `GET /-/started`
pub async fn started() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// `GET /-/ready` — turns 503 if DB / cache become unreachable. v0.1
/// in-memory backend never fails the readiness check.
pub async fn ready(State(_state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// `GET /-/healthy` — liveness; turns 503 only on internal panic recovery state.
pub async fn healthy() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}
