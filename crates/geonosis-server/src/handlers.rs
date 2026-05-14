//! HTTP handlers. v0.1 ships:
//!
//! - Health probes: `/-/started`, `/-/ready`, `/-/healthy`
//! - Discovery: `/realms/{slug}/.well-known/openid-configuration`
//! - JWKS: `/realms/{slug}/protocol/openid-connect/jwks`
//!
//! `/authorize` + `/token` wiring lives in `app.rs` once the handler
//! ergonomics around `axum::extract::Form` + grant dispatch lands. The
//! protocol decisions (parsing + invariants) are already covered by
//! tests in `geonosis-protocol-oidc` + `geonosis-protocol-oauth`.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use url::Url;

use geonosis_protocol_oidc::{discovery_document, DiscoveryDocument};

use crate::state::AppState;

/// `GET /-/started`
pub async fn started() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// `GET /-/ready` — should turn `503` if DB / cache become unreachable.
pub async fn ready(State(_state): State<AppState>) -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// `GET /-/healthy` — liveness; turns to `503` only on internal panic recovery state.
pub async fn healthy() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

/// `GET /realms/{slug}/.well-known/openid-configuration`
pub async fn openid_configuration(
    Path(slug): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<DiscoveryDocument>, (StatusCode, String)> {
    let realm = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "realm not found".into()))?;
    let issuer = realm_issuer_url(&state.public_base_url, &realm.slug)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(discovery_document(issuer)))
}

/// `GET /realms/{slug}/protocol/openid-connect/jwks`
pub async fn jwks(
    Path(slug): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<geonosis_crypto::JwkSet>, (StatusCode, String)> {
    let realm = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "realm not found".into()))?;
    let set = geonosis_crypto::KeyManagementService::jwks(&*state.kms, realm.id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(set))
}

fn realm_issuer_url(base: &Url, slug: &str) -> Result<Url, url::ParseError> {
    let mut u = base.clone();
    u.set_path(&format!("/realms/{slug}"));
    Ok(u)
}

#[allow(dead_code)]
async fn _coerce<T>(_v: Arc<T>) {}
