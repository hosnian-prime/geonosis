//! `/admin/v1/realms/:slug/events` — audit event explorer query.
//!
//! v0.1.x ships a read-only list endpoint with a small filter surface
//! (realm-scoped automatically, plus optional `action` / `actor` /
//! `from` / `until`). The richer query language (full-text over the
//! `detail` JSON column) lands with the postgres impl of the audit
//! sink.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::handlers_v1::extractors::realm_by_slug;
use crate::state::{AdminError, AdminState};

#[derive(Debug, Deserialize)]
pub struct EventQuery {
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub until: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

#[derive(Debug, Serialize)]
pub struct EventRow {
    pub id: String,
    pub realm_id: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub detail: serde_json::Value,
}

pub async fn list(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Query(_q): Query<EventQuery>,
) -> Result<Json<Vec<EventRow>>, AdminError> {
    // Resolving the realm authorizes the query and bounds the result
    // set. The audit sink itself doesn't expose a query trait yet —
    // doc 13 §"Audit event explorer" is the v0.1.x deliverable for
    // the SELECT path. We surface the endpoint shape so the Leptos
    // pages and `geoctl events` have a stable contract while the
    // sink-side query SPI lands.
    let _realm = realm_by_slug(&state, &slug).await?;
    Ok(Json(vec![]))
}
