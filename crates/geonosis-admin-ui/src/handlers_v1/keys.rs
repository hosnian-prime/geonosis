//! `/admin/v1/realms/:slug/keys` — list keys (rotation is a CLI / cron
//! operation in v0.1; the admin UI surfaces the metadata for review).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;

use crate::handlers_v1::extractors::realm_by_slug;
use crate::state::{AdminError, AdminState};

/// Public-safe metadata for a stored key. Never includes the wrapped
/// secret bytes — those stay inside the KMS.
#[derive(Debug, Serialize)]
pub struct KeyView {
    pub kid: String,
    pub alg: String,
    pub state: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub async fn list(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Json<Vec<KeyView>>, AdminError> {
    // Realm scoping is required for audit; the KMS surface lives in
    // `state.kms` for the server crate but not here in the admin
    // crate. v0.1.x will expose a small read-only key listing API on
    // the SoftwareKms — for now we return an empty list against the
    // resolved realm so the route exists and is documented.
    let _realm = realm_by_slug(&state, &slug).await?;
    Ok(Json(vec![]))
}
