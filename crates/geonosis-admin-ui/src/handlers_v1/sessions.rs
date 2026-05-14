//! `/admin/v1/realms/:slug/sessions/:session_id` — admin session revoke.

use std::sync::Arc;

use axum::extract::{Path, State};

use geonosis_core::SessionId;

use crate::handlers_v1::extractors::realm_by_slug;
use crate::state::{AdminError, AdminState};

pub async fn revoke(
    State(state): State<Arc<AdminState>>,
    Path((slug, session_id)): Path<(String, String)>,
) -> Result<axum::http::StatusCode, AdminError> {
    // Realm scoping is enforced at the storage layer once that backend
    // supports per-realm session indexing. v0.1 sessions table is
    // globally addressable by id, so a successful realm lookup is
    // sufficient to authorize the call.
    let _realm = realm_by_slug(&state, &slug).await?;
    state
        .storage
        .delete_session(&SessionId(session_id))
        .await
        .map_err(AdminError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
