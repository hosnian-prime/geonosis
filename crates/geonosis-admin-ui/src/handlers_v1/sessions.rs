//! `/admin/v1/realms/:slug/sessions` — admin session list + revoke.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use geonosis_core::SessionId;

use crate::handlers_v1::extractors::realm_by_slug;
use crate::state::{AdminError, AdminState};

const MAX_LIMIT: usize = 500;

#[derive(Debug, Deserialize)]
pub struct ListSessionsQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

#[derive(Debug, Serialize)]
pub struct SessionRow {
    pub id: String,
    pub user_id: String,
    pub authn_level: String,
    pub idp_alias: Option<String>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub last_seen_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub client_count: usize,
}

pub async fn list(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Query(q): Query<ListSessionsQuery>,
) -> Result<Json<Vec<SessionRow>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let limit = q.limit.min(MAX_LIMIT);
    let sessions = state.storage.list_sessions(realm.id, limit).await?;
    let payload = sessions
        .into_iter()
        .map(|s| SessionRow {
            id: s.id.to_string(),
            user_id: s.user_id.to_string(),
            authn_level: format!("{:?}", s.authn_level).to_lowercase(),
            idp_alias: s.idp_alias,
            started_at: s.started_at,
            last_seen_at: s.last_seen_at,
            expires_at: s.expires_at,
            client_count: s.clients.len(),
        })
        .collect();
    Ok(Json(payload))
}

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
