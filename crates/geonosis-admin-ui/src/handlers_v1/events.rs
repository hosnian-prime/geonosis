//! `/admin/v1/realms/:slug/events` — audit event explorer query.
//!
//! Realm-scoped read-only window into the `audit_event` table.
//! Filters mirror what the Leptos audit-explorer page surfaces:
//! optional `action` (exact match), `actor` (substring match against
//! the JSONB `actor` cast to text), and a time window via `from` /
//! `until`. Hard-capped at `limit=500` so an unfiltered page request
//! cannot pull megabytes back over the admin tier.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::handlers_v1::extractors::realm_by_slug;
use crate::state::{AdminError, AdminState};

const MAX_LIMIT: usize = 500;

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
    pub actor: serde_json::Value,
    pub action: String,
    pub target: Option<serde_json::Value>,
    pub detail: serde_json::Value,
}

pub async fn list(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Query(q): Query<EventQuery>,
) -> Result<Json<Vec<EventRow>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let limit = q.limit.min(MAX_LIMIT);
    let filter = geonosis_storage::AuditEventFilter {
        action: q.action.as_deref(),
        actor: q.actor.as_deref(),
        from: q.from,
        until: q.until,
    };
    let rows = state.storage.list_audit_events(realm.id, &filter, limit).await?;
    let payload = rows
        .into_iter()
        .map(|r| EventRow {
            id: r.id,
            realm_id: r.realm_id,
            occurred_at: r.occurred_at,
            actor: r.actor,
            action: r.action,
            target: r.target,
            detail: r.detail,
        })
        .collect();
    Ok(Json(payload))
}
