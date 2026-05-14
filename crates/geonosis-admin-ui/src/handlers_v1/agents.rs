//! `/admin/v1/realms/:slug/agents` — AI / M2M identity admin.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;

use geonosis_audit::Target;
use geonosis_core::id::AgentId;
use geonosis_core::{
    Agent, AgentAuthMethod, AgentCapability, AgentKind, AgentRateLimit, ParentSubject, ScopeName,
};

use crate::audit_emit;
use crate::handlers_v1::extractors::realm_by_slug;
use crate::state::{AdminError, AdminState};

#[derive(Debug, Deserialize)]
pub struct CreateAgentRequest {
    pub alias: String,
    pub display_name: String,
    pub kind: AgentKind,
    pub parent_subject: ParentSubject,
    #[serde(default)]
    pub model_hint: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<AgentCapability>,
    #[serde(default)]
    pub allowed_scopes: Vec<ScopeName>,
    #[serde(default)]
    pub allowed_audiences: Vec<String>,
    #[serde(default)]
    pub rate_limit: AgentRateLimit,
    pub auth_method: AgentAuthMethod,
    #[serde(default)]
    pub public_jwk: Option<serde_json::Value>,
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn list(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Json<Vec<Agent>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let agents = state
        .storage
        .list_agents(realm.id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(agents))
}

pub async fn create(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Json(req): Json<CreateAgentRequest>,
) -> Result<Json<Agent>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let agent = Agent {
        id: AgentId::new(),
        realm_id: realm.id,
        alias: req.alias,
        display_name: req.display_name,
        kind: req.kind,
        model_hint: req.model_hint,
        vendor: req.vendor,
        version: req.version,
        parent_subject: req.parent_subject,
        capabilities: req.capabilities,
        allowed_scopes: req.allowed_scopes,
        allowed_audiences: req.allowed_audiences,
        rate_limit: req.rate_limit,
        auth_method: req.auth_method,
        public_jwk: req.public_jwk,
        created_at: chrono::Utc::now(),
        expires_at: req.expires_at,
        revoked_at: None,
        enabled: true,
    };
    state
        .storage
        .create_agent(agent.clone())
        .await
        .map_err(AdminError::from)?;
    audit_emit::emit(
        &state,
        agent.realm_id,
        "agent.created",
        Some(Target::Other {
            entity: "agent".into(),
            id: agent.id.to_string(),
        }),
        serde_json::json!({ "alias": agent.alias, "kind": format!("{:?}", agent.kind) }),
    );
    Ok(Json(agent))
}

pub async fn get(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
) -> Result<Json<Agent>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let agent = state
        .storage
        .get_agent_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(agent))
}

pub async fn update(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    Json(mut agent): Json<Agent>,
) -> Result<Json<Agent>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let existing = state
        .storage
        .get_agent_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    // Per doc §18: parent_subject is immutable after creation. Force
    // the incoming payload back to the existing parent to make the
    // contract explicit at the handler layer.
    agent.id = existing.id;
    agent.realm_id = realm.id;
    agent.parent_subject = existing.parent_subject;
    agent.created_at = existing.created_at;
    state
        .storage
        .update_agent(agent.clone())
        .await
        .map_err(AdminError::from)?;
    audit_emit::emit(
        &state,
        agent.realm_id,
        "agent.updated",
        Some(Target::Other {
            entity: "agent".into(),
            id: agent.id.to_string(),
        }),
        serde_json::json!({ "alias": agent.alias }),
    );
    Ok(Json(agent))
}

pub async fn revoke(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let existing = state
        .storage
        .get_agent_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    state
        .storage
        .revoke_agent(realm.id, existing.id)
        .await
        .map_err(AdminError::from)?;
    audit_emit::emit(
        &state,
        realm.id,
        "agent.revoked",
        Some(Target::Other {
            entity: "agent".into(),
            id: existing.id.to_string(),
        }),
        serde_json::json!({ "alias": existing.alias }),
    );
    Ok(axum::http::StatusCode::NO_CONTENT)
}
