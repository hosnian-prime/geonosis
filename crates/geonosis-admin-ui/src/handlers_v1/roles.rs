//! `/admin/v1/realms/:slug/roles` and user-role assignments.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;

use geonosis_audit::Target;
use geonosis_core::{Role, RoleId, UserId};

use crate::audit_emit;
use crate::handlers_v1::extractors::realm_by_slug;
use crate::state::{AdminError, AdminState};

#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub client_id: Option<geonosis_core::ClientId>,
}

pub async fn list(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Json<Vec<Role>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let roles = state
        .storage
        .list_roles(realm.id, None)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(roles))
}

pub async fn create(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Json(req): Json<CreateRoleRequest>,
) -> Result<Json<Role>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let now = chrono::Utc::now();
    let role = Role {
        id: RoleId::new(),
        realm_id: realm.id,
        client_id: req.client_id,
        name: req.name,
        description: req.description,
        composites: Default::default(),
        attributes: BTreeMap::new(),
        created_at: now,
        updated_at: now,
    };
    state
        .storage
        .create_role(role.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(role))
}

pub async fn get(
    State(state): State<Arc<AdminState>>,
    Path((slug, name)): Path<(String, String)>,
) -> Result<Json<Role>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let role = state
        .storage
        .get_role_by_name(realm.id, None, &name)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(role))
}

pub async fn update(
    State(state): State<Arc<AdminState>>,
    Path((slug, name)): Path<(String, String)>,
    Json(mut role): Json<Role>,
) -> Result<Json<Role>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let existing = state
        .storage
        .get_role_by_name(realm.id, None, &name)
        .await
        .map_err(AdminError::from)?;
    // Identity stays canonical from the existing row; payload may
    // mutate everything else.
    role.id = existing.id;
    role.realm_id = realm.id;
    role.updated_at = chrono::Utc::now();
    state
        .storage
        .update_role(role.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(role))
}

pub async fn delete_(
    State(state): State<Arc<AdminState>>,
    Path((slug, name)): Path<(String, String)>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let role = state
        .storage
        .get_role_by_name(realm.id, None, &name)
        .await
        .map_err(AdminError::from)?;
    state
        .storage
        .delete_role(realm.id, role.id)
        .await
        .map_err(AdminError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct AssignRoleRequest {
    pub role_id: RoleId,
}

pub async fn list_user_roles(
    State(state): State<Arc<AdminState>>,
    Path((slug, user_id)): Path<(String, UserId)>,
) -> Result<Json<Vec<Role>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let roles = state
        .storage
        .list_user_roles(realm.id, user_id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(roles))
}

pub async fn assign_user_role(
    State(state): State<Arc<AdminState>>,
    Path((slug, user_id)): Path<(String, UserId)>,
    Json(req): Json<AssignRoleRequest>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    state
        .storage
        .assign_user_role(realm.id, user_id, req.role_id)
        .await
        .map_err(AdminError::from)?;
    audit_emit::emit(
        &state,
        realm.id,
        "role.assigned_to_user",
        Some(Target::User { id: user_id }),
        serde_json::json!({ "role_id": req.role_id.to_string() }),
    );
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn unassign_user_role(
    State(state): State<Arc<AdminState>>,
    Path((slug, user_id, role_id)): Path<(String, UserId, RoleId)>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    state
        .storage
        .unassign_user_role(realm.id, user_id, role_id)
        .await
        .map_err(AdminError::from)?;
    audit_emit::emit(
        &state,
        realm.id,
        "role.unassigned_from_user",
        Some(Target::User { id: user_id }),
        serde_json::json!({ "role_id": role_id.to_string() }),
    );
    Ok(axum::http::StatusCode::NO_CONTENT)
}
