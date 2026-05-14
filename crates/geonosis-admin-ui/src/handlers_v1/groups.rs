//! `/admin/v1/realms/:slug/groups` and group ↔ user/role membership.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;

use geonosis_core::{Group, GroupId, Role, RoleId, UserId};

use crate::handlers_v1::extractors::realm_by_slug;
use crate::state::{AdminError, AdminState};

#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<GroupId>,
}

fn group_path(parent_path: Option<&str>, name: &str) -> String {
    match parent_path {
        Some(p) => format!("{p}/{name}"),
        None => format!("/{name}"),
    }
}

pub async fn list(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Json<Vec<Group>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let groups = state
        .storage
        .list_groups(realm.id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(groups))
}

pub async fn create(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<Group>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let parent_path = if let Some(p) = req.parent_id {
        Some(
            state
                .storage
                .get_group(realm.id, p)
                .await
                .map_err(AdminError::from)?
                .path,
        )
    } else {
        None
    };
    let now = chrono::Utc::now();
    let group = Group {
        id: GroupId::new(),
        realm_id: realm.id,
        parent_id: req.parent_id,
        name: req.name.clone(),
        path: group_path(parent_path.as_deref(), &req.name),
        attributes: BTreeMap::new(),
        realm_role_ids: vec![],
        client_role_ids: BTreeMap::new(),
        created_at: now,
        updated_at: now,
    };
    state
        .storage
        .create_group(group.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(group))
}

pub async fn get(
    State(state): State<Arc<AdminState>>,
    Path((slug, id)): Path<(String, GroupId)>,
) -> Result<Json<Group>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let g = state
        .storage
        .get_group(realm.id, id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(g))
}

pub async fn update(
    State(state): State<Arc<AdminState>>,
    Path((slug, id)): Path<(String, GroupId)>,
    Json(mut group): Json<Group>,
) -> Result<Json<Group>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let existing = state
        .storage
        .get_group(realm.id, id)
        .await
        .map_err(AdminError::from)?;
    group.id = existing.id;
    group.realm_id = realm.id;
    group.path = existing.path; // path stays canonical; rename rebuilds via dedicated endpoint
    group.updated_at = chrono::Utc::now();
    state
        .storage
        .update_group(group.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(group))
}

pub async fn delete_(
    State(state): State<Arc<AdminState>>,
    Path((slug, id)): Path<(String, GroupId)>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    state
        .storage
        .delete_group(realm.id, id)
        .await
        .map_err(AdminError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct AssignGroupRequest {
    pub group_id: GroupId,
}

pub async fn list_user_groups(
    State(state): State<Arc<AdminState>>,
    Path((slug, user_id)): Path<(String, UserId)>,
) -> Result<Json<Vec<Group>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let groups = state
        .storage
        .list_user_groups(realm.id, user_id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(groups))
}

pub async fn assign_user_group(
    State(state): State<Arc<AdminState>>,
    Path((slug, user_id)): Path<(String, UserId)>,
    Json(req): Json<AssignGroupRequest>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    state
        .storage
        .assign_user_group(realm.id, user_id, req.group_id)
        .await
        .map_err(AdminError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn unassign_user_group(
    State(state): State<Arc<AdminState>>,
    Path((slug, user_id, group_id)): Path<(String, UserId, GroupId)>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    state
        .storage
        .unassign_user_group(realm.id, user_id, group_id)
        .await
        .map_err(AdminError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
pub struct AssignGroupRoleRequest {
    pub role_id: RoleId,
}

pub async fn list_group_roles(
    State(state): State<Arc<AdminState>>,
    Path((slug, id)): Path<(String, GroupId)>,
) -> Result<Json<Vec<Role>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let roles = state
        .storage
        .list_group_roles(realm.id, id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(roles))
}

pub async fn assign_group_role(
    State(state): State<Arc<AdminState>>,
    Path((slug, id)): Path<(String, GroupId)>,
    Json(req): Json<AssignGroupRoleRequest>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    state
        .storage
        .assign_group_role(realm.id, id, req.role_id)
        .await
        .map_err(AdminError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn unassign_group_role(
    State(state): State<Arc<AdminState>>,
    Path((slug, id, role_id)): Path<(String, GroupId, RoleId)>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    state
        .storage
        .unassign_group_role(realm.id, id, role_id)
        .await
        .map_err(AdminError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
