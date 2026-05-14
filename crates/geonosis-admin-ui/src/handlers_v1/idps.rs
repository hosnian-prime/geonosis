//! `/admin/v1/realms/:slug/idps` — Identity Provider (broker) admin.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;

use geonosis_broker::{IdentityProvider, IdpConfig, IdpKind};
use geonosis_core::id::IdpId;

use crate::handlers_v1::extractors::realm_by_slug;
use crate::state::{AdminError, AdminState};

#[derive(Debug, Deserialize)]
pub struct CreateIdpRequest {
    pub alias: String,
    pub display_name: String,
    pub kind: IdpKind,
    pub config: IdpConfig,
    #[serde(default = "default_first_login")]
    pub first_login_flow_alias: String,
    #[serde(default)]
    pub post_login_flow_alias: Option<String>,
    #[serde(default)]
    pub link_only: bool,
    #[serde(default)]
    pub adapter_urn: Option<String>,
}

fn default_first_login() -> String {
    "first-broker-login".into()
}

pub async fn list(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Json<Vec<IdentityProvider>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let idps = state
        .storage
        .list_idps(realm.id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(idps))
}

pub async fn create(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Json(req): Json<CreateIdpRequest>,
) -> Result<Json<IdentityProvider>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let idp = IdentityProvider {
        id: IdpId::new(),
        realm_id: realm.id,
        alias: req.alias,
        display_name: req.display_name,
        kind: req.kind,
        config: req.config,
        first_login_flow_alias: req.first_login_flow_alias,
        post_login_flow_alias: req.post_login_flow_alias,
        link_only: req.link_only,
        adapter_urn: req.adapter_urn,
        enabled: true,
    };
    state
        .storage
        .create_idp(idp.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(idp))
}

pub async fn get(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
) -> Result<Json<IdentityProvider>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let idp = state
        .storage
        .get_idp_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(idp))
}

pub async fn update(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
    Json(mut idp): Json<IdentityProvider>,
) -> Result<Json<IdentityProvider>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let existing = state
        .storage
        .get_idp_by_alias(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    // Preserve identity + alias from the existing row; payload mutates
    // everything else.
    idp.id = existing.id;
    idp.realm_id = realm.id;
    idp.alias = existing.alias;
    // create_idp is an upsert at the storage layer for the memory
    // backend; postgres impl follows the same contract.
    state
        .storage
        .create_idp(idp.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(idp))
}

pub async fn delete_(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    state
        .storage
        .delete_idp(realm.id, &alias)
        .await
        .map_err(AdminError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
