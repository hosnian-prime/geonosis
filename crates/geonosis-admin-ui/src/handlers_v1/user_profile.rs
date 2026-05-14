//! `/admin/v1/realms/:slug/user-profile` — declarative attribute schema.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;

use geonosis_core::UserProfile;

use crate::handlers_v1::extractors::realm_by_slug;
use crate::state::{AdminError, AdminState};

pub async fn get_schema(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Json<UserProfile>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let profile = state
        .storage
        .get_user_profile_schema(realm.id)
        .await
        .map_err(AdminError::from)?;
    Ok(Json(profile))
}

pub async fn put_schema(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Json(mut profile): Json<UserProfile>,
) -> Result<Json<UserProfile>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    profile.realm_id = realm.id;
    profile.updated_at = chrono::Utc::now();
    state
        .storage
        .save_user_profile_schema(profile.clone())
        .await
        .map_err(AdminError::from)?;
    Ok(Json(profile))
}
