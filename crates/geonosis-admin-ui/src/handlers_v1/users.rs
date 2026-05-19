//! `/admin/v1/realms/:slug/users` — user CRUD + admin credential ops.
//!
//! Per `docs/02-data-model.md` and `docs/21-dx-package.md`, the CLI
//! recipes lean heavily on the user surface — `verify-email`,
//! `credential-set`, etc. v0.1 routes them all through this module so
//! every user-management op emits a unified audit trail.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::Deserialize;

use geonosis_audit::Target;
use geonosis_core::id::UserId;
use geonosis_core::{PersonName, User};

use crate::audit_emit;

use crate::handlers_v1::extractors::realm_by_slug;
use crate::state::{AdminError, AdminState};

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    /// Cap on the number of rows returned. v0.1 returns the first N
    /// rows in insertion order; pagination cursor lands in v0.1.x
    /// with the typed `(offset, limit, sort)` signature.
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub name: Option<PersonName>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct SetPasswordRequest {
    pub password: String,
}

pub async fn list(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Query(q): Query<ListUsersQuery>,
) -> Result<Json<Vec<User>>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    state
        .storage
        .list_users(realm.id, q.limit)
        .await
        .map(Json)
        .map_err(AdminError::from)
}

pub async fn create(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<User>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let now = chrono::Utc::now();
    let user = User {
        id: UserId::new(),
        realm_id: realm.id,
        username: req.username,
        email: req.email,
        email_verified: req.email_verified,
        name: req.name,
        credentials: vec![],
        federation: None,
        attributes: Default::default(),
        required_actions: vec![],
        required_flow: None,
        organizations: vec![],
        enabled: req.enabled,
        failed_attempts: 0,
        locked_until: None,
        last_failed_at: None,
        created_at: now,
        updated_at: now,
    };
    // Validate user attributes against the realm's profile schema.
    if let Ok(profile) = state.storage.get_user_profile_schema(realm.id).await {
        let violations = profile.validate_attributes(&user.attributes);
        if !violations.is_empty() {
            let msgs: Vec<String> = violations
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect();
            return Err(AdminError::Storage(format!(
                "profile validation failed: {}",
                msgs.join(", ")
            )));
        }
    }
    state
        .storage
        .create_user(user.clone())
        .await
        .map_err(AdminError::from)?;
    audit_emit::emit(
        &state,
        user.realm_id,
        "user.created",
        Some(Target::User { id: user.id }),
        serde_json::json!({ "username": user.username }),
    );
    Ok(Json(user))
}

pub async fn get(
    State(state): State<Arc<AdminState>>,
    Path((slug, username)): Path<(String, String)>,
) -> Result<Json<User>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    state
        .storage
        .get_user_by_username(realm.id, &username)
        .await
        .map(Json)
        .map_err(AdminError::from)
}

pub async fn update(
    State(state): State<Arc<AdminState>>,
    Path((slug, username)): Path<(String, String)>,
    Json(mut user): Json<User>,
) -> Result<Json<User>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let existing = state
        .storage
        .get_user_by_username(realm.id, &username)
        .await
        .map_err(AdminError::from)?;
    // Identity + creation timestamp + username stay canonical. v0.1
    // rejects username rename through PATCH because federation links
    // and tokens carry it; v0.2 will add `geoctl users rename`.
    user.id = existing.id;
    user.realm_id = realm.id;
    user.username = existing.username;
    user.created_at = existing.created_at;
    user.updated_at = chrono::Utc::now();
    if let Ok(profile) = state.storage.get_user_profile_schema(realm.id).await {
        let violations = profile.validate_attributes(&user.attributes);
        if !violations.is_empty() {
            let msgs: Vec<String> = violations
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect();
            return Err(AdminError::Storage(format!(
                "profile validation failed: {}",
                msgs.join(", ")
            )));
        }
    }
    state
        .storage
        .update_user(user.clone())
        .await
        .map_err(AdminError::from)?;
    audit_emit::emit(
        &state,
        user.realm_id,
        "user.updated",
        Some(Target::User { id: user.id }),
        serde_json::json!({ "username": user.username }),
    );
    Ok(Json(user))
}

pub async fn delete_(
    State(state): State<Arc<AdminState>>,
    Path((slug, username)): Path<(String, String)>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let existing = state
        .storage
        .get_user_by_username(realm.id, &username)
        .await
        .map_err(AdminError::from)?;
    state
        .storage
        .delete_user(realm.id, existing.id)
        .await
        .map_err(AdminError::from)?;
    audit_emit::emit(
        &state,
        realm.id,
        "user.deleted",
        Some(Target::User { id: existing.id }),
        serde_json::json!({ "username": existing.username }),
    );
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Mark the user's email as verified. Used by `geoctl users verify-email`
/// after an admin out-of-band confirms the address.
pub async fn verify_email(
    State(state): State<Arc<AdminState>>,
    Path((slug, username)): Path<(String, String)>,
) -> Result<Json<User>, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let mut user = state
        .storage
        .get_user_by_username(realm.id, &username)
        .await
        .map_err(AdminError::from)?;
    user.email_verified = true;
    user.updated_at = chrono::Utc::now();
    state
        .storage
        .update_user(user.clone())
        .await
        .map_err(AdminError::from)?;
    audit_emit::emit(
        &state,
        user.realm_id,
        "user.email_verified",
        Some(Target::User { id: user.id }),
        serde_json::json!({ "username": user.username }),
    );
    Ok(Json(user))
}

/// Set a new password on the user. Argon2id hash is computed inside
/// the handler; the plaintext never leaves this function's stack.
/// CLI calls this for `geoctl users credential-set --kind password`.
pub async fn set_password(
    State(state): State<Arc<AdminState>>,
    Path((slug, username)): Path<(String, String)>,
    Json(req): Json<SetPasswordRequest>,
) -> Result<axum::http::StatusCode, AdminError> {
    let realm = realm_by_slug(&state, &slug).await?;
    let user = state
        .storage
        .get_user_by_username(realm.id, &username)
        .await
        .map_err(AdminError::from)?;
    // Enforce the realm's password policy BEFORE the Argon2id hash
    // is computed — the hash is expensive, and the violation is
    // user-correctable so we fail fast. Per `docs/02-data-model.md`
    // §"Password policy".
    let report =
        realm
            .password_policy
            .validate(&req.password, &user.username, user.email.as_deref());
    if !report.is_ok() {
        return Err(AdminError::PasswordPolicy(report.violations));
    }
    let phc = geonosis_crypto::hash_password(&req.password)
        .map_err(|e| AdminError::Storage(format!("hash_password: {e}")))?;
    state
        .storage
        .store_password_hash(realm.id, user.id, phc)
        .await
        .map_err(AdminError::from)?;
    audit_emit::emit(
        &state,
        realm.id,
        "user.password_set",
        Some(Target::User { id: user.id }),
        serde_json::json!({ "username": user.username }),
    );
    Ok(axum::http::StatusCode::NO_CONTENT)
}
