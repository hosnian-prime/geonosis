//! `/admin/v1/realms` — realm CRUD.
//!
//! Fills the gap the legacy `handlers::api_realms_*` endpoints left:
//! the old surface was list+get only, so CLI / admin tooling that
//! needed `create / update / delete` fell back to direct Postgres.
//! v0.1 closes that gap so every entity-management path goes through
//! one authenticated admin REST surface.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::Json;
use serde::Deserialize;

use geonosis_audit::Target;
use geonosis_core::id::RealmId;
use geonosis_core::Realm;

use crate::audit_emit;
use crate::state::{AdminError, AdminState};

#[derive(Debug, Deserialize)]
pub struct CreateRealmRequest {
    pub slug: String,
    pub display_name: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

pub async fn list(
    State(state): State<Arc<AdminState>>,
) -> Result<Json<Vec<Realm>>, AdminError> {
    state
        .storage
        .list_realms()
        .await
        .map(Json)
        .map_err(AdminError::from)
}

pub async fn create(
    State(state): State<Arc<AdminState>>,
    Json(req): Json<CreateRealmRequest>,
) -> Result<Json<Realm>, AdminError> {
    let now = chrono::Utc::now();
    let mut realm = Realm {
        id: RealmId::new(),
        slug: req.slug,
        display_name: req.display_name,
        enabled: req.enabled,
        frontend_url: None,
        admin_frontend_url: None,
        ssl_required: geonosis_core::SslRequirement::ExternalRequests,
        login: Default::default(),
        registration: Default::default(),
        session_policy: Default::default(),
        token_policy: Default::default(),
        brute_force: Default::default(),
        password_policy: Default::default(),
        otp_policy: Default::default(),
        webauthn_policy: Default::default(),
        acr_policy: Default::default(),
        sender_constraint_default: geonosis_core::SenderConstraint::None,
        theme_binding: Default::default(),
        localization: Default::default(),
        events: Default::default(),
        default_groups: vec![],
        default_roles: Default::default(),
        organizations_enabled: true,
        created_at: now,
        updated_at: now,
    };
    // Touch the binding fields realm policy implies — verify_email is
    // realm-level boolean v0.1.x will surface; here we only ensure the
    // serializable default is set so the realm is round-trippable.
    realm.created_at = now;
    state
        .storage
        .create_realm(realm.clone())
        .await
        .map_err(AdminError::from)?;
    // Seed the v0.1 built-in flows (browser, direct-grant, etc.) so
    // the realm can actually serve `/authorize` immediately. Without
    // this the next interactive login attempt 500s with "realm has no
    // browser flow"; see `docs/06-auth-flows.md` §"Built-in flows".
    geonosis_storage::seed_default_flows(state.storage.as_ref(), realm.id)
        .await
        .map_err(AdminError::from)?;
    audit_emit::emit(
        &state,
        realm.id,
        "realm.created",
        Some(Target::Realm { id: realm.id }),
        serde_json::json!({ "slug": realm.slug }),
    );
    Ok(Json(realm))
}

pub async fn get(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Json<Realm>, AdminError> {
    state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map(Json)
        .map_err(AdminError::from)
}

pub async fn update(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    Json(mut realm): Json<Realm>,
) -> Result<Json<Realm>, AdminError> {
    let existing = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(AdminError::from)?;
    // Identity stays canonical from the existing row; payload mutates
    // everything else. Slug rename intentionally NOT allowed via
    // PATCH — operators must export + import to change a slug since
    // it propagates to token issuers and external IdP redirect URIs.
    realm.id = existing.id;
    realm.slug = existing.slug;
    realm.created_at = existing.created_at;
    realm.updated_at = chrono::Utc::now();
    state
        .storage
        .update_realm(realm.clone())
        .await
        .map_err(AdminError::from)?;
    audit_emit::emit(
        &state,
        realm.id,
        "realm.updated",
        Some(Target::Realm { id: realm.id }),
        serde_json::json!({ "slug": realm.slug }),
    );
    Ok(Json(realm))
}

pub async fn delete_(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<axum::http::StatusCode, AdminError> {
    let existing = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(AdminError::from)?;
    state
        .storage
        .delete_realm(existing.id)
        .await
        .map_err(AdminError::from)?;
    audit_emit::emit(
        &state,
        existing.id,
        "realm.deleted",
        Some(Target::Realm { id: existing.id }),
        serde_json::json!({ "slug": existing.slug }),
    );
    Ok(axum::http::StatusCode::NO_CONTENT)
}
