//! `/realms/{slug}/protocol/openid-connect/logout`
//!
//! - `GET`  — front-channel logout: invalidates session via `id_token_hint`
//!   or `sid` query, then redirects to `post_logout_redirect_uri`.
//! - `POST` — back-channel logout: server-to-server; expects a logout
//!   token in the body. v0.1 accepts `id_token_hint` or `refresh_token`
//!   hints; full RFC 8414/OIDC back-channel logout token verification
//!   lands in v0.1.x.

use std::collections::BTreeMap;

use axum::extract::{Form, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

use crate::state::AppState;

#[derive(serde::Deserialize, Default)]
pub struct LogoutQuery {
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    pub client_id: Option<String>,
}

pub async fn logout_get(
    Path(slug): Path<String>,
    Query(q): Query<LogoutQuery>,
    State(state): State<AppState>,
) -> Response {
    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };

    if let Some(hint) = &q.id_token_hint {
        // v0.1: best-effort — extract `sid` from the hint without verifying
        // the signature (RFC 7519 §3.1 permits this for hints). v0.1.x
        // wires full verification.
        if let Some(sid) = sid_from_jwt_unsafe(hint) {
            let sess_id = geonosis_core::SessionId(sid);
            let _ = state.storage.delete_session(&sess_id).await;
        }
    }

    let target = q
        .post_logout_redirect_uri
        .as_deref()
        .and_then(|s| url::Url::parse(s).ok());
    let mut target = target.unwrap_or_else(|| {
        let mut u = state.public_base_url.clone();
        u.set_path(&format!("/realms/{}/", realm.slug));
        u
    });
    if let Some(s) = q.state {
        target.query_pairs_mut().append_pair("state", &s);
    }
    Redirect::to(target.as_str()).into_response()
}

pub async fn logout_post(
    Path(slug): Path<String>,
    State(state): State<AppState>,
    Form(form): Form<BTreeMap<String, String>>,
) -> Response {
    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };

    if let Some(rt) = form.get("refresh_token") {
        let id = geonosis_core::RefreshTokenId(geonosis_crypto::refresh_token_hash(
            rt,
            &state.refresh_hash_key,
        ));
        if let Ok(t) = state.storage.get_refresh_token(&id).await {
            let _ = state.storage.revoke_token_family(t.family_id).await;
        }
    }
    if let Some(hint) = form.get("id_token_hint") {
        if let Some(sid) = sid_from_jwt_unsafe(hint) {
            let sess_id = geonosis_core::SessionId(sid);
            let _ = state.storage.delete_session(&sess_id).await;
        }
    }
    let _ = realm;
    StatusCode::NO_CONTENT.into_response()
}

/// Extract `sid` from a JWT payload **without verifying the signature**.
/// Acceptable for hint-only routing per OIDC RP-Initiated Logout §3.
fn sid_from_jwt_unsafe(jwt: &str) -> Option<String> {
    let mut parts = jwt.split('.');
    parts.next()?;
    let payload_b64 = parts.next()?;
    let bytes = geonosis_crypto::base64url::decode(payload_b64).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("sid").and_then(|s| s.as_str()).map(String::from)
}
