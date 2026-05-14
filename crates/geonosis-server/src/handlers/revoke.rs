//! `/realms/{slug}/protocol/openid-connect/revoke` (RFC 7009).
//!
//! Authenticates the calling client, attempts to delete the matching
//! refresh token (and its family for safety) or invalidate the access
//! token's session. Returns `200 OK` whether or not the token existed
//! (RFC 7009 §2.2).

use std::collections::BTreeMap;

use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use geonosis_core::RefreshTokenId;
use geonosis_crypto::refresh_token_hash;

use crate::handlers::client_auth::authenticate_client;
use crate::handlers::error::oauth_error_response;
use crate::state::AppState;

pub async fn revoke(
    Path(slug): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> Response {
    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        // Per RFC 7009 §2.2 we do not reveal token state — but invalid realm
        // is a real client misconfiguration, so we surface it.
        Err(_) => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };
    if let Err(e) = authenticate_client(&state, realm.id, &headers, &form).await {
        return oauth_error_response(&e);
    }

    let token = match form.get("token") {
        Some(t) => t.clone(),
        None => return StatusCode::OK.into_response(),
    };
    // Try as refresh token first (the only token kind we can revoke
    // server-side in v0.1; access-token revocation requires session
    // termination wired through the storage layer).
    let id = RefreshTokenId(refresh_token_hash(&token, &state.refresh_hash_key));
    if let Ok(rt) = state.storage.get_refresh_token(&id).await {
        let _ = state.storage.revoke_token_family(rt.family_id).await;
    }

    // Per RFC 7009: respond 200 regardless.
    StatusCode::OK.into_response()
}
