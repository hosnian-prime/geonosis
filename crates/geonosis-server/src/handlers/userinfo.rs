//! `/realms/{slug}/protocol/openid-connect/userinfo` (GET + POST).
//!
//! Per OIDC §5.3 — accepts a Bearer access token, returns standard
//! profile/email claims gated by the token's scope.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;

use geonosis_core::scope::parse_scope_string;
use geonosis_protocol_oidc::userinfo_for;

use crate::handlers::client_auth::bearer_from;
use crate::state::AppState;
use crate::token_verify::{verify_access_token, VerifyError};

pub async fn userinfo_get(
    Path(slug): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    handle(slug, state, headers).await
}

pub async fn userinfo_post(
    Path(slug): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    handle(slug, state, headers).await
}

async fn handle(slug: String, state: AppState, headers: HeaderMap) -> Response {
    let bearer = match bearer_from(&headers) {
        Some(b) => b,
        None => return unauthorized("Bearer realm=\"geonosis\", error=\"invalid_token\""),
    };
    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };
    let claims = match verify_access_token(&state, &realm, &bearer).await {
        Ok(c) => c,
        Err(_) => return unauthorized("Bearer error=\"invalid_token\""),
    };

    let scopes = parse_scope_string(&claims.scope).unwrap_or_default();
    let user_id: geonosis_core::UserId = match claims.sub.parse() {
        Ok(id) => id,
        // Service-account / agent tokens have non-ULID `sub` values; the
        // OIDC userinfo endpoint is for user subjects.
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "userinfo only valid for user subjects",
            )
                .into_response()
        }
    };
    let user = match state.storage.get_user(realm.id, user_id).await {
        Ok(u) => u,
        Err(_) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
    };
    Json(userinfo_for(&user, &scopes)).into_response()
}

fn unauthorized(www_authenticate: &'static str) -> Response {
    let mut resp = (StatusCode::UNAUTHORIZED, "").into_response();
    resp.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        axum::http::HeaderValue::from_static(www_authenticate),
    );
    resp
}

// Suppress unused-error warnings until v0.1.x feature flags arrive.
#[allow(dead_code)]
fn _silence(_: VerifyError) {}
