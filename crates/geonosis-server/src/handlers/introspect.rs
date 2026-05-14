//! `/realms/{slug}/protocol/openid-connect/introspect` (RFC 7662).
//!
//! Authenticates the calling client (basic / post / none) and returns
//! the standard introspection response. For unknown / expired tokens
//! we return `{"active": false}` per RFC 7662 §2.2.

use std::collections::BTreeMap;

use axum::extract::{Form, Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;

use geonosis_protocol_oidc::{build_introspection, IntrospectionResponse};

use crate::handlers::client_auth::authenticate_client;
use crate::handlers::error::oauth_error_response;
use crate::state::AppState;
use crate::token_verify::verify_access_token;

pub async fn introspect(
    Path(slug): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> Response {
    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        Err(_) => return Json(IntrospectionResponse::inactive()).into_response(),
    };
    if let Err(e) = authenticate_client(&state, realm.id, &headers, &form).await {
        return oauth_error_response(&e);
    }
    let token = match form.get("token") {
        Some(t) => t,
        None => return Json(IntrospectionResponse::inactive()).into_response(),
    };
    // RFC 7662 allows a `token_type_hint`; we ignore it (try as access token).
    match verify_access_token(&state, &realm, token).await {
        Ok(claims) => {
            let username = if let Ok(uid) = claims.sub.parse::<geonosis_core::UserId>() {
                state.storage.get_user(realm.id, uid).await.ok().map(|u| u.username)
            } else {
                None
            };
            Json(build_introspection(&claims, username)).into_response()
        }
        Err(_) => Json(IntrospectionResponse::inactive()).into_response(),
    }
}
