//! Admin authentication middleware.
//!
//! Protects `/admin/...` routes with bearer token or session cookie
//! auth. API consumers send `Authorization: Bearer <jwt>`; the HTML
//! admin UI uses a `geonosis_admin_sid` cookie set at login.
//!
//! Per `docs/08-admin-ui.md` §"Authentication": the admin surface
//! uses the same OAuth 2.1 token path as application clients. v0.1
//! implements cookie-based session auth for the HTML UI and bearer
//! token verification for the REST API.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};

use geonosis_core::id::{RealmId, SessionId, UserId};
use geonosis_crypto::base64url;
use geonosis_crypto::jwt::{verify_jwt, JwsHeader};
use geonosis_crypto::KeyManagementService;
use subtle::ConstantTimeEq;

use crate::state::AdminState;

/// Identity of the authenticated admin user, inserted into request
/// extensions by the `require_admin` middleware.
#[derive(Debug, Clone)]
pub struct AdminPrincipal {
    pub user_id: UserId,
    pub username: String,
    pub realm_id: RealmId,
}

pub const COOKIE_NAME: &str = "geonosis_admin_sid";

/// Extract the admin session cookie value from headers (used by logout).
pub fn cookie_value_from(headers: &HeaderMap) -> Option<String> {
    cookie_value(headers, COOKIE_NAME)
}

/// Axum middleware that enforces admin authentication.
pub async fn require_admin(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    // 0. Try static admin API key (CI / CLI headless access).
    if let Some(ref expected) = state.admin_api_key {
        if let Some(provided) = headers.get("x-admin-key").and_then(|v| v.to_str().ok()) {
            if provided.len() == expected.len()
                && provided.as_bytes().ct_eq(expected.as_bytes()).into()
            {
                return next.run(req).await;
            }
        }
    }

    // 1. Try bearer token (API clients).
    if let Some(token) = bearer_from(&headers) {
        match verify_bearer(&state, &token).await {
            Ok(principal) => {
                req.extensions_mut().insert(principal);
                return next.run(req).await;
            }
            Err(msg) => {
                if wants_html(&headers) {
                    return Redirect::to("/admin/login").into_response();
                }
                return (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"")],
                    msg,
                )
                    .into_response();
            }
        }
    }

    // 2. Try session cookie (HTML UI).
    if let Some(sid) = cookie_value(&headers, COOKIE_NAME) {
        match verify_session(&state, &sid).await {
            Ok(principal) => {
                req.extensions_mut().insert(principal);
                return next.run(req).await;
            }
            Err(_) => {
                // Stale/invalid cookie — redirect to login.
            }
        }
    }

    // 3. No valid auth — redirect HTML, 401 API.
    if wants_html(&headers) {
        Redirect::to("/admin/login").into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "authentication required",
        )
            .into_response()
    }
}

/// Extract `Bearer <token>` from the Authorization header.
fn bearer_from(headers: &HeaderMap) -> Option<String> {
    let val = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = val.strip_prefix("Bearer ")?.to_string();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// Extract a named cookie value from the Cookie header.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in cookies.split(';') {
        let pair = pair.trim();
        if let Some(val) = pair.strip_prefix(name) {
            let val = val.strip_prefix('=')?;
            return Some(val.to_string());
        }
    }
    None
}

/// Check if the client prefers HTML (browser) over JSON (API).
fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("text/html"))
        .unwrap_or(true) // Default to HTML for browsers that don't send Accept
}

/// Verify a bearer JWT against the realm's signing keys.
async fn verify_bearer(state: &AdminState, token: &str) -> Result<AdminPrincipal, String> {
    // Parse JWT header to get kid + alg.
    let mut parts = token.split('.');
    let h_b64 = parts.next().ok_or("malformed jwt")?;
    let _ = parts.next().ok_or("malformed jwt")?;
    let _ = parts.next().ok_or("malformed jwt")?;

    let header_bytes = base64url::decode(h_b64).map_err(|e| e.to_string())?;
    let header: JwsHeader = serde_json::from_slice(&header_bytes).map_err(|e| e.to_string())?;

    let kid: geonosis_core::KeyId = header.kid.parse().map_err(|_| "bad kid".to_string())?;
    let alg = match header.alg.as_str() {
        "RS256" => geonosis_core::JwsAlgorithm::RS256,
        "ES256" => geonosis_core::JwsAlgorithm::ES256,
        "EdDSA" => geonosis_core::JwsAlgorithm::EdDSA,
        other => return Err(format!("unsupported alg: {other}")),
    };

    let public = state
        .kms
        .load_public(&kid)
        .await
        .map_err(|e| e.to_string())?;

    let claims: geonosis_core::AccessTokenClaims =
        verify_jwt(token, alg, &header.kid, &public).map_err(|e| e.to_string())?;

    // Check expiration.
    let now = chrono::Utc::now().timestamp();
    if claims.exp < now {
        return Err("token expired".into());
    }

    // Check admin role in realm_access.
    let is_admin = claims
        .realm_access
        .as_ref()
        .map(|ra| ra.roles.iter().any(|r| r == "admin"))
        .unwrap_or(false);
    if !is_admin {
        return Err("admin role required".into());
    }

    // Parse sub as UserId.
    let user_id: UserId = claims.sub.parse().map_err(|_| "bad sub")?;

    // Resolve realm from issuer.
    let realm_slug = claims.iss.rsplit('/').next().ok_or("bad issuer")?;
    let realm = state
        .storage
        .get_realm_by_slug(realm_slug)
        .await
        .map_err(|_| "unknown realm")?;

    // Load user to get username.
    let user = state
        .storage
        .get_user(realm.id, user_id)
        .await
        .map_err(|_| "user not found")?;

    Ok(AdminPrincipal {
        user_id,
        username: user.username,
        realm_id: realm.id,
    })
}

/// Verify a session cookie against stored sessions.
async fn verify_session(state: &AdminState, sid: &str) -> Result<AdminPrincipal, String> {
    let session_id = SessionId(sid.to_string());
    let session = state
        .storage
        .get_session(&session_id)
        .await
        .map_err(|_| "session not found")?;

    // Check expiration.
    if session.expires_at < chrono::Utc::now() {
        let _ = state.storage.delete_session(&session_id).await;
        return Err("session expired".into());
    }

    // Load user to get username and check admin attribute.
    let user = state
        .storage
        .get_user(session.realm_id, session.user_id)
        .await
        .map_err(|_| "user not found")?;

    let is_admin = matches!(
        user.attributes.get("admin"),
        Some(geonosis_core::attribute::AttributeValue::Bool(true))
    );
    if !is_admin {
        return Err("admin role required".into());
    }

    Ok(AdminPrincipal {
        user_id: session.user_id,
        username: user.username,
        realm_id: session.realm_id,
    })
}
