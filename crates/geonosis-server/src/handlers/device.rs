//! `/realms/{slug}/protocol/openid-connect/device/authorize` (RFC 8628 §3.2)
//! and the verification UI page that approves a pending device grant.
//!
//! The polling endpoint `/protocol/openid-connect/device/token` is wired
//! through the standard `/token` handler under
//! `grant_type=urn:ietf:params:oauth:grant-type:device_code`.

use std::collections::BTreeMap;

use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration as ChronoDuration, Utc};

use geonosis_core::scope::parse_scope_string;
use geonosis_protocol_oidc::{
    generate_user_code, DeviceAuthorizationResponse, DEVICE_CODE_DEFAULT_INTERVAL_SECS,
    DEVICE_CODE_DEFAULT_TTL_SECS,
};
use geonosis_storage::{DeviceGrant, DeviceGrantStatus};

use crate::handlers::client_auth::authenticate_client;
use crate::handlers::error::oauth_error_response;
use crate::handlers::oidc_meta::realm_issuer_url;
use crate::state::AppState;

pub async fn device_authorize(
    Path(slug): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> Response {
    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };
    let authed = match authenticate_client(&state, realm.id, &headers, &form).await {
        Ok(a) => a,
        Err(e) => return oauth_error_response(&e),
    };
    if !authed.client.grants.device_code {
        return oauth_error_response(&geonosis_protocol_oauth::OAuthError::unauthorized_client(
            "device_code grant disabled for client",
        ));
    }
    let scope = parse_scope_string(form.get("scope").map(String::as_str).unwrap_or("openid"))
        .unwrap_or_default();

    let device_code = geonosis_crypto::random::random_token();
    let user_code = generate_user_code();
    let now = Utc::now();
    let grant = DeviceGrant {
        device_code: device_code.clone(),
        user_code: user_code.clone(),
        realm_id: realm.id,
        client_id: authed.client.id,
        scope,
        interval_seconds: DEVICE_CODE_DEFAULT_INTERVAL_SECS,
        status: DeviceGrantStatus::Pending,
        user_id: None,
        session_id: None,
        created_at: now,
        expires_at: now + ChronoDuration::seconds(DEVICE_CODE_DEFAULT_TTL_SECS),
        last_polled_at: None,
    };
    if let Err(e) = state.storage.save_device_grant(grant).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    let mut verification_uri = realm_issuer_url(&state.public_base_url, &realm.slug);
    verification_uri.set_path(&format!("/realms/{}/device", realm.slug));
    let mut verification_uri_complete = verification_uri.clone();
    verification_uri_complete
        .query_pairs_mut()
        .append_pair("user_code", &user_code);

    Json(DeviceAuthorizationResponse {
        device_code,
        user_code,
        verification_uri: verification_uri.to_string(),
        verification_uri_complete: verification_uri_complete.to_string(),
        expires_in: DEVICE_CODE_DEFAULT_TTL_SECS,
        interval: DEVICE_CODE_DEFAULT_INTERVAL_SECS,
    })
    .into_response()
}

/// `POST /realms/{slug}/protocol/openid-connect/device/token` —
/// thin alias to the main `/token` handler. Wired through the router.
pub async fn device_token(
    p: Path<String>,
    s: State<AppState>,
    h: HeaderMap,
    f: Form<BTreeMap<String, String>>,
) -> Response {
    crate::handlers::token::token(p, s, h, f).await
}
