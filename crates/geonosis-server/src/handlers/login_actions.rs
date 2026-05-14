//! `/realms/{slug}/login-actions/authenticate` — accepts the form
//! submission from the rendered login page (see `authorize.rs`),
//! validates credentials, mints the authorization code, redirects.

use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{Duration as ChronoDuration, Utc};

use geonosis_core::token::{CodeChallenge, CodeChallengeMethod, CodeGrant};
use geonosis_core::{AuthnLevel, CodeId, ScopeName, Session, SessionId};
use geonosis_core::scope::parse_scope_string;

use crate::state::AppState;

#[derive(serde::Deserialize)]
pub struct AuthForm {
    pub flow_state_id: String,
    pub username: String,
    pub password: String,
}

/// `POST /realms/{slug}/login-actions/authenticate`
pub async fn authenticate_post(
    Path(slug): Path<String>,
    State(state): State<AppState>,
    Form(form): Form<AuthForm>,
) -> Response {
    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };

    let flow_state_id: geonosis_core::FlowStateId = match form.flow_state_id.parse() {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid flow_state_id").into_response(),
    };
    let row = match state.storage.get_flow_state(&flow_state_id).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::BAD_REQUEST, "unknown / expired flow state").into_response(),
    };
    if row.state.expires_at < Utc::now() {
        let _ = state.storage.delete_flow_state(&flow_state_id).await;
        return (StatusCode::BAD_REQUEST, "flow state expired").into_response();
    }
    if row.state.realm_id != realm.id {
        return (StatusCode::BAD_REQUEST, "realm mismatch").into_response();
    }

    // Lookup user + verify password.
    let user = match state
        .storage
        .get_user_by_username(realm.id, &form.username)
        .await
    {
        Ok(u) if u.enabled => u,
        _ => return (StatusCode::UNAUTHORIZED, "invalid username or password").into_response(),
    };
    let phc = match state
        .storage
        .get_password_hash(realm.id, user.id)
        .await
    {
        Ok(h) => h,
        Err(_) => return (StatusCode::UNAUTHORIZED, "invalid username or password").into_response(),
    };
    let ok = geonosis_crypto::verify_password(&form.password, &phc).unwrap_or(false);
    if !ok {
        return (StatusCode::UNAUTHORIZED, "invalid username or password").into_response();
    }

    // Mint a fresh session.
    let session_id = SessionId::new_random();
    let now = Utc::now();
    let session = Session {
        id: session_id.clone(),
        realm_id: realm.id,
        user_id: user.id,
        authn_level: AuthnLevel::Single,
        idp_alias: None,
        started_at: now,
        last_seen_at: now,
        expires_at: now + ChronoDuration::from_std(realm.session_policy.sso_session_max).unwrap_or_default(),
        clients: vec![],
    };
    if let Err(e) = state.storage.create_session(session).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("session create failed: {e}"),
        )
            .into_response();
    }

    // Build CodeGrant from captured authorize params.
    let p = &row.authorize_params;
    let client_id = match p.get("client_id") {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "missing client_id in flow state").into_response(),
    };
    let client = match state
        .storage
        .get_client_by_client_id(realm.id, client_id)
        .await
    {
        Ok(c) => c,
        Err(_) => return (StatusCode::BAD_REQUEST, "unknown client").into_response(),
    };
    let redirect_uri = p
        .get("redirect_uri")
        .and_then(|s| url::Url::parse(s).ok());
    let redirect_uri = match redirect_uri {
        Some(u) => u,
        None => return (StatusCode::BAD_REQUEST, "missing/invalid redirect_uri in flow state").into_response(),
    };
    let scope: Vec<ScopeName> = parse_scope_string(p.get("scope").map(String::as_str).unwrap_or(""))
        .unwrap_or_default();
    let code_challenge = match p.get("code_challenge") {
        Some(c) => Some(CodeChallenge {
            method: CodeChallengeMethod::S256,
            challenge: c.clone(),
        }),
        None => None,
    };

    let code = CodeId::new_random();
    let auth_code_lifetime = ChronoDuration::from_std(realm.token_policy.auth_code_lifespan)
        .unwrap_or_else(|_| ChronoDuration::seconds(60));
    let grant = CodeGrant {
        code: code.clone(),
        realm_id: realm.id,
        client_id: client.id,
        user_id: user.id,
        session_id: session_id.clone(),
        scope,
        redirect_uri: redirect_uri.clone(),
        code_challenge,
        nonce: p.get("nonce").cloned(),
        state: p.get("state").cloned(),
        amr: vec![geonosis_core::Amr::Pwd],
        auth_time: now,
        created_at: now,
        expires_at: now + auth_code_lifetime,
    };
    if let Err(e) = state.storage.save_code_grant(grant).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("code save failed: {e}"),
        )
            .into_response();
    }

    // Drop the flow state — single-use.
    let _ = state.storage.delete_flow_state(&flow_state_id).await;

    // 302 back to client with code + state.
    let mut url = redirect_uri;
    url.query_pairs_mut().append_pair("code", code.0.as_str());
    if let Some(s) = p.get("state") {
        url.query_pairs_mut().append_pair("state", s);
    }
    Redirect::to(url.as_str()).into_response()
}
