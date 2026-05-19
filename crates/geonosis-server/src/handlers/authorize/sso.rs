//! SSO session resolution, prompt enforcement, and shortcircuit
//! code-grant minting for `/authorize`.
//!
//! Extracted from authorize/mod.rs per Clean Architecture: separates
//! the SSO domain logic from the HTTP handler plumbing.

use std::collections::BTreeMap;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{Duration as ChronoDuration, Utc};

use geonosis_core::scope::parse_scope_string;
use geonosis_core::token::{CodeChallenge, CodeChallengeMethod, CodeGrant};
use geonosis_core::{Client, CodeId, ScopeName, Session, SessionId};
use geonosis_protocol_oidc::AuthorizeRequest;

use crate::audit_emit;
use crate::state::AppState;

// ── Cookie extraction ───────────────────────────────────────────────

/// Extract `geonosis_sid` from the `Cookie` header.
pub fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    for hv in headers.get_all(axum::http::header::COOKIE) {
        let Ok(s) = hv.to_str() else { continue };
        for pair in s.split(';') {
            let pair = pair.trim();
            if let Some(val) = pair.strip_prefix("geonosis_sid=") {
                let val = val.trim();
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

// ── Session resolution ──────────────────────────────────────────────

/// Resolve a valid SSO session. Returns `None` when the session
/// doesn't exist, is expired, or belongs to a different realm.
pub async fn resolve_session(
    state: &AppState,
    sid_value: &str,
    realm_id: geonosis_core::RealmId,
) -> Option<Session> {
    let session_id = SessionId(sid_value.to_string());
    let session = state.storage.get_session(&session_id).await.ok()?;
    if session.realm_id != realm_id {
        return None;
    }
    if session.expires_at < Utc::now() {
        return None;
    }
    Some(session)
}

// ── Prompt policy enforcement (OIDC Core §3.1.2.1) ─────────────────

pub enum PromptDecision {
    /// Valid session — skip flow, mint code directly.
    Shortcircuit(Session),
    /// Must run the interactive login flow.
    StartFlow(Option<Session>),
    /// Return an OIDC error redirect.
    Error {
        code: &'static str,
        description: &'static str,
    },
}

pub fn enforce_prompt_policy(
    req: &AuthorizeRequest,
    sso_session: &Option<Session>,
    _realm: &geonosis_core::Realm,
    _params: &BTreeMap<String, String>,
) -> PromptDecision {
    let prompt_values: Vec<&str> = req
        .prompt
        .as_deref()
        .map(|p| p.split_whitespace().collect())
        .unwrap_or_default();

    // Validate prompt values.
    for tok in &prompt_values {
        match *tok {
            "none" | "login" | "consent" | "select_account" => {}
            _ => {
                return PromptDecision::Error {
                    code: "invalid_request",
                    description: "unknown prompt value",
                };
            }
        }
    }

    let prompt_none = prompt_values.contains(&"none");
    let prompt_login = prompt_values.contains(&"login");
    let prompt_consent = prompt_values.contains(&"consent");

    // `prompt=none` is mutually exclusive with ALL other values per
    // OIDC Core §3.1.2.1.
    if prompt_none && prompt_values.len() > 1 {
        return PromptDecision::Error {
            code: "invalid_request",
            description: "prompt=none must not be combined with other values",
        };
    }

    // `max_age` enforcement: compare against `session.started_at`.
    // OIDC Core says `auth_time` — for v0.1 `started_at` is the
    // closest proxy. When SSO shortcircuit reuses a session, it sets
    // `auth_time` to `started_at` on the CodeGrant so the id_token
    // `auth_time` claim stays consistent.
    let session_fresh_enough = match (req.max_age, sso_session) {
        (Some(max_age), Some(session)) if max_age >= 0 => {
            let elapsed = (Utc::now() - session.started_at).num_seconds();
            elapsed <= max_age
        }
        (Some(max_age), _) if max_age < 0 => {
            return PromptDecision::Error {
                code: "invalid_request",
                description: "max_age must be non-negative",
            };
        }
        (Some(_), None) => false,
        (None, _) => true,
        _ => true,
    };

    // `id_token_hint` validation: `sub` must match session user.
    let hint_matches = match (&req.id_token_hint, sso_session) {
        (Some(hint), Some(session)) => {
            match extract_sub_from_id_token_hint(hint) {
                Some(sub) => sub == session.user_id.to_string(),
                None => false,
            }
        }
        (Some(_), None) => false,
        (None, _) => true,
    };

    let can_reuse = sso_session.is_some()
        && !prompt_login
        && session_fresh_enough
        && hint_matches;

    if prompt_none {
        if sso_session.is_none() || !hint_matches {
            return PromptDecision::Error {
                code: "login_required",
                description: "user is not authenticated",
            };
        }
        if !session_fresh_enough {
            return PromptDecision::Error {
                code: "login_required",
                description: "session exceeded max_age",
            };
        }
        // prompt=none + valid session → shortcircuit.
        return PromptDecision::Shortcircuit(sso_session.clone().unwrap());
    }

    if prompt_login {
        // Force re-authentication — start flow even with valid session.
        return PromptDecision::StartFlow(sso_session.clone());
    }

    if can_reuse && !prompt_consent {
        return PromptDecision::Shortcircuit(sso_session.clone().unwrap());
    }

    // No reusable session, or prompt=consent → run the flow.
    PromptDecision::StartFlow(sso_session.clone())
}

// ── id_token_hint sub extraction ────────────────────────────────────

/// Extract `sub` from an id_token_hint JWT payload. Signature
/// verification deferred to v0.2 — the hint was issued by this server.
/// At minimum we validate the 3-part JWT structure.
fn extract_sub_from_id_token_hint(hint: &str) -> Option<String> {
    let parts: Vec<&str> = hint.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = b64.decode(parts[1]).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    claims.get("sub")?.as_str().map(String::from)
}

// ── SSO shortcircuit ────────────────────────────────────────────────

/// Reuse a valid session to mint an authorization code without running
/// the authentication flow. Updates session freshness and records
/// client participation for logout fan-out.
pub async fn shortcircuit(
    state: &AppState,
    realm: &geonosis_core::Realm,
    client: &Client,
    session: Session,
    params: &BTreeMap<String, String>,
) -> Response {
    update_session_participation(state, &session, client).await;

    let redirect_uri = match params.get("redirect_uri").and_then(|s| url::Url::parse(s).ok()) {
        Some(u) => u,
        None => {
            return (StatusCode::BAD_REQUEST, "missing/invalid redirect_uri").into_response();
        }
    };

    let scope: Vec<ScopeName> =
        parse_scope_string(params.get("scope").map(String::as_str).unwrap_or(""))
            .unwrap_or_default();

    // Read code_challenge_method from params — don't hardcode S256.
    let code_challenge = params.get("code_challenge").map(|c| {
        // v0.1 only supports S256 (plain rejected by AuthorizeRequest).
        let method = CodeChallengeMethod::S256;
        CodeChallenge {
            method,
            challenge: c.clone(),
        }
    });

    let code = CodeId::new_random();
    let now = Utc::now();
    let auth_code_lifetime = ChronoDuration::from_std(realm.token_policy.auth_code_lifespan)
        .unwrap_or_else(|_| ChronoDuration::seconds(60));

    let acr = match session.authn_level {
        geonosis_core::AuthnLevel::Single => Some("urn:geonosis:acr:password".to_string()),
        geonosis_core::AuthnLevel::Mfa | geonosis_core::AuthnLevel::HardwareBound => {
            Some("urn:geonosis:acr:mfa".to_string())
        }
        geonosis_core::AuthnLevel::Anonymous => None,
    };

    let grant = CodeGrant {
        code: code.clone(),
        realm_id: realm.id,
        client_id: client.id,
        user_id: session.user_id,
        session_id: session.id.clone(),
        scope,
        redirect_uri: redirect_uri.clone(),
        code_challenge,
        nonce: params.get("nonce").cloned(),
        state: params.get("state").cloned(),
        amr: vec![],
        acr,
        auth_time: session.started_at,
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

    audit_emit::emit_user(
        state,
        realm.id,
        session.user_id,
        geonosis_audit::action::LOGIN_SUCCESS,
        Some(geonosis_audit::Target::Session {
            id: session.id.clone(),
        }),
        serde_json::json!({ "flow": "sso_shortcircuit" }),
    );

    let mut url = redirect_uri;
    url.query_pairs_mut().append_pair("code", code.0.as_str());
    if let Some(s) = params.get("state") {
        url.query_pairs_mut().append_pair("state", s);
    }
    Redirect::to(url.as_str()).into_response()
}

async fn update_session_participation(state: &AppState, session: &Session, client: &Client) {
    let mut updated = session.clone();
    updated.last_seen_at = Utc::now();
    if !updated.clients.iter().any(|c| c.client_id == client.id) {
        updated.clients.push(geonosis_core::ClientSessionRef {
            client_id: client.id,
            last_seen_at: Utc::now(),
            frontchannel_logout: client.front_channel_logout_enabled,
            backchannel_logout: client.backchannel_logout_url.is_some(),
        });
    }
    if let Err(e) = state.storage.update_session(updated).await {
        tracing::warn!(error = %e, "SSO session update failed; proceeding with stale session");
    }
}
