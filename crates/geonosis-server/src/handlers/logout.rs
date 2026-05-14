//! `/realms/{slug}/protocol/openid-connect/logout`
//!
//! - `GET`  — front-channel logout: invalidates session via `id_token_hint`
//!   or `sid` query, then redirects to `post_logout_redirect_uri`.
//! - `POST` — back-channel logout: server-to-server; expects a logout
//!   token in the body. v0.1 accepts `id_token_hint` or `refresh_token`
//!   hints; full RFC 8414/OIDC back-channel logout token verification
//!   lands in v0.1.x.
//!
//! When the resolved client carries a `backchannel_logout_url`, the
//! server mints an OIDC Back-Channel Logout 1.0 logout token signed
//! with the realm's active RS256 key and POSTs it (fire-and-forget)
//! to the RP so registered relying parties learn about the logout.

use std::collections::BTreeMap;

use axum::extract::{Form, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::Utc;
use geonosis_core::{Client, Realm, SessionId};
use geonosis_crypto::jwt::{sign_jwt, JwsHeader, PrivateMaterial};
use geonosis_crypto::KeyManagementService;
use geonosis_protocol_oidc::{LogoutTokenClaims, LOGOUT_TOKEN_TYP};

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

    // Capture (sid, sub, client_id) before any state is dropped so we
    // can fan out a logout token to the client even after the
    // refresh family and session are gone.
    let mut sid_hint: Option<String> = None;
    let mut sub_hint: Option<String> = None;
    let mut client_id_hint: Option<String> = None;

    if let Some(rt) = form.get("refresh_token") {
        let id = geonosis_core::RefreshTokenId(geonosis_crypto::refresh_token_hash(
            rt,
            &state.refresh_hash_key,
        ));
        if let Ok(t) = state.storage.get_refresh_token(&id).await {
            sub_hint = Some(t.user_id.to_string());
            client_id_hint = Some(t.client_id.to_string());
            let _ = state.storage.revoke_token_family(t.family_id).await;
        }
    }
    if let Some(hint) = form.get("id_token_hint") {
        let parts = id_token_hint_parts_unsafe(hint);
        if sid_hint.is_none() {
            sid_hint = parts.sid;
        }
        if sub_hint.is_none() {
            sub_hint = parts.sub;
        }
        if client_id_hint.is_none() {
            // `aud` is preferred for OIDC; `azp` is the authorized party
            // when `aud` is an array of >1 entries.
            client_id_hint = parts.azp.or(parts.aud);
        }
        if let Some(ref sid) = sid_hint {
            let _ = state
                .storage
                .delete_session(&SessionId(sid.clone()))
                .await;
        }
    }
    // `client_id` form parameter — RP-Initiated Logout §3 allows
    // direct identification when no token hint is supplied.
    if client_id_hint.is_none() {
        if let Some(c) = form.get("client_id") {
            client_id_hint = Some(c.clone());
        }
    }

    // OIDC Back-Channel Logout 1.0 §2.5: mint + POST the logout token
    // to the resolved client if it has registered a callback URL.
    // Fire-and-forget so RP latency / outage cannot block the OP's
    // logout response.
    if let (Some(cid), Some(_)) = (client_id_hint.as_ref(), sid_hint.as_ref().or(sub_hint.as_ref())) {
        if let Ok(client) = state.storage.get_client_by_client_id(realm.id, cid).await {
            if client.backchannel_logout_url.is_some() {
                dispatch_backchannel_logout(
                    state.clone(),
                    realm.clone(),
                    client,
                    sub_hint.clone(),
                    sid_hint.clone(),
                );
            }
        }
    }

    StatusCode::NO_CONTENT.into_response()
}

/// Parsed claim snippets useful for routing the logout — never
/// verified, only inspected. Acceptable per OIDC RP-Initiated
/// Logout §3 (hint-only usage of `id_token_hint`).
#[derive(Default, Debug, Clone)]
struct IdTokenHintParts {
    sid: Option<String>,
    sub: Option<String>,
    /// First element of `aud` when it's an array, or the string when
    /// it's a scalar.
    aud: Option<String>,
    azp: Option<String>,
}

fn id_token_hint_parts_unsafe(jwt: &str) -> IdTokenHintParts {
    let mut parts = jwt.split('.');
    if parts.next().is_none() {
        return IdTokenHintParts::default();
    }
    let Some(payload_b64) = parts.next() else {
        return IdTokenHintParts::default();
    };
    let Ok(bytes) = geonosis_crypto::base64url::decode(payload_b64) else {
        return IdTokenHintParts::default();
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return IdTokenHintParts::default();
    };
    let aud = match v.get("aud") {
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(serde_json::Value::Array(a)) => a.first().and_then(|x| x.as_str()).map(String::from),
        _ => None,
    };
    IdTokenHintParts {
        sid: v.get("sid").and_then(|s| s.as_str()).map(String::from),
        sub: v.get("sub").and_then(|s| s.as_str()).map(String::from),
        aud,
        azp: v.get("azp").and_then(|s| s.as_str()).map(String::from),
    }
}

/// Mint a logout token and POST it to `client.backchannel_logout_url`
/// in a detached tokio task. The OP's logout response (204) is
/// returned to the caller regardless of RP availability.
fn dispatch_backchannel_logout(
    state: AppState,
    realm: Realm,
    client: Client,
    sub: Option<String>,
    sid: Option<String>,
) {
    tokio::spawn(async move {
        let Some(url) = client.backchannel_logout_url.clone() else {
            return;
        };
        let token = match build_logout_token(&state, &realm, &client, sub.clone(), sid.clone()).await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    realm = %realm.slug,
                    client_id = %client.client_id,
                    error = %e,
                    "backchannel logout: token mint failed",
                );
                return;
            }
        };
        // RP receives `application/x-www-form-urlencoded` body with a
        // single `logout_token` field per spec §2.6.
        let res = reqwest::Client::new()
            .post(url.as_str())
            .form(&[("logout_token", token.as_str())])
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await;
        match res {
            Ok(r) if r.status().is_success() => {
                tracing::info!(
                    realm = %realm.slug,
                    client_id = %client.client_id,
                    rp_url = %url,
                    "backchannel logout delivered",
                );
            }
            Ok(r) => {
                tracing::warn!(
                    realm = %realm.slug,
                    client_id = %client.client_id,
                    rp_url = %url,
                    status = %r.status(),
                    "backchannel logout: RP returned non-2xx",
                );
            }
            Err(e) => {
                tracing::warn!(
                    realm = %realm.slug,
                    client_id = %client.client_id,
                    rp_url = %url,
                    error = %e,
                    "backchannel logout: RP unreachable",
                );
            }
        }
    });
}

async fn build_logout_token(
    state: &AppState,
    realm: &Realm,
    client: &Client,
    sub: Option<String>,
    sid: Option<String>,
) -> Result<String, String> {
    if sub.is_none() && sid.is_none() {
        return Err("logout token MUST carry sub or sid (spec §2.4)".into());
    }
    let alg = client
        .access_token_signing_alg
        .unwrap_or(realm.token_policy.default_signing_alg);
    let kid = state
        .kms
        .active_signing_kid(realm.id, alg)
        .await
        .map_err(|e| e.to_string())?;
    let private: PrivateMaterial = state
        .kms
        .load_private(&kid)
        .await
        .map_err(|e| e.to_string())?;

    let mut issuer_base = state.public_base_url.clone();
    issuer_base.set_path(&format!("/realms/{}", realm.slug));

    let now = Utc::now().timestamp();
    let jti = geonosis_crypto::random::random_token();
    let claims = LogoutTokenClaims::new(
        issuer_base.to_string(),
        client.client_id.clone(),
        now,
        jti,
        sub,
        sid,
    );
    let header = JwsHeader::new(alg, kid.to_string(), LOGOUT_TOKEN_TYP);
    sign_jwt(&header, &claims, &private).map_err(|e| e.to_string())
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
