//! `/realms/{slug}/protocol/openid-connect/token` — RFC 6749 §4.
//!
//! Dispatches across all v0.1 grant types:
//! - `authorization_code` — code exchange with PKCE verification
//! - `refresh_token`      — rotation + family reuse detection
//! - `client_credentials` — service-account access token
//! - `password`           — direct grant (deprecated; per `docs/03`)
//! - `urn:ietf:params:oauth:grant-type:device_code` — RFC 8628
//! - `urn:ietf:params:oauth:grant-type:token-exchange` — RFC 8693

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Form, Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration as ChronoDuration, Utc};
use serde::Serialize;

use geonosis_core::scope::parse_scope_string;
use geonosis_core::{
    AuthnLevel, CodeId, GrantType, RefreshToken, RefreshTokenId, ScopeName, Session, SessionId,
    Subject, User, UserId,
};
use geonosis_crypto::refresh_token_hash;
use geonosis_protocol_oauth::{
    assert_grant_permitted, AuthorizationCodeGrant, ClientCredentialsGrant, IssuedTokens,
    OAuthError, TokenIssuer,
};
use geonosis_protocol_oidc::OidcIssuer;

use crate::audit_emit;
use crate::handlers::client_auth::{authenticate_client, server_err};
use crate::handlers::error::oauth_error_response;
use crate::state::AppState;

#[derive(Debug, Serialize)]
struct TokenResponseBody {
    access_token: String,
    token_type: String,
    expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
    scope: String,
}

impl From<IssuedTokens> for TokenResponseBody {
    fn from(t: IssuedTokens) -> Self {
        Self {
            access_token: t.access_token,
            token_type: "Bearer".into(),
            expires_in: t.access_token_expires_in,
            refresh_token: t.refresh_token,
            id_token: t.id_token,
            scope: t.scope,
        }
    }
}

pub async fn token(
    Path(slug): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> Response {
    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        Err(_) => return oauth_error_response(&OAuthError::invalid_request("realm not found")),
    };

    let grant_str = match form.get("grant_type") {
        Some(g) => g.clone(),
        None => return oauth_error_response(&OAuthError::invalid_request("missing grant_type")),
    };
    let grant_type = match GrantType::parse(&grant_str) {
        Some(g) => g,
        None => return oauth_error_response(&OAuthError::unsupported_grant_type(grant_str)),
    };

    // Authenticate the client (basic / post / none).
    let auth = match authenticate_client(&state, realm.id, &headers, &form).await {
        Ok(a) => a,
        Err(e) => return oauth_error_response(&e),
    };
    let client = auth.client;

    if let Err(e) = assert_grant_permitted(&client, grant_type) {
        return oauth_error_response(&e);
    }

    let issuer = build_issuer(&state, &realm.slug);

    let result: Result<IssuedTokens, OAuthError> = match grant_type {
        GrantType::AuthorizationCode => handle_auth_code(&form, &state, &issuer, &client, &realm)
            .await
            .map_err(into_oauth_err),
        GrantType::RefreshToken => handle_refresh(&form, &state, &issuer, &client, &realm)
            .await
            .map_err(into_oauth_err),
        GrantType::ClientCredentials => {
            let scope = parse_scope_string(form.get("scope").map(String::as_str).unwrap_or(""))
                .unwrap_or_default();
            ClientCredentialsGrant { scope }
                .exchange(&state.storage, &issuer, &client, &realm)
                .await
                .map_err(into_oauth_err)
        }
        GrantType::Password => handle_password(&form, &state, &issuer, &client, &realm).await,
        GrantType::DeviceCode => handle_device_code(&form, &state, &issuer, &client, &realm).await,
        GrantType::TokenExchange => {
            handle_token_exchange(&form, &state, &issuer, &client, &realm).await
        }
    };

    let grant_label = grant_type_label(grant_type);
    match result {
        Ok(ref tokens) => {
            state
                .metrics
                .oidc_token
                .inc(&[&realm.slug, grant_label, "success"]);
            audit_emit::emit_system(
                &state,
                realm.id,
                geonosis_audit::action::TOKEN_ISSUED,
                Some(geonosis_audit::Target::Session {
                    id: tokens.session_id.clone(),
                }),
                serde_json::json!({
                    "grant_type": grant_label,
                    "client_id": client.client_id,
                }),
            );
            let body: TokenResponseBody = tokens.clone().into();
            (axum::http::StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => {
            state
                .metrics
                .oidc_token
                .inc(&[&realm.slug, grant_label, "error"]);
            if matches!(grant_type, GrantType::Password) {
                state
                    .metrics
                    .oidc_login_failures
                    .inc(&[&realm.slug, error_reason_label(&e)]);
                audit_emit::emit_system(
                    &state,
                    realm.id,
                    geonosis_audit::action::LOGIN_FAILURE,
                    None,
                    serde_json::json!({
                        "grant_type": "password",
                        "client_id": client.client_id,
                        "reason": error_reason_label(&e),
                    }),
                );
            }
            oauth_error_response(&e)
        }
    }
}

fn grant_type_label(g: GrantType) -> &'static str {
    match g {
        GrantType::AuthorizationCode => "authorization_code",
        GrantType::RefreshToken => "refresh_token",
        GrantType::ClientCredentials => "client_credentials",
        GrantType::Password => "password",
        GrantType::DeviceCode => "device_code",
        GrantType::TokenExchange => "token_exchange",
    }
}

fn error_reason_label(e: &OAuthError) -> &'static str {
    // The OAuthErrorCode enum's `as_str()` is the stable RFC string
    // — feeding it back into the label keeps cardinality bounded to
    // the spec-defined set.
    e.code.as_str()
}

fn into_oauth_err(e: geonosis_protocol_oauth::grants::GrantError) -> OAuthError {
    use geonosis_protocol_oauth::grants::GrantError;
    match e {
        GrantError::OAuth(e) => e,
        GrantError::Pkce(e) => OAuthError::invalid_grant(e.to_string()),
        GrantError::Storage(s) => server_err(s),
        GrantError::Internal(s) => server_err(s),
    }
}

fn build_issuer(state: &AppState, _slug: &str) -> OidcIssuer<geonosis_crypto::SoftwareKms> {
    OidcIssuer {
        kms: state.kms.clone(),
        refresh_hash_key: state.refresh_hash_key,
        issuer_base: state.public_base_url.clone(),
    }
}

async fn handle_auth_code(
    form: &BTreeMap<String, String>,
    state: &AppState,
    issuer: &OidcIssuer<geonosis_crypto::SoftwareKms>,
    client: &geonosis_core::Client,
    realm: &geonosis_core::Realm,
) -> Result<IssuedTokens, geonosis_protocol_oauth::grants::GrantError> {
    let code = form
        .get("code")
        .cloned()
        .ok_or_else(|| OAuthError::invalid_request("missing code"))?;
    let redirect_uri_s = form
        .get("redirect_uri")
        .cloned()
        .ok_or_else(|| OAuthError::invalid_request("missing redirect_uri"))?;
    let redirect_uri = url::Url::parse(&redirect_uri_s)
        .map_err(|e| OAuthError::invalid_request(format!("invalid redirect_uri: {e}")))?;
    let client_id = form
        .get("client_id")
        .cloned()
        .unwrap_or_else(|| client.client_id.clone());

    AuthorizationCodeGrant {
        code: CodeId(code),
        code_verifier: form.get("code_verifier").cloned(),
        redirect_uri,
        client_id,
    }
    .exchange(&state.storage, issuer, client, realm)
    .await
}

async fn handle_refresh(
    form: &BTreeMap<String, String>,
    state: &AppState,
    issuer: &OidcIssuer<geonosis_crypto::SoftwareKms>,
    client: &geonosis_core::Client,
    realm: &geonosis_core::Realm,
) -> Result<IssuedTokens, geonosis_protocol_oauth::grants::GrantError> {
    let presented = form
        .get("refresh_token")
        .cloned()
        .ok_or_else(|| OAuthError::invalid_request("missing refresh_token"))?;
    let storage_arc: Arc<dyn geonosis_storage::Storage> = state.storage.clone();
    let outcome = geonosis_protocol_oauth::validate_refresh(
        &storage_arc,
        &presented,
        &state.refresh_hash_key,
    )
    .await
    .map_err(|e| match e {
        geonosis_protocol_oauth::RefreshRotateError::NotFound => {
            OAuthError::invalid_grant("unknown refresh token")
        }
        geonosis_protocol_oauth::RefreshRotateError::Expired => {
            OAuthError::invalid_grant("refresh token expired")
        }
        geonosis_protocol_oauth::RefreshRotateError::Reuse => {
            state.metrics.token_reuse_detected.inc(&[&realm.slug]);
            audit_emit::emit_system(
                state,
                realm.id,
                geonosis_audit::action::TOKEN_REUSE,
                None,
                serde_json::json!({
                    "client_id": client.client_id,
                }),
            );
            OAuthError::invalid_grant("refresh token reuse — family burned")
        }
        geonosis_protocol_oauth::RefreshRotateError::Storage(s) => server_err(s),
    })?;
    let prior = match outcome {
        geonosis_protocol_oauth::RefreshOutcome::Ok { prior } => prior,
    };

    // Mint replacement tokens reusing the prior session + scope + family.
    let subject = Subject::Local {
        user_id: prior.user_id,
    };
    let scope: Vec<ScopeName> = prior.scope.clone();
    let (access, exp) = issuer
        .mint_access_token(realm, client, &subject, &prior.session_id, &scope)
        .await?;
    let id_token = if scope.iter().any(|s| s.as_str() == "openid") {
        Some(
            issuer
                .mint_id_token(realm, client, &subject, &prior.session_id, &scope, None, None)
                .await?,
        )
    } else {
        None
    };

    // Rotate the refresh token.
    let new_secret = geonosis_crypto::RefreshTokenSecret::generate();
    let new_token = RefreshToken {
        id: RefreshTokenId(refresh_token_hash(
            new_secret.as_str(),
            &state.refresh_hash_key,
        )),
        family_id: prior.family_id,
        realm_id: prior.realm_id,
        client_id: prior.client_id,
        user_id: prior.user_id,
        session_id: prior.session_id.clone(),
        scope: prior.scope.clone(),
        issued_at: Utc::now(),
        expires_at: Utc::now()
            + ChronoDuration::from_std(realm.token_policy.refresh_token_lifespan)
                .unwrap_or_default(),
        used: false,
    };
    geonosis_protocol_oauth::rotate_refresh_token(&storage_arc, &prior, new_token)
        .await
        .map_err(|e| server_err(e.to_string()))?;

    audit_emit::emit_user(
        state,
        realm.id,
        prior.user_id,
        geonosis_audit::action::TOKEN_REFRESHED,
        Some(geonosis_audit::Target::Session {
            id: prior.session_id.clone(),
        }),
        serde_json::json!({ "client_id": client.client_id }),
    );

    Ok(IssuedTokens {
        access_token: access,
        access_token_expires_in: exp,
        id_token,
        refresh_token: Some(new_secret.as_str().to_string()),
        scope: scope
            .iter()
            .map(geonosis_core::ScopeName::as_str)
            .collect::<Vec<_>>()
            .join(" "),
        token_type: geonosis_protocol_oauth::grants::TokenType::Bearer,
        session_id: prior.session_id,
    })
}

async fn handle_password(
    form: &BTreeMap<String, String>,
    state: &AppState,
    issuer: &OidcIssuer<geonosis_crypto::SoftwareKms>,
    client: &geonosis_core::Client,
    realm: &geonosis_core::Realm,
) -> Result<IssuedTokens, OAuthError> {
    let username = form
        .get("username")
        .cloned()
        .ok_or_else(|| OAuthError::invalid_request("missing username"))?;
    let password = form
        .get("password")
        .cloned()
        .ok_or_else(|| OAuthError::invalid_request("missing password"))?;
    let scope = parse_scope_string(form.get("scope").map(String::as_str).unwrap_or("openid"))
        .map_err(|e| OAuthError::invalid_request(e.0))?;

    let user: User = state
        .storage
        .get_user_by_username(realm.id, &username)
        .await
        .map_err(|_| OAuthError::invalid_grant("invalid username or password"))?;
    if !user.enabled {
        return Err(OAuthError::invalid_grant("user disabled"));
    }
    let phc = state
        .storage
        .get_password_hash(realm.id, user.id)
        .await
        .map_err(|_| OAuthError::invalid_grant("invalid username or password"))?;
    let ok = geonosis_crypto::verify_password(&password, &phc).unwrap_or(false);
    if !ok {
        return Err(OAuthError::invalid_grant("invalid username or password"));
    }

    issue_user_tokens(state, issuer, client, realm, user.id, &scope).await
}

async fn handle_device_code(
    form: &BTreeMap<String, String>,
    state: &AppState,
    issuer: &OidcIssuer<geonosis_crypto::SoftwareKms>,
    client: &geonosis_core::Client,
    realm: &geonosis_core::Realm,
) -> Result<IssuedTokens, OAuthError> {
    let device_code = form
        .get("device_code")
        .cloned()
        .ok_or_else(|| OAuthError::invalid_request("missing device_code"))?;
    let mut grant = state
        .storage
        .get_device_grant_by_device_code(&device_code)
        .await
        .map_err(|_| OAuthError::invalid_grant("unknown device_code"))?;
    if grant.realm_id != realm.id || grant.client_id != client.id {
        return Err(OAuthError::invalid_grant("device_code mismatch"));
    }
    let now = Utc::now();
    if grant.expires_at < now {
        let _ = state.storage.delete_device_grant(&device_code).await;
        return Err(OAuthError::new(
            geonosis_protocol_oauth::OAuthErrorCode::ExpiredToken,
            "device_code expired",
        ));
    }
    if let Some(last) = grant.last_polled_at {
        if (now - last).num_seconds() < grant.interval_seconds as i64 {
            return Err(OAuthError::new(
                geonosis_protocol_oauth::OAuthErrorCode::SlowDown,
                "slow down",
            ));
        }
    }
    grant.last_polled_at = Some(now);

    use geonosis_storage::DeviceGrantStatus::*;
    match grant.status {
        Pending => {
            let _ = state.storage.update_device_grant(grant).await;
            Err(OAuthError::new(
                geonosis_protocol_oauth::OAuthErrorCode::AuthorizationPending,
                "authorization pending",
            ))
        }
        Denied => {
            let _ = state.storage.delete_device_grant(&device_code).await;
            Err(OAuthError::new(
                geonosis_protocol_oauth::OAuthErrorCode::AccessDenied,
                "user denied",
            ))
        }
        Expired => Err(OAuthError::new(
            geonosis_protocol_oauth::OAuthErrorCode::ExpiredToken,
            "device_code expired",
        )),
        Approved => {
            let user_id = grant
                .user_id
                .ok_or_else(|| server_err("device grant approved without user_id"))?;
            let scope = grant.scope.clone();
            let _ = state.storage.delete_device_grant(&device_code).await;
            issue_user_tokens(state, issuer, client, realm, user_id, &scope).await
        }
    }
}

/// Token Exchange (RFC 8693). v0.1 baseline:
/// - **Delegation** form: `subject_token` is one of our access tokens.
///   We verify it against our own KMS, lift the subject, and mint a
///   new access token whose `act` chain records the requesting client
///   as the actor. This is the path doc 18 calls "agent acting for
///   user".
/// - **Impersonation** (no `act`), audience reduction, scope reduction,
///   refresh-token subject tokens, and Agent-specific capability
///   pruning land in v0.1.x. The handler surfaces them as
///   `invalid_request` until then so callers don't silently get a
///   delegation token.
async fn handle_token_exchange(
    form: &BTreeMap<String, String>,
    state: &AppState,
    issuer: &OidcIssuer<geonosis_crypto::SoftwareKms>,
    client: &geonosis_core::Client,
    realm: &geonosis_core::Realm,
) -> Result<IssuedTokens, OAuthError> {
    let subject_token = form
        .get("subject_token")
        .cloned()
        .ok_or_else(|| OAuthError::invalid_request("missing subject_token"))?;
    let subject_token_type = form
        .get("subject_token_type")
        .cloned()
        .ok_or_else(|| OAuthError::invalid_request("missing subject_token_type"))?;
    if subject_token_type != "urn:ietf:params:oauth:token-type:access_token" {
        return Err(OAuthError::invalid_request(format!(
            "subject_token_type {subject_token_type} not supported in v0.1; access_token only"
        )));
    }

    // Verify the inbound token against our own issuer + signing keys.
    // External-issued tokens land with the Trust Federation work in
    // v0.1.x.
    let inbound_claims = crate::token_verify::verify_access_token(state, realm, &subject_token)
        .await
        .map_err(|e| OAuthError::invalid_grant(format!("subject_token: {e}")))?;

    // Lift the user from `sub`. Local subjects use the ULID; broker
    // subjects are namespaced — v0.1 supports the local case.
    let user_id: UserId = inbound_claims
        .sub
        .parse()
        .map_err(|_| OAuthError::invalid_request("subject_token sub is not a local user id"))?;

    // Scope: subset of the original. If `scope` form param is present,
    // intersect; otherwise reuse.
    let original_scope = geonosis_core::scope::parse_scope_string(&inbound_claims.scope)
        .map_err(|e| OAuthError::invalid_request(e.0))?;
    let requested_scope = match form.get("scope") {
        Some(s) => geonosis_core::scope::parse_scope_string(s)
            .map_err(|e| OAuthError::invalid_request(e.0))?,
        None => original_scope.clone(),
    };
    if !requested_scope.iter().all(|s| original_scope.contains(s)) {
        return Err(OAuthError::new(
            geonosis_protocol_oauth::OAuthErrorCode::InvalidScope,
            "requested scope must be a subset of subject_token scope",
        ));
    }

    // Build the `act` chain. RFC 8693 §2.2 places the immediate actor
    // at `act.sub`; if the subject_token already carried an `act`, we
    // nest it. The recursion shows the full delegation lineage.
    let act = build_actor_chain(client.client_id.clone(), inbound_claims.act.clone());

    // Audience: prefer explicit `audience`/`resource` form values, fall
    // back to the calling client_id.
    let audience: Option<Vec<String>> = form
        .get("audience")
        .map(|s| s.split(' ').map(String::from).collect())
        .or_else(|| form.get("resource").map(|s| vec![s.clone()]));

    // Mint a fresh session so /sessions can revoke this exchange leg
    // independently from the original interactive session.
    let session_id = SessionId::new_random();
    let now = Utc::now();
    let session = Session {
        id: session_id.clone(),
        realm_id: realm.id,
        user_id,
        authn_level: AuthnLevel::Single,
        idp_alias: None,
        started_at: now,
        last_seen_at: now,
        expires_at: now
            + ChronoDuration::from_std(realm.session_policy.sso_session_max).unwrap_or_default(),
        clients: vec![],
    };
    state
        .storage
        .create_session(session)
        .await
        .map_err(|e| server_err(e.to_string()))?;

    let subject = Subject::Local { user_id };
    let extras = geonosis_protocol_oidc::AccessTokenExtras {
        org: inbound_claims.org,
        act: Some(act),
        audience,
    };
    let (access, exp) = issuer
        .mint_access_token_with_extras(
            realm,
            client,
            &subject,
            &session_id,
            &requested_scope,
            extras,
        )
        .await
        .map_err(into_oauth_err)?;

    Ok(IssuedTokens {
        access_token: access,
        access_token_expires_in: exp,
        id_token: None,
        refresh_token: None,
        scope: requested_scope
            .iter()
            .map(geonosis_core::ScopeName::as_str)
            .collect::<Vec<_>>()
            .join(" "),
        token_type: geonosis_protocol_oauth::grants::TokenType::Bearer,
        session_id,
    })
}

/// Compose the `act` claim per RFC 8693 §2.2. New actor wraps any
/// prior chain in its own `act` field, preserving the lineage from
/// the original user all the way to the latest delegating client.
fn build_actor_chain(actor_sub: String, inner: Option<serde_json::Value>) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("sub".into(), serde_json::Value::String(actor_sub));
    if let Some(prior) = inner {
        obj.insert("act".into(), prior);
    }
    serde_json::Value::Object(obj)
}

async fn issue_user_tokens(
    state: &AppState,
    issuer: &OidcIssuer<geonosis_crypto::SoftwareKms>,
    client: &geonosis_core::Client,
    realm: &geonosis_core::Realm,
    user_id: UserId,
    scope: &[ScopeName],
) -> Result<IssuedTokens, OAuthError> {
    let session_id = SessionId::new_random();
    let now = Utc::now();
    let session = Session {
        id: session_id.clone(),
        realm_id: realm.id,
        user_id,
        authn_level: AuthnLevel::Single,
        idp_alias: None,
        started_at: now,
        last_seen_at: now,
        expires_at: now
            + ChronoDuration::from_std(realm.session_policy.sso_session_max).unwrap_or_default(),
        clients: vec![],
    };
    state
        .storage
        .create_session(session)
        .await
        .map_err(|e| server_err(e.to_string()))?;
    state.metrics.session_created.inc(&[&realm.slug]);

    let subject = Subject::Local { user_id };
    let (access, exp) = issuer
        .mint_access_token(realm, client, &subject, &session_id, scope)
        .await
        .map_err(into_oauth_err)?;
    let id_token = if scope.iter().any(|s| s.as_str() == "openid") {
        Some(
            issuer
                .mint_id_token(realm, client, &subject, &session_id, scope, None, None)
                .await
                .map_err(into_oauth_err)?,
        )
    } else {
        None
    };

    let refresh = if client.grants.refresh_token {
        let secret = geonosis_crypto::RefreshTokenSecret::generate();
        let token = RefreshToken {
            id: RefreshTokenId(refresh_token_hash(secret.as_str(), &state.refresh_hash_key)),
            family_id: geonosis_protocol_oauth::refresh::new_family(),
            realm_id: realm.id,
            client_id: client.id,
            user_id,
            session_id: session_id.clone(),
            scope: scope.to_vec(),
            issued_at: now,
            expires_at: now
                + ChronoDuration::from_std(realm.token_policy.refresh_token_lifespan)
                    .unwrap_or_default(),
            used: false,
        };
        state
            .storage
            .save_refresh_token(token)
            .await
            .map_err(|e| server_err(e.to_string()))?;
        Some(secret.as_str().to_string())
    } else {
        None
    };

    Ok(IssuedTokens {
        access_token: access,
        access_token_expires_in: exp,
        id_token,
        refresh_token: refresh,
        scope: scope
            .iter()
            .map(geonosis_core::ScopeName::as_str)
            .collect::<Vec<_>>()
            .join(" "),
        token_type: geonosis_protocol_oauth::grants::TokenType::Bearer,
        session_id,
    })
}
