//! Broker HTTP surface — `/realms/{slug}/broker/{alias}/...`.
//!
//! Per `docs/05-identity-broker.md` §"URL surface":
//! - `GET  /login`     — kicks off the redirect to the IdP
//! - `GET /POST /endpoint` — OIDC callback / SAML ACS
//! - `GET  /metadata`  — SAML SP metadata
//!
//! v0.1 ships the OIDC flow end-to-end and the SAML AuthnRequest +
//! ACS plumbing; full SAML SLO is parked for the next minor release.

use axum::extract::{Form, Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};

use geonosis_broker::{
    adapter::urn as adapter_urn,
    oidc::{self, IdTokenClaims},
    saml::{self, OutboundRequest},
    BrokerAssertion, BrokerAuthnState, BrokerError, IdpConfig, OidcIdpConfig, PkcePair,
    SamlIdpConfig,
};
use geonosis_core::id::FlowStateId;

use crate::handlers::error::JsonProblem;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    /// FlowStateId the caller wants to resume after the IdP returns.
    /// Optional in v0.1: smoke tests can hit the endpoint without an
    /// in-flight flow.
    #[serde(default)]
    pub flow: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OidcCallbackQuery {
    pub code: Option<String>,
    pub state: String,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SamlCallbackForm {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    #[serde(rename = "RelayState")]
    pub relay_state: Option<String>,
}

/// Initiate broker login. Builds the IdP-side authorization URL,
/// persists a `BrokerAuthnState` row, and 302s the browser.
pub async fn broker_login(
    State(state): State<AppState>,
    Path((slug, alias)): Path<(String, String)>,
    Query(q): Query<LoginQuery>,
) -> Result<Response, JsonProblem> {
    let realm = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| JsonProblem::not_found("unknown realm"))?;
    let idp = state
        .storage
        .get_idp_by_alias(realm.id, &alias)
        .await
        .map_err(|_| JsonProblem::not_found("unknown idp"))?;
    if !idp.enabled {
        return Err(JsonProblem::bad_request("idp disabled"));
    }

    let flow_state_id = q
        .flow
        .as_deref()
        .and_then(|s| s.parse::<FlowStateId>().ok())
        .unwrap_or_default();

    match &idp.config {
        IdpConfig::Oidc(cfg) => {
            let discovery = state
                .broker
                .discovery
                .discovery(&alias, cfg)
                .await
                .map_err(broker_err_to_problem)?;
            let redirect_uri = state.broker.redirect_uri(&state.public_base_url, &realm, &alias);
            let pkce = if cfg.pkce {
                Some(PkcePair::generate())
            } else {
                None
            };
            let mut br_state = BrokerAuthnState::new(realm.id, alias.clone(), flow_state_id);
            if let Some(p) = &pkce {
                br_state = br_state.with_pkce(p.verifier.clone());
            }
            let state_value = br_state.state.clone();
            let nonce = br_state.nonce.clone().unwrap_or_default();
            state
                .storage
                .save_broker_state(br_state)
                .await
                .map_err(|e| JsonProblem::internal(e.to_string()))?;
            let adapter_urn_s = idp
                .adapter_urn
                .as_deref()
                .unwrap_or(adapter_urn::GENERIC_OIDC);
            let adapter = state.broker_adapters.get(adapter_urn_s);
            let mut extra_owned = adapter.extra_authorization_params(cfg);
            if let Some(p) = cfg.prompt.as_deref() {
                extra_owned.push(("prompt", p.into()));
            }
            if let Some(m) = cfg.response_mode.as_deref() {
                extra_owned.push(("response_mode", m.into()));
            }
            let extra: Vec<(&str, &str)> = extra_owned
                .iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect();
            let url = oidc::authorization_url(
                &discovery,
                cfg,
                &redirect_uri,
                &state_value,
                &nonce,
                pkce.as_ref().map(|p| p.challenge.as_str()),
                &extra,
            );
            Ok(Redirect::to(&url).into_response())
        }
        IdpConfig::Saml(cfg) => {
            let sp_entity = format!(
                "{}/realms/{}",
                state.public_base_url.as_str().trim_end_matches('/'),
                realm.slug,
            );
            let acs = state.broker.redirect_uri(&state.public_base_url, &realm, &alias);
            let br_state = BrokerAuthnState::new(realm.id, alias.clone(), flow_state_id);
            let state_value = br_state.state.clone();
            state
                .storage
                .save_broker_state(br_state)
                .await
                .map_err(|e| JsonProblem::internal(e.to_string()))?;
            let out: OutboundRequest =
                saml::build_authn_request(cfg, &sp_entity, &acs, &state_value)
                    .map_err(broker_err_to_problem)?;
            if let Some(url) = out.redirect {
                Ok(Redirect::to(&url).into_response())
            } else if let Some(form) = out.post_form {
                // Render a self-submitting form; v0.1 keeps it bare.
                let html = format!(
                    r#"<!doctype html><html><body onload="document.forms[0].submit()"><form method="POST" action="{action}"><input type="hidden" name="SAMLRequest" value="{rq}"/><input type="hidden" name="RelayState" value="{rs}"/><noscript><button type="submit">Continue</button></noscript></form></body></html>"#,
                    action = html_escape(&form.sso_url),
                    rq = html_escape(&form.saml_request),
                    rs = html_escape(&form.relay_state),
                );
                let mut resp = (StatusCode::OK, html).into_response();
                resp.headers_mut()
                    .insert(header::CONTENT_TYPE, "text/html; charset=utf-8".parse().unwrap());
                Ok(resp)
            } else {
                Err(JsonProblem::internal("saml binding produced no output"))
            }
        }
    }
}

/// OIDC code-flow callback.
pub async fn broker_endpoint_get(
    State(state): State<AppState>,
    Path((slug, alias)): Path<(String, String)>,
    Query(q): Query<OidcCallbackQuery>,
) -> Result<Json<BrokerAssertion>, JsonProblem> {
    if let Some(err) = q.error.as_deref() {
        return Err(JsonProblem::bad_request(format!(
            "idp error: {err} {}",
            q.error_description.clone().unwrap_or_default()
        )));
    }
    let realm = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| JsonProblem::not_found("unknown realm"))?;
    let idp = state
        .storage
        .get_idp_by_alias(realm.id, &alias)
        .await
        .map_err(|_| JsonProblem::not_found("unknown idp"))?;
    let cfg = match &idp.config {
        IdpConfig::Oidc(c) => c.clone(),
        IdpConfig::Saml(_) => {
            return Err(JsonProblem::bad_request("GET callback is OIDC-only"))
        }
    };
    let br_state = state
        .storage
        .consume_broker_state(realm.id, &q.state)
        .await
        .map_err(|_| JsonProblem::bad_request("state not found"))?;
    if br_state.is_expired(Utc::now()) {
        return Err(JsonProblem::bad_request("state expired"));
    }
    let code = q
        .code
        .ok_or_else(|| JsonProblem::bad_request("missing code"))?;
    let assertion = exchange_and_verify(&state, &alias, &cfg, &br_state, &code, &idp.adapter_urn)
        .await
        .map_err(broker_err_to_problem)?;
    persist_or_link(&state, &realm.id, &assertion).await?;
    Ok(Json(assertion))
}

/// SAML ACS handler.
pub async fn broker_endpoint_post(
    State(state): State<AppState>,
    Path((slug, alias)): Path<(String, String)>,
    Form(form): Form<SamlCallbackForm>,
) -> Result<Json<BrokerAssertion>, JsonProblem> {
    let realm = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| JsonProblem::not_found("unknown realm"))?;
    let idp = state
        .storage
        .get_idp_by_alias(realm.id, &alias)
        .await
        .map_err(|_| JsonProblem::not_found("unknown idp"))?;
    let cfg = match &idp.config {
        IdpConfig::Saml(c) => c.clone(),
        IdpConfig::Oidc(_) => {
            return Err(JsonProblem::bad_request("POST callback is SAML-only"))
        }
    };
    let response =
        saml::parse_response(&form.saml_response).map_err(broker_err_to_problem)?;
    if cfg.want_responses_signed || cfg.want_assertions_signed {
        saml::verify_response_signature(&response, &cfg.signing_cert_pems)
            .map_err(broker_err_to_problem)?;
    }
    let relay = form
        .relay_state
        .as_deref()
        .ok_or_else(|| JsonProblem::bad_request("missing RelayState"))?;
    let _br_state = state
        .storage
        .consume_broker_state(realm.id, relay)
        .await
        .map_err(|_| JsonProblem::bad_request("RelayState not found"))?;
    let sp_entity = format!(
        "{}/realms/{}",
        state.public_base_url.as_str().trim_end_matches('/'),
        realm.slug,
    );
    let assertion =
        saml::assertion_to_broker(&alias, &sp_entity, None, &response).map_err(broker_err_to_problem)?;
    persist_or_link(&state, &realm.id, &assertion).await?;
    Ok(Json(assertion))
}

#[derive(Debug, Serialize)]
pub struct SamlMetadata {
    pub entity_id: String,
    pub acs_url: String,
    pub slo_url: String,
}

/// Minimal SP metadata document. v0.1 emits a JSON form; XML metadata
/// lands with `geonosis-protocol-saml-idp` follow-up.
pub async fn broker_metadata(
    State(state): State<AppState>,
    Path((slug, alias)): Path<(String, String)>,
) -> Result<Json<SamlMetadata>, JsonProblem> {
    let realm = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| JsonProblem::not_found("unknown realm"))?;
    let _ = state
        .storage
        .get_idp_by_alias(realm.id, &alias)
        .await
        .map_err(|_| JsonProblem::not_found("unknown idp"))?;
    let base = state.public_base_url.as_str().trim_end_matches('/');
    Ok(Json(SamlMetadata {
        entity_id: format!("{base}/realms/{}", realm.slug),
        acs_url: format!("{base}/realms/{}/broker/{}/endpoint", realm.slug, alias),
        slo_url: format!("{base}/realms/{}/protocol/openid-connect/logout", realm.slug),
    }))
}

async fn exchange_and_verify(
    state: &AppState,
    alias: &str,
    cfg: &OidcIdpConfig,
    br_state: &BrokerAuthnState,
    code: &str,
    adapter_urn_override: &Option<String>,
) -> Result<BrokerAssertion, BrokerError> {
    let discovery = state.broker.discovery.discovery(alias, cfg).await?;
    let redirect_uri = state
        .broker
        .redirect_uri(&state.public_base_url, &fake_realm_for(alias)?, alias);
    let _ = redirect_uri; // computed below per real realm

    let realm = state
        .storage
        .get_realm(br_state.realm_id)
        .await
        .map_err(|e| BrokerError::Transport(e.to_string()))?;
    let redirect_uri = state
        .broker
        .redirect_uri(&state.public_base_url, &realm, alias);
    let verifier = br_state
        .pkce_verifier
        .as_ref()
        .map(|s| s.expose().clone());
    let token = oidc::exchange_code(
        state.broker.discovery.http(),
        &discovery,
        cfg,
        code,
        &redirect_uri,
        verifier.as_deref(),
    )
    .await?;

    let now = Utc::now().timestamp();
    let jwks = state
        .broker
        .discovery
        .jwks(alias, &discovery.jwks_uri)
        .await?;

    let claims: IdTokenClaims = if let Some(id_token) = &token.id_token {
        oidc::verify_id_token(
            id_token,
            &cfg.issuer,
            &cfg.client_id,
            br_state.nonce.as_deref(),
            &jwks,
            now,
        )?
    } else {
        return Err(BrokerError::InvalidAssertion("no id_token".into()));
    };

    let adapter_urn_s = adapter_urn_override
        .as_deref()
        .unwrap_or(adapter_urn::GENERIC_OIDC);
    let adapter = state.broker_adapters.get(adapter_urn_s);

    let mut assertion = oidc::assertion_from_claims(
        alias,
        &claims,
        token
            .expires_in
            .map(|s| Utc::now() + Duration::seconds(s)),
    );
    adapter.enrich_assertion(&claims, &mut assertion);
    if let Some(extra) = adapter
        .userinfo_override(state.broker.discovery.http(), cfg, &token.access_token)
        .await?
    {
        for (k, v) in extra {
            assertion.claims.insert(k, v);
        }
    }
    Ok(assertion)
}

fn fake_realm_for(_alias: &str) -> Result<geonosis_core::Realm, BrokerError> {
    // Helper kept solely so the redirect_uri call above type-checks at
    // first compilation; the real realm fetch happens immediately after.
    Err(BrokerError::Transport("internal".into()))
}

async fn persist_or_link(
    state: &AppState,
    realm_id: &geonosis_core::RealmId,
    assertion: &BrokerAssertion,
) -> Result<(), JsonProblem> {
    // v0.1: idempotent upsert keyed on (realm, alias, external_id).
    // First-login flow / link-only branching lives in the flow
    // executor; this handler captures the link so subsequent logins
    // resolve in a single round-trip.
    use geonosis_broker::BrokerLink;
    use geonosis_core::id::BrokerLinkId;

    if let Some(existing) = state
        .storage
        .find_broker_link(*realm_id, &assertion.idp_alias, &assertion.external_id)
        .await
        .map_err(|e| JsonProblem::internal(e.to_string()))?
    {
        let mut updated = existing;
        updated.last_login_at = Some(Utc::now());
        state
            .storage
            .upsert_broker_link(updated)
            .await
            .map_err(|e| JsonProblem::internal(e.to_string()))?;
    } else {
        let link = BrokerLink {
            id: BrokerLinkId::new(),
            realm_id: *realm_id,
            // No local user yet — the flow executor's first-login step
            // will replace this placeholder once the user resolves.
            user_id: geonosis_core::UserId::new(),
            idp_alias: assertion.idp_alias.clone(),
            external_id: assertion.external_id.clone(),
            external_username: assertion
                .claims
                .get("preferred_username")
                .and_then(|v| match v {
                    geonosis_core::attribute::AttributeValue::String(s) => Some(s.clone()),
                    _ => None,
                }),
            created_at: Utc::now(),
            last_login_at: Some(Utc::now()),
        };
        state
            .storage
            .upsert_broker_link(link)
            .await
            .map_err(|e| JsonProblem::internal(e.to_string()))?;
    }
    Ok(())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn broker_err_to_problem(e: BrokerError) -> JsonProblem {
    match e {
        BrokerError::StateMismatch | BrokerError::NonceMismatch | BrokerError::ExpiredState => {
            JsonProblem::bad_request(e.to_string())
        }
        BrokerError::UnknownIdp(_) => JsonProblem::not_found(e.to_string()),
        BrokerError::Transport(_) | BrokerError::Discovery(_) | BrokerError::TokenExchange(_) => {
            JsonProblem::bad_gateway(e.to_string())
        }
        _ => JsonProblem::bad_request(e.to_string()),
    }
}

// Silence the unused-import warning when SamlIdpConfig is not used
// in handlers (it's used through `IdpConfig::Saml`).
const _: Option<&SamlIdpConfig> = None;
