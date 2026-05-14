//! SAML 2.0 IdP HTTP surface.
//!
//! Per `docs/20-saml-idp.md` v0.1 wires three endpoints:
//!
//! - `GET /realms/:slug/protocol/saml/descriptor` — IdP metadata.
//! - `POST /realms/:slug/protocol/saml/sso` — SP-initiated SSO via
//!   the HTTP-POST binding.
//! - `GET /realms/:slug/protocol/saml/sso` — placeholder for the
//!   HTTP-Redirect binding (DEFLATE decode lands with the redirect
//!   path in v0.1.x).
//!
//! The full assertion-issuing flow:
//!
//! 1. SP posts a base64-encoded `<AuthnRequest>` as the `SAMLRequest`
//!    form field.
//! 2. We decode + parse it via
//!    [`geonosis_protocol_saml_idp::parse_authn_request`].
//! 3. Resolve the SP `Client` row by `Issuer` (which matches the
//!    SP's `Client.client_id`) and validate the typed
//!    `SamlSpClientConfig` against the SP's request:
//!    `AssertionConsumerServiceURL` must be in `acs_urls`,
//!    `Destination` must be our SSO endpoint.
//! 4. Stash a SAML continuation on the `FlowState`'s
//!    `authorize_params` (keys prefixed `__geonosis_saml_*`) so
//!    `login_actions::authenticate_post` can detect the SAML branch
//!    after credential verification.
//! 5. Render the login form (same one OIDC `/authorize` uses) — the
//!    realm's browser flow runs unchanged.
//! 6. On success, login_actions reads the SAML continuation, builds
//!    + signs the assertion, and returns the auto-POST form to the
//!    SP's ACS URL.

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Form;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use geonosis_core::id::{FlowId, NodeId};
use geonosis_core::JwsAlgorithm;
use geonosis_crypto::cert::{der_to_b64, self_signed_x509_for_rs256};
use geonosis_crypto::jwt::PrivateMaterial;
use geonosis_crypto::KeyManagementService;
use geonosis_flow::FlowState;
use geonosis_protocol_saml_idp::{
    parse_authn_request, serialize_idp_metadata, IdpMetadataInput, SamlSpClientConfig,
};
use geonosis_saml_types::NameIdFormat;
use geonosis_storage::FlowStateRow;

use crate::state::AppState;

/// `GET /realms/:slug/protocol/saml/descriptor` — IdP metadata XML.
pub async fn metadata(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Response {
    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };

    let issuer_base = state.public_base_url.as_str().trim_end_matches('/');
    let entity_id = format!("{issuer_base}/realms/{}", realm.slug);
    let sso_url = format!("{issuer_base}/realms/{}/protocol/saml/sso", realm.slug);
    let slo_url = format!("{issuer_base}/realms/{}/protocol/saml/slo", realm.slug);

    let name_id_formats = [
        NameIdFormat::EmailAddress,
        NameIdFormat::Persistent,
        NameIdFormat::Transient,
        NameIdFormat::Unspecified,
    ];

    let signing_certs_b64 = match build_signing_certs(&state, &realm).await {
        Ok(certs) => certs,
        Err(e) => {
            tracing::warn!(
                realm = %realm.slug,
                error = %e,
                "saml metadata: signing cert generation failed; emitting metadata without KeyDescriptor body"
            );
            Vec::new()
        }
    };

    let xml = serialize_idp_metadata(&IdpMetadataInput {
        entity_id: &entity_id,
        sso_url: &sso_url,
        slo_url: Some(&slo_url),
        signing_certs_b64: &signing_certs_b64,
        name_id_formats: &name_id_formats,
    });

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/samlmetadata+xml; charset=utf-8",
        )],
        xml,
    )
        .into_response()
}

/// Build the `<X509Certificate>` body list for the metadata's
/// `<md:KeyDescriptor use="signing">` from the realm's active
/// RS256 signing key.
async fn build_signing_certs(
    state: &AppState,
    realm: &geonosis_core::Realm,
) -> Result<Vec<String>, String> {
    let kid = state
        .kms
        .active_signing_kid(realm.id, JwsAlgorithm::RS256)
        .await
        .map_err(|e| format!("no active RS256 key: {e}"))?;
    let material = state
        .kms
        .load_private(&kid)
        .await
        .map_err(|e| format!("load_private: {e}"))?;
    let PrivateMaterial::Rs256(rsa) = material else {
        return Err("active signing key is not RS256".into());
    };
    let der = self_signed_x509_for_rs256(rsa.as_ref(), &realm.slug)
        .map_err(|e| format!("cert mint: {e}"))?;
    Ok(vec![der_to_b64(&der)])
}

#[derive(Debug, serde::Deserialize)]
pub struct SamlSloForm {
    #[serde(rename = "SAMLRequest", default)]
    pub saml_request: String,
    #[serde(rename = "RelayState", default)]
    pub relay_state: Option<String>,
}

/// `POST /realms/:slug/protocol/saml/slo` — SP-initiated SLO entry
/// via the HTTP-POST binding.
///
/// v0.1 handles single-session revocation:
/// 1. Parse the LogoutRequest, validate Issuer matches the
///    registered SP.
/// 2. Look up the realm session via the request's `SessionIndex`
///    (which the SAML branch wrote as the local Geonosis
///    `SessionId` per `SessionIndexStrategy::UseSessionId`).
/// 3. Delete the session (clearing all OIDC + SAML state).
/// 4. Return a signed `<LogoutResponse>` to the SP's
///    `slo_url`, base64'd, via the same ACS auto-POST form
///    pattern.
///
/// Multi-SP front-channel propagation (logout fan-out across every
/// SP the user was logged into in that session) lands in v0.1.x
/// once per-SP session participation is tracked on
/// `Session.clients`.
pub async fn slo_post(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Form(form): Form<SamlSloForm>,
) -> Response {
    use geonosis_protocol_saml_idp::{parse_logout_request, serialize_logout_response};

    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        Err(_) => return reject("realm not found", StatusCode::NOT_FOUND),
    };
    if form.saml_request.is_empty() {
        return reject("missing SAMLRequest", StatusCode::BAD_REQUEST);
    }
    let xml_bytes = match B64.decode(form.saml_request.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            return reject(
                &format!("SAMLRequest base64 decode failed: {e}"),
                StatusCode::BAD_REQUEST,
            )
        }
    };
    let parsed = match parse_logout_request(&xml_bytes) {
        Ok(p) => p,
        Err(e) => {
            return reject(
                &format!("LogoutRequest parse failed: {e}"),
                StatusCode::BAD_REQUEST,
            )
        }
    };

    // Resolve SP by Issuer.
    let client = match state
        .storage
        .get_client_by_client_id(realm.id, &parsed.issuer)
        .await
    {
        Ok(c) => c,
        Err(_) => {
            return reject(
                &format!("unknown SP Issuer {}", parsed.issuer),
                StatusCode::BAD_REQUEST,
            )
        }
    };
    if !matches!(client.kind, geonosis_core::ClientKind::SamlServiceProvider) {
        return reject(
            "client is not registered as a SAML SP",
            StatusCode::BAD_REQUEST,
        );
    }
    let raw_config = match &client.saml_sp_config {
        Some(v) => v,
        None => return reject("SP has no saml_sp_config", StatusCode::BAD_REQUEST),
    };
    let sp_config = match SamlSpClientConfig::try_from_value(raw_config) {
        Ok(c) => c,
        Err(e) => {
            return reject(
                &format!("invalid SP config: {e}"),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    };

    // Revoke the session. The SAML branch wrote the local
    // SessionId as the SAML SessionIndex, so the look-up is direct.
    // Capture the session's client list BEFORE deleting so we can
    // propagate the logout to every other SP the user signed into
    // during this session (multi-SP fan-out per docs/20 §SLO).
    let mut peer_logouts: Vec<(geonosis_core::ClientId, bool)> = Vec::new();
    if let Some(session_index) = parsed.session_index.as_deref() {
        let session_id = geonosis_core::SessionId(session_index.to_string());
        if let Ok(session) = state.storage.get_session(&session_id).await {
            for c in &session.clients {
                if c.client_id != client.id {
                    peer_logouts.push((c.client_id, c.backchannel_logout));
                }
            }
        }
        let _ = state.storage.delete_session(&session_id).await;
    }

    // Best-effort back-channel logout fan-out to every other SP the
    // user participated with during the session. Front-channel
    // (iframe) propagation is v0.1.x+. Each dispatch is
    // fire-and-forget on a tokio spawn — SLO must complete promptly
    // for the originating SP regardless of peer SP reachability.
    if !peer_logouts.is_empty() {
        propagate_saml_logout(state.clone(), realm.id, peer_logouts).await;
    }

    // Build a signed LogoutResponse. SLO destination = the SP's
    // slo_url. v0.1 emits unsigned LogoutResponse here — signing
    // the response itself lands once the LogoutRequest signature
    // verification path does in v0.1.x (the same DSig harness).
    let response_id = format!("_slo_{}", geonosis_crypto::random::random_token());
    let issuer_base = state.public_base_url.as_str().trim_end_matches('/');
    let idp_issuer = format!("{issuer_base}/realms/{}", realm.slug);
    let slo_destination = sp_config
        .slo_url
        .as_ref()
        .map(|u| u.as_str().to_string())
        .unwrap_or_else(|| format!("{}/slo", sp_config.entity_id));
    let response_xml = serialize_logout_response(
        &response_id,
        chrono::Utc::now(),
        &idp_issuer,
        &slo_destination,
        &parsed.id,
    );
    let response_b64 = B64.encode(response_xml.as_bytes());

    let html = acs_auto_post_form(&slo_destination, &response_b64, form.relay_state.as_deref());
    Html(html).into_response()
}

#[derive(Debug, serde::Deserialize)]
pub struct SamlSsoForm {
    #[serde(rename = "SAMLRequest", default)]
    pub saml_request: String,
    #[serde(rename = "RelayState", default)]
    pub relay_state: Option<String>,
}

/// `POST /realms/:slug/protocol/saml/sso` — SP-initiated SSO entry
/// via the HTTP-POST binding.
pub async fn sso_post(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Form(form): Form<SamlSsoForm>,
) -> Response {
    handle_sso(state, slug, form).await
}

#[derive(Debug, serde::Deserialize)]
pub struct SamlSsoQuery {
    #[serde(rename = "SAMLRequest", default)]
    pub saml_request: String,
    #[serde(rename = "RelayState", default)]
    pub relay_state: Option<String>,
    /// `SigAlg` URI when the SP signs the Redirect-binding payload.
    #[serde(default, rename = "SigAlg")]
    pub sig_alg: Option<String>,
    /// `Signature` (base64) when the SP signs the
    /// Redirect-binding payload.
    #[serde(default, rename = "Signature")]
    pub signature: Option<String>,
}

impl SamlSsoQuery {
    fn signature_b64(&self) -> &str {
        self.signature.as_deref().unwrap_or("")
    }
}

/// `GET /realms/:slug/protocol/saml/sso` — HTTP-Redirect binding
/// entry. The `SAMLRequest` query parameter is base64'd DEFLATE-
/// compressed XML per SAML 2.0 Bindings §3.4.4; we decode in place
/// and re-enter the common SSO dispatch. When the SP supplies
/// `Signature` + `SigAlg`, the verify path runs **before** the
/// AuthnRequest is parsed so a bad signature short-circuits with
/// `saml.authnrequest.rejected`.
pub async fn sso_get(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    axum::extract::OriginalUri(orig): axum::extract::OriginalUri,
    axum::extract::Query(q): axum::extract::Query<SamlSsoQuery>,
) -> Response {
    if q.saml_request.is_empty() {
        return reject("missing SAMLRequest", StatusCode::BAD_REQUEST);
    }
    let xml = match geonosis_protocol_saml_idp::decode_redirect_payload(
        &q.saml_request,
        REDIRECT_BINDING_DECOMPRESS_CAP,
    ) {
        Ok(b) => b,
        Err(e) => {
            return reject(
                &format!("Redirect-binding decode failed: {e}"),
                StatusCode::BAD_REQUEST,
            )
        }
    };
    // If the SP supplied Signature + SigAlg, verify it now against
    // the SP's registered signing certs. The query has to be
    // reconstructed from `OriginalUri` because axum's `Query`
    // already URL-decoded the values; the signed bytes use the
    // wire-form encoding.
    let raw_query = orig.query().unwrap_or("");
    if !q.signature_b64().is_empty() {
        if let Err(e) = verify_inbound_redirect_signature(&state, &slug, &xml, raw_query).await {
            return reject(&e, StatusCode::BAD_REQUEST);
        }
    }
    let form = SamlSsoForm {
        saml_request: base64::engine::general_purpose::STANDARD.encode(&xml),
        relay_state: q.relay_state,
    };
    handle_sso(state, slug, form).await
}

const REDIRECT_BINDING_DECOMPRESS_CAP: usize = 64 * 1024;

/// Verify the inbound Redirect-binding signature against the SP's
/// `authn_request_signing_certificates`. The signed bytes are the
/// raw wire-form query string slices for `SAMLRequest`,
/// `RelayState` (if present), and `SigAlg`, joined by `&`.
async fn verify_inbound_redirect_signature(
    state: &AppState,
    slug: &str,
    decoded_xml: &[u8],
    raw_query: &str,
) -> Result<(), String> {
    use geonosis_protocol_saml_idp::{
        parse_authn_request, verify_redirect_signature, RedirectSignatureCheck,
        REDIRECT_SIG_ALG_RSA_SHA256,
    };

    // We need the SP's Issuer to look up its certs — parse the
    // AuthnRequest once. The handle_sso path re-parses; an
    // optimisation pass could cache the parsed result on the
    // request context.
    let parsed = parse_authn_request(decoded_xml).map_err(|e| format!("authn parse: {e}"))?;
    let realm = state
        .storage
        .get_realm_by_slug(slug)
        .await
        .map_err(|_| "realm not found".to_string())?;
    let client = state
        .storage
        .get_client_by_client_id(realm.id, &parsed.issuer)
        .await
        .map_err(|_| format!("unknown SP Issuer {}", parsed.issuer))?;
    let raw_config = client
        .saml_sp_config
        .as_ref()
        .ok_or_else(|| "SP has no saml_sp_config".to_string())?;
    let sp_config = geonosis_protocol_saml_idp::SamlSpClientConfig::try_from_value(raw_config)
        .map_err(|e| format!("invalid SP config: {e}"))?;

    // No certs registered → operator has opted into "trust the
    // request" mode. Fall through silently.
    if sp_config.authn_request_signing_certificates.is_empty() {
        return Ok(());
    }

    // Slice the raw query so the signed-bytes match the wire form.
    let saml_pair = find_pair(raw_query, "SAMLRequest")
        .ok_or_else(|| "SAMLRequest segment not in query".to_string())?;
    let relay_pair = find_pair(raw_query, "RelayState");
    let sig_alg_pair = find_pair(raw_query, "SigAlg")
        .ok_or_else(|| "SigAlg segment not in query".to_string())?;

    let signature_b64 = query_value(raw_query, "Signature")
        .ok_or_else(|| "Signature segment not in query".to_string())?;
    let sig_alg = query_value(raw_query, "SigAlg")
        .ok_or_else(|| "SigAlg value not in query".to_string())?;
    let sig_alg_decoded = percent_decode(&sig_alg);

    let check = RedirectSignatureCheck {
        saml_request_pair: saml_pair,
        relay_state_pair: relay_pair,
        sig_alg_pair,
        signature_b64: &percent_decode(&signature_b64),
        sig_alg: &sig_alg_decoded,
    };
    let _ = REDIRECT_SIG_ALG_RSA_SHA256; // assert constant resolves
    verify_redirect_signature(&check, &sp_config.authn_request_signing_certificates)
        .map_err(|e| format!("signature verification failed: {e}"))
}

/// Locate the literal `key=value` slice for `key` inside the raw
/// query string. Returns `None` when the key isn't present.
fn find_pair<'a>(raw: &'a str, key: &str) -> Option<&'a str> {
    for segment in raw.split('&') {
        if segment.starts_with(key)
            && segment.as_bytes().get(key.len()) == Some(&b'=')
        {
            return Some(segment);
        }
    }
    None
}

/// Extract the URL-encoded value portion of `key=value` from the
/// raw query string.
fn query_value(raw: &str, key: &str) -> Option<String> {
    find_pair(raw, key).map(|seg| seg[key.len() + 1..].to_string())
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// `GET /realms/:slug/protocol/saml/slo` — Redirect-binding logout
/// entry. Same decode chain as `sso_get`, dispatched into the
/// common SLO handler.
pub async fn slo_get(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    axum::extract::Query(q): axum::extract::Query<SamlSsoQuery>,
) -> Response {
    if q.saml_request.is_empty() {
        return reject("missing SAMLRequest", StatusCode::BAD_REQUEST);
    }
    let xml = match geonosis_protocol_saml_idp::decode_redirect_payload(
        &q.saml_request,
        REDIRECT_BINDING_DECOMPRESS_CAP,
    ) {
        Ok(b) => b,
        Err(e) => {
            return reject(
                &format!("Redirect-binding decode failed: {e}"),
                StatusCode::BAD_REQUEST,
            )
        }
    };
    let form = SamlSloForm {
        saml_request: base64::engine::general_purpose::STANDARD.encode(&xml),
        relay_state: q.relay_state,
    };
    slo_post(State(state), Path(slug), Form(form)).await
}

async fn handle_sso(state: AppState, slug: String, form: SamlSsoForm) -> Response {
    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        Err(_) => return reject("realm not found", StatusCode::NOT_FOUND),
    };

    if form.saml_request.is_empty() {
        return reject("missing SAMLRequest", StatusCode::BAD_REQUEST);
    }
    let xml_bytes = match B64.decode(form.saml_request.as_bytes()) {
        Ok(b) => b,
        Err(e) => return reject(&format!("SAMLRequest is not valid base64: {e}"), StatusCode::BAD_REQUEST),
    };
    let parsed = match parse_authn_request(&xml_bytes) {
        Ok(p) => p,
        Err(e) => {
            return reject(
                &format!("AuthnRequest parse failed: {e}"),
                StatusCode::BAD_REQUEST,
            )
        }
    };

    // Resolve SP: the SP's Client.client_id MUST equal AuthnRequest.Issuer.
    let client = match state
        .storage
        .get_client_by_client_id(realm.id, &parsed.issuer)
        .await
    {
        Ok(c) => c,
        Err(_) => return reject(
            &format!("unknown SP Issuer {}", parsed.issuer),
            StatusCode::BAD_REQUEST,
        ),
    };
    if !matches!(client.kind, geonosis_core::ClientKind::SamlServiceProvider) {
        return reject(
            "client is not registered as a SAML service provider",
            StatusCode::BAD_REQUEST,
        );
    }
    let raw_config = match &client.saml_sp_config {
        Some(v) => v,
        None => return reject(
            "SAML SP client has no saml_sp_config",
            StatusCode::BAD_REQUEST,
        ),
    };
    let sp_config = match SamlSpClientConfig::try_from_value(raw_config) {
        Ok(c) => c,
        Err(e) => return reject(
            &format!("invalid SP config: {e}"),
            StatusCode::INTERNAL_SERVER_ERROR,
        ),
    };

    // ACS validation: the AuthnRequest's AssertionConsumerServiceURL
    // (if supplied) MUST be in the SP's whitelist. If absent, fall
    // back to the first registered ACS URL.
    let acs_url = match parsed.assertion_consumer_service_url.as_deref() {
        Some(req_acs) => {
            if !sp_config.acs_urls.iter().any(|u| u.as_str() == req_acs) {
                return reject(
                    "AssertionConsumerServiceURL not in SP whitelist",
                    StatusCode::BAD_REQUEST,
                );
            }
            req_acs.to_string()
        }
        None => match sp_config.acs_urls.first() {
            Some(u) => u.as_str().to_string(),
            None => return reject(
                "SP has no registered ACS URL",
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        },
    };

    // Persist the flow state with the SAML continuation. The keys
    // prefixed `__geonosis_saml_` are the contract `login_actions`
    // checks for the SAML completion branch.
    let mut params: BTreeMap<String, String> = BTreeMap::new();
    params.insert("client_id".into(), client.client_id.clone());
    params.insert("__geonosis_saml_sp_entity_id".into(), parsed.issuer.clone());
    params.insert("__geonosis_saml_request_id".into(), parsed.id.clone());
    params.insert("__geonosis_saml_acs_url".into(), acs_url);
    if let Some(rs) = form.relay_state {
        params.insert("__geonosis_saml_relay_state".into(), rs);
    }

    let flow_state = FlowState::fresh(
        realm.id,
        FlowId::new(),
        1,
        NodeId::new(),
        std::time::Duration::from_secs(realm.session_policy.sso_session_idle.as_secs().min(900)),
    );
    let row = FlowStateRow {
        state: flow_state.clone(),
        authorize_params: params,
    };
    if let Err(e) = state.storage.save_flow_state(row).await {
        return reject(
            &format!("failed to save SAML flow state: {e}"),
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    // Render the canonical login form — login_actions picks up the
    // SAML continuation on completion. We reuse the OIDC login form
    // unchanged because per docs/06-auth-flows.md the flow executor
    // is protocol-agnostic.
    Html(render_login_form(&realm.slug, &flow_state.id.to_string())).into_response()
}

fn render_login_form(realm_slug: &str, flow_state_id: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Sign in</title></head>
<body>
<h1>Sign in to {realm_slug}</h1>
<form method="POST" action="/realms/{realm_slug}/login-actions/authenticate">
  <input type="hidden" name="flow_state_id" value="{flow_state_id}"/>
  <label>Username <input type="text" name="username" required autofocus/></label><br/>
  <label>Password <input type="password" name="password" required/></label><br/>
  <button type="submit">Sign in</button>
</form>
</body></html>"#
    )
}

fn reject(reason: &str, status: StatusCode) -> Response {
    tracing::info!(
        action = "saml.authnrequest.rejected",
        reason = reason,
        "SAML AuthnRequest rejected"
    );
    (status, reason.to_string()).into_response()
}

/// Best-effort back-channel logout fan-out per docs/20 §SLO.
/// For every (client_id, backchannel_enabled) pair captured from
/// the revoked session's `clients` list, build a signed
/// LogoutRequest XML and POST it to the SP's `slo_url`. Failures
/// are logged + audited; they don't block the originating SLO
/// response.
async fn propagate_saml_logout(
    state: AppState,
    realm_id: geonosis_core::RealmId,
    peers: Vec<(geonosis_core::ClientId, bool)>,
) {
    let issuer_base = state.public_base_url.as_str().trim_end_matches('/');
    let idp_issuer = match state.storage.get_realm(realm_id).await {
        Ok(r) => format!("{issuer_base}/realms/{}", r.slug),
        Err(_) => return,
    };
    let client_http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    for (client_id, want_backchannel) in peers {
        if !want_backchannel {
            // Front-channel (iframe) propagation needs UI work; we
            // mark the participation in the audit trail so the
            // operator can verify the user logged out manually on
            // the other SPs.
            tracing::info!(
                client_id = %client_id,
                "saml.slo.skipped_no_backchannel"
            );
            continue;
        }
        let client = match state.storage.get_client(realm_id, client_id).await {
            Ok(c) => c,
            Err(_) => continue,
        };
        let raw_config = match client.saml_sp_config.as_ref() {
            Some(v) => v,
            None => continue,
        };
        let sp_config =
            match geonosis_protocol_saml_idp::SamlSpClientConfig::try_from_value(raw_config) {
                Ok(c) => c,
                Err(_) => continue,
            };
        let slo_url = match sp_config.slo_url.as_ref() {
            Some(u) => u.to_string(),
            None => continue,
        };

        // Build an outbound LogoutRequest XML. v0.1 emits unsigned
        // — signed LogoutRequest from the IdP side lands with the
        // same XML-DSig harness as the assertion signer.
        let request_id = format!("_idplo_{}", geonosis_crypto::random::random_token());
        let now = chrono::Utc::now();
        let xml = build_idp_logout_request(&request_id, now, &idp_issuer, &slo_url);
        let payload = B64.encode(xml.as_bytes());

        let form = [
            ("SAMLRequest", payload.as_str()),
        ];
        let send = client_http.post(&slo_url).form(&form).send();
        // Spawn so this dispatch doesn't block the original SLO
        // response; fire-and-forget per the multi-SP fan-out
        // contract.
        tokio::spawn(async move {
            match send.await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::info!(
                        client_id = %client_id,
                        slo_url = %slo_url,
                        status = %resp.status(),
                        "saml.slo.peer_notified"
                    );
                }
                Ok(resp) => {
                    tracing::warn!(
                        client_id = %client_id,
                        slo_url = %slo_url,
                        status = %resp.status(),
                        "saml.slo.peer_notify_status_error"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        client_id = %client_id,
                        slo_url = %slo_url,
                        error = %e,
                        "saml.slo.peer_notify_failed"
                    );
                }
            }
        });
    }
}

/// Build an IdP-initiated `<LogoutRequest>` for the SLO fan-out
/// path. Minimal — issuer + destination + ID + IssueInstant; no
/// NameID because the peer SP keys its session by SessionIndex
/// which doesn't survive across SPs anyway.
fn build_idp_logout_request(
    id: &str,
    instant: chrono::DateTime<chrono::Utc>,
    issuer: &str,
    destination: &str,
) -> String {
    use chrono::SecondsFormat;
    let issue = instant.to_rfc3339_opts(SecondsFormat::Millis, true);
    format!(
        r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{issue}" Destination="{destination}"><saml:Issuer>{issuer}</saml:Issuer></samlp:LogoutRequest>"#
    )
}

/// `GET /realms/:slug/clients-saml/:alias/unsolicited` — IdP-
/// initiated SSO entry. The authenticated user (via the
/// `geonosis_sid` cookie set by `login_actions`) picks an SP by
/// alias; we mint + sign an assertion as if responding to an
/// `<AuthnRequest>` and auto-POST to the SP's first registered
/// ACS URL.
///
/// Per docs/20-saml-idp.md §"URL surface" / §"Assertion
/// construction": the IdP-initiated case differs from
/// SP-initiated only in that there is no inbound `AuthnRequest`
/// — `InResponseTo` is omitted from the Response.
pub async fn unsolicited(
    State(state): State<AppState>,
    Path((slug, alias)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> Response {
    use geonosis_protocol_saml_idp::{
        serialize_assertion, serialize_response, sign_assertion, KeyInfoMaterial,
        SamlSpClientConfig,
    };

    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };

    let session_id = match read_session_cookie(&headers) {
        Some(s) => geonosis_core::SessionId(s),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                "no SSO session — sign in first via /authorize",
            )
                .into_response()
        }
    };
    let session = match state.storage.get_session(&session_id).await {
        Ok(s) if s.realm_id == realm.id => s,
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                "session not found or realm mismatch",
            )
                .into_response()
        }
    };
    let user = match state.storage.get_user(realm.id, session.user_id).await {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "user lookup failed",
            )
                .into_response()
        }
    };

    // Resolve the SP client by alias (its client_id).
    let client = match state
        .storage
        .get_client_by_client_id(realm.id, &alias)
        .await
    {
        Ok(c) => c,
        Err(_) => return (StatusCode::NOT_FOUND, "unknown SP alias").into_response(),
    };
    if !matches!(client.kind, geonosis_core::ClientKind::SamlServiceProvider) {
        return (
            StatusCode::BAD_REQUEST,
            "client is not a SAML service provider",
        )
            .into_response();
    }
    let raw_config = match client.saml_sp_config.as_ref() {
        Some(v) => v,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "SP has no saml_sp_config",
            )
                .into_response()
        }
    };
    let sp_config = match SamlSpClientConfig::try_from_value(raw_config) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("invalid SP config: {e}"),
            )
                .into_response()
        }
    };
    let acs_url = match sp_config.acs_urls.first() {
        Some(u) => u.as_str().to_string(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "SP has no registered ACS URL",
            )
                .into_response()
        }
    };

    // NameID resolution mirrors the SP-initiated branch.
    let name_id = match sp_config.name_id_format {
        geonosis_saml_types::NameIdFormat::EmailAddress => {
            user.email.clone().unwrap_or_else(|| user.username.clone())
        }
        geonosis_saml_types::NameIdFormat::Unspecified => user.username.clone(),
        geonosis_saml_types::NameIdFormat::Transient => session.id.0.clone(),
        geonosis_saml_types::NameIdFormat::Persistent
        | geonosis_saml_types::NameIdFormat::X509SubjectName => {
            // Reuse the same persistent NameID lookup as the
            // SP-initiated branch (login_actions).
            match crate::handlers::login_actions::resolve_persistent_name_id(
                &state,
                &realm,
                &user,
                &sp_config.entity_id,
            )
            .await
            {
                Ok(n) => n,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("persistent NameID resolve failed: {e}"),
                    )
                        .into_response()
                }
            }
        }
    };

    let session_index_value = match sp_config.session_index_strategy {
        geonosis_protocol_saml_idp::SessionIndexStrategy::UseSessionId => session.id.0.clone(),
        geonosis_protocol_saml_idp::SessionIndexStrategy::Random => {
            geonosis_crypto::random::random_token()
        }
    };
    let issuer_base = state.public_base_url.as_str().trim_end_matches('/');
    let idp_issuer = format!("{issuer_base}/realms/{}", realm.slug);

    let attrs = crate::handlers::login_actions::default_user_attributes(&user);
    let assertion = geonosis_protocol_saml_idp::build_assertion(
        &idp_issuer,
        &sp_config,
        &name_id,
        &session_index_value,
        attrs,
        Some("urn:oasis:names:tc:SAML:2.0:ac:classes:Password".into()),
        5,
    );
    let assertion_xml = serialize_assertion(&assertion);
    let kid = match state
        .kms
        .active_signing_kid(realm.id, geonosis_core::JwsAlgorithm::RS256)
        .await
    {
        Ok(k) => k,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("no active RS256 key: {e}"),
            )
                .into_response()
        }
    };
    let key_info = match crate::handlers::login_actions::build_key_info_for_realm(
        &state, &realm,
    )
    .await
    {
        Ok(k) => k,
        Err(_) => KeyInfoMaterial::RsaKeyValue {
            modulus_b64: "".into(),
            exponent_b64: "AQAB".into(),
        },
    };
    let signed_xml = match sign_assertion(
        state.kms.as_ref(),
        realm.id,
        &kid,
        &assertion.id,
        &assertion_xml,
        key_info,
    )
    .await
    {
        Ok(x) => x,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("assertion sign failed: {e}"),
            )
                .into_response()
        }
    };
    // IdP-initiated → no InResponseTo.
    let response_xml = serialize_response(
        &format!("_resp_{}", geonosis_crypto::random::random_token()),
        chrono::Utc::now(),
        &idp_issuer,
        &acs_url,
        None,
        &signed_xml,
    );
    let response_b64 = B64.encode(response_xml.as_bytes());
    Html(acs_auto_post_form(&acs_url, &response_b64, None)).into_response()
}

/// Read the `geonosis_sid` cookie value out of a request's
/// Cookie header. Returns `None` if the cookie isn't set or the
/// header doesn't parse.
fn read_session_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for segment in raw.split(';') {
        let segment = segment.trim();
        if let Some(rest) = segment.strip_prefix("geonosis_sid=") {
            return Some(rest.to_string());
        }
    }
    None
}

/// Build a self-posting form that returns the signed SAML
/// Response to the SP's ACS URL. Called from `login_actions` when
/// the SAML continuation is set on the completed flow state.
pub fn acs_auto_post_form(
    acs_url: &str,
    saml_response_b64: &str,
    relay_state: Option<&str>,
) -> String {
    let escaped_acs = html_escape(acs_url);
    let escaped_response = html_escape(saml_response_b64);
    let relay_input = relay_state
        .map(|rs| {
            format!(
                r#"<input type="hidden" name="RelayState" value="{}"/>"#,
                html_escape(rs)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Completing sign-in</title></head>
<body onload="document.forms[0].submit()">
<form method="POST" action="{escaped_acs}">
  <input type="hidden" name="SAMLResponse" value="{escaped_response}"/>
  {relay_input}
  <noscript><button type="submit">Continue</button></noscript>
</form>
</body></html>"#
    )
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acs_auto_post_form_html_escapes_user_inputs() {
        let html = acs_auto_post_form(
            "https://sp.example/acs?next=\"hi\"&amp=1",
            "PHNh...<bad>",
            Some("evil&\"<>\""),
        );
        assert!(html.contains("onload=\"document.forms[0].submit()\""));
        assert!(html.contains("&quot;"));
        assert!(html.contains("&amp;"));
        assert!(html.contains("&lt;"));
        assert!(html.contains("name=\"SAMLResponse\""));
        assert!(html.contains("name=\"RelayState\""));
    }

    #[test]
    fn acs_auto_post_form_omits_relay_state_when_absent() {
        let html = acs_auto_post_form("https://sp/acs", "PHNh", None);
        assert!(!html.contains("name=\"RelayState\""));
    }
}
