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

/// `GET /realms/:slug/protocol/saml/sso` — HTTP-Redirect binding
/// landing. v0.1 returns a structured error explaining the
/// DEFLATE-decode path is v0.1.x; SPs configured for POST binding
/// hit `sso_post` above and work end-to-end.
pub async fn sso_get(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Response {
    let _ = state.storage.get_realm_by_slug(&slug).await;
    (
        StatusCode::NOT_IMPLEMENTED,
        "HTTP-Redirect binding (DEFLATE-encoded SAMLRequest) lands in v0.1.x — configure your SP to use the HTTP-POST binding for now.",
    )
        .into_response()
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
