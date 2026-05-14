//! `/realms/{slug}/login-actions/authenticate` — accepts the form
//! submission from the rendered login page (see `authorize.rs`) and
//! advances the realm's browser flow. Successful completion mints an
//! authorization code and redirects.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use chrono::{Duration as ChronoDuration, Utc};

use geonosis_crypto::KeyManagementService;

use geonosis_core::token::{CodeChallenge, CodeChallengeMethod, CodeGrant};
use geonosis_core::{AuthnLevel, CodeId, ScopeName, Session, SessionId};
use geonosis_core::scope::parse_scope_string;
use geonosis_flow::{
    compile, AuthnDispatcher, FlowError, FlowExecutor, StepInput, StepOutput,
};
use geonosis_flow::executor::DefaultExecutor;

use crate::flow_runtime::BuiltinAuthnDispatcher;
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
    let mut row = match state.storage.get_flow_state(&flow_state_id).await {
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

    // Resolve the realm's browser flow. The audit found the executor
    // dispatch chain was un-wired; B5c closes that by routing every
    // login form submission through DefaultExecutor +
    // BuiltinAuthnDispatcher → BuiltinAuthenticators.dispatch.
    let definition = match state
        .storage
        .get_auth_flow_by_alias(realm.id, geonosis_flow::builtin::alias::BROWSER)
        .await
    {
        Ok(d) => d,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "realm has no `browser` flow installed; seed via geonosis_flow::builtin::v0_1_flows on realm create",
            )
                .into_response()
        }
    };
    let compiled = match compile(definition) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("flow compile failed: {e}"),
            )
                .into_response()
        }
    };

    // Reconcile the stored flow_state's current_node with the loaded
    // graph. authorize.rs currently creates the flow_state with a
    // sentinel NodeId because admin-managed flow binding isn't wired
    // yet; if the stored node isn't in the compiled graph we
    // re-anchor at the flow's start. Once authorize.rs looks up the
    // real flow at /authorize time this block becomes a no-op.
    if !compiled.by_id.contains_key(&row.state.current_node) {
        row.state.current_node = compiled.definition.start;
        row.state.flow_id = compiled.definition.id;
        row.state.flow_version = compiled.definition.version;
    }

    // Populate FlowContext fields the dispatcher needs.
    let client_id = match row.authorize_params.get("client_id") {
        Some(c) => c.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "missing client_id in flow state",
            )
                .into_response()
        }
    };
    row.state.context.client_id = Some(client_id);
    row.state.context.username = Some(form.username.clone());

    // Form fields the password authenticator expects.
    let mut submit: BTreeMap<String, String> = BTreeMap::new();
    submit.insert("username".into(), form.username.clone());
    submit.insert("password".into(), form.password.clone());

    let dispatcher: Arc<dyn AuthnDispatcher> = Arc::new(BuiltinAuthnDispatcher::new(
        state.authenticators.clone(),
        state.storage.clone(),
        state.refresh_hash_key,
        state.providers.clone(),
        state.wasm_engine.clone(),
    ));
    let executor = DefaultExecutor::new(dispatcher);

    let outcome = match executor
        .step(&compiled, &mut row.state, StepInput::Submit(submit))
        .await
    {
        Ok(o) => o,
        Err(FlowError::Expired) => {
            let _ = state.storage.delete_flow_state(&flow_state_id).await;
            return (StatusCode::BAD_REQUEST, "flow state expired").into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("flow step failed: {e}"),
            )
                .into_response()
        }
    };

    match outcome {
        StepOutput::Done(_) => mint_code_and_redirect(&state, &realm, &row).await,
        StepOutput::Failed(_) => {
            (StatusCode::UNAUTHORIZED, "invalid username or password").into_response()
        }
        StepOutput::Render(_) | StepOutput::Redirect(_) => {
            // Flow needs another step (e.g. OTP, broker redirect).
            // Persist the advanced flow_state so the next request can
            // resume. v0.1 baseline returns 200 with a hint; the
            // visual multi-step renderer lands with Phase 3 Leptos UI.
            if let Err(e) = state.storage.save_flow_state(row).await {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("flow_state save failed: {e}"),
                )
                    .into_response();
            }
            (StatusCode::OK, "flow step accepted; resume").into_response()
        }
    }
}

/// Mint the authorization code + session after the flow signals Done.
/// Split out so the success path stays readable.
async fn mint_code_and_redirect(
    state: &AppState,
    realm: &geonosis_core::Realm,
    row: &geonosis_storage::FlowStateRow,
) -> Response {
    let user_id = match row
        .state
        .context
        .user_id
        .as_deref()
        .and_then(|s| s.parse::<geonosis_core::UserId>().ok())
    {
        Some(u) => u,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "flow completed without resolving user_id",
            )
                .into_response()
        }
    };

    let now = Utc::now();
    let session_id = SessionId::new_random();
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
    if let Err(e) = state.storage.create_session(session).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("session create failed: {e}"),
        )
            .into_response();
    }

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
    // SAML branch: if /saml/sso stashed a continuation, mint a
    // signed assertion + return the ACS auto-POST form instead of
    // following the OIDC code-grant path. Per `docs/20-saml-idp.md`
    // §"Assertion construction" — the realm's browser flow runs
    // identically; only the post-auth artefact differs.
    if p.contains_key("__geonosis_saml_request_id") {
        let user = match state.storage.get_user(realm.id, user_id).await {
            Ok(u) => u,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "SAML completion: user lookup failed",
                )
                    .into_response()
            }
        };
        match try_complete_saml(state, realm, &client, &user, p, &session_id).await {
            Some(resp) => {
                let _ = state.storage.delete_flow_state(&row.state.id).await;
                return resp;
            }
            None => {
                // Missing SAML continuation keys despite the flag —
                // fall through to OIDC (defensive).
            }
        }
    }

    let redirect_uri = p.get("redirect_uri").and_then(|s| url::Url::parse(s).ok());
    let redirect_uri = match redirect_uri {
        Some(u) => u,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "missing/invalid redirect_uri in flow state",
            )
                .into_response()
        }
    };
    let scope: Vec<ScopeName> =
        parse_scope_string(p.get("scope").map(String::as_str).unwrap_or(""))
            .unwrap_or_default();
    let code_challenge = p.get("code_challenge").map(|c| CodeChallenge {
        method: CodeChallengeMethod::S256,
        challenge: c.clone(),
    });

    let code = CodeId::new_random();
    let auth_code_lifetime = ChronoDuration::from_std(realm.token_policy.auth_code_lifespan)
        .unwrap_or_else(|_| ChronoDuration::seconds(60));
    // AMR comes from the FlowContext the dispatcher populated. Map
    // String → Amr per the same convention BuiltinAuthnDispatcher
    // uses on the way in.
    let amr: Vec<geonosis_core::Amr> = row
        .state
        .context
        .amr
        .iter()
        .map(|s| {
            serde_json::from_value::<geonosis_core::Amr>(serde_json::Value::String(s.clone()))
                .unwrap_or(geonosis_core::Amr::Custom(s.clone()))
        })
        .collect();
    let grant = CodeGrant {
        code: code.clone(),
        realm_id: realm.id,
        client_id: client.id,
        user_id,
        session_id: session_id.clone(),
        scope,
        redirect_uri: redirect_uri.clone(),
        code_challenge,
        nonce: p.get("nonce").cloned(),
        state: p.get("state").cloned(),
        amr,
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
    let _ = state.storage.delete_flow_state(&row.state.id).await;

    let mut url = redirect_uri;
    url.query_pairs_mut().append_pair("code", code.0.as_str());
    if let Some(s) = p.get("state") {
        url.query_pairs_mut().append_pair("state", s);
    }
    Redirect::to(url.as_str()).into_response()
}

/// Detect a SAML continuation set on the flow state by
/// `handlers::saml::handle_sso`. If present, build + sign the
/// assertion and render the ACS auto-POST form per
/// `docs/20-saml-idp.md` §"Assertion construction". Returns `None`
/// when the request is an OIDC code-grant (no SAML markers in the
/// flow state); the caller falls through to the OIDC redirect path.
async fn try_complete_saml(
    state: &AppState,
    realm: &geonosis_core::Realm,
    client: &geonosis_core::Client,
    user: &geonosis_core::User,
    p: &std::collections::BTreeMap<String, String>,
    session_id: &geonosis_core::SessionId,
) -> Option<axum::response::Response> {
    use axum::response::{Html, IntoResponse};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use geonosis_protocol_saml_idp::{
        serialize_assertion, serialize_response, sign_assertion, KeyInfoMaterial,
        SamlSpClientConfig,
    };

    let saml_request_id = p.get("__geonosis_saml_request_id")?;
    let acs_url = p.get("__geonosis_saml_acs_url")?.clone();
    let relay_state = p.get("__geonosis_saml_relay_state").cloned();

    let raw_config = client.saml_sp_config.as_ref()?;
    let sp_config = match SamlSpClientConfig::try_from_value(raw_config) {
        Ok(c) => c,
        Err(e) => {
            return Some(
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("SAML SP config decode failed: {e}"),
                )
                    .into_response(),
            );
        }
    };

    // NameID: per docs/20 §"NameID strategies". v0.1 ships
    // emailAddress, persistent (transient mapping), unspecified
    // (username). Persistent is now table-backed (see
    // `Storage::get_saml_persistent_id` / `save_saml_persistent_id`)
    // so the same (user, SP) tuple resolves to the same NameID
    // across sessions even after server restarts.
    let name_id = match sp_config.name_id_format {
        geonosis_saml_types::NameIdFormat::EmailAddress => user
            .email
            .clone()
            .unwrap_or_else(|| user.username.clone()),
        geonosis_saml_types::NameIdFormat::Unspecified => user.username.clone(),
        geonosis_saml_types::NameIdFormat::Transient => session_id.0.clone(),
        geonosis_saml_types::NameIdFormat::Persistent
        | geonosis_saml_types::NameIdFormat::X509SubjectName => {
            match resolve_persistent_name_id(state, realm, user, &sp_config.entity_id).await {
                Ok(name) => name,
                Err(e) => {
                    return Some(
                        (
                            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                            format!("persistent NameID resolve failed: {e}"),
                        )
                            .into_response(),
                    );
                }
            }
        }
    };

    let session_index_value = match sp_config.session_index_strategy {
        geonosis_protocol_saml_idp::SessionIndexStrategy::UseSessionId => session_id.0.clone(),
        geonosis_protocol_saml_idp::SessionIndexStrategy::Random => {
            geonosis_crypto::random::random_token()
        }
    };

    let issuer_base = state.public_base_url.as_str().trim_end_matches('/');
    let idp_issuer = format!("{issuer_base}/realms/{}", realm.slug);

    let assertion = geonosis_protocol_saml_idp::build_assertion(
        &idp_issuer,
        &sp_config,
        &name_id,
        &session_index_value,
        vec![], // attribute statements land with mapper SPI wiring (v0.1.x)
        Some("urn:oasis:names:tc:SAML:2.0:ac:classes:Password".into()),
        5,
    );

    let assertion_xml = serialize_assertion(&assertion);

    // Resolve the realm's active RS256 kid + render the key
    // material the SP needs to verify against. v0.1 emits
    // RSAKeyValue (SAML-spec-compliant alternative to
    // X509Certificate) since the metadata-side cert isn't bound to
    // a specific kid yet.
    let kid = match state
        .kms
        .active_signing_kid(realm.id, geonosis_core::JwsAlgorithm::RS256)
        .await
    {
        Ok(k) => k,
        Err(e) => {
            return Some(
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("no active RS256 key: {e}"),
                )
                    .into_response(),
            );
        }
    };

    // Build the KeyInfo body. We try the proper X.509 path first;
    // on failure we fall back to RSAKeyValue so SPs that accept
    // either format keep working.
    let key_info = match build_key_info_for_realm(state, realm).await {
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
            return Some(
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("assertion sign failed: {e}"),
                )
                    .into_response(),
            );
        }
    };

    let response_xml = serialize_response(
        &format!("_resp_{}", geonosis_crypto::random::random_token()),
        chrono::Utc::now(),
        &idp_issuer,
        &acs_url,
        Some(saml_request_id),
        &signed_xml,
    );
    let response_b64 = B64.encode(response_xml.as_bytes());

    let html = crate::handlers::saml::acs_auto_post_form(
        &acs_url,
        &response_b64,
        relay_state.as_deref(),
    );
    Some(Html(html).into_response())
}

/// Mint the `<ds:KeyInfo>` payload for the assertion signature.
/// Tries X.509 cert generation (canonical SAML form) and falls
/// back to RSAKeyValue if cert minting fails.
async fn build_key_info_for_realm(
    state: &AppState,
    realm: &geonosis_core::Realm,
) -> Result<geonosis_protocol_saml_idp::KeyInfoMaterial, String> {
    use geonosis_crypto::cert::{der_to_b64, self_signed_x509_for_rs256};
    use geonosis_crypto::jwt::PrivateMaterial;
    use geonosis_crypto::KeyManagementService;
    use geonosis_protocol_saml_idp::KeyInfoMaterial;

    let kid = state
        .kms
        .active_signing_kid(realm.id, geonosis_core::JwsAlgorithm::RS256)
        .await
        .map_err(|e| e.to_string())?;
    let material = state
        .kms
        .load_private(&kid)
        .await
        .map_err(|e| e.to_string())?;
    let PrivateMaterial::Rs256(rsa) = material else {
        return Err("active key is not RS256".into());
    };
    let der = self_signed_x509_for_rs256(rsa.as_ref(), &realm.slug)
        .map_err(|e| e.to_string())?;
    Ok(KeyInfoMaterial::X509Certificate {
        cert_b64: der_to_b64(&der),
    })
}

/// Resolve (or mint + persist) the persistent SAML NameID for a
/// `(realm, user, SP)` tuple. The mint format is `g_<ULID-base32>`
/// — opaque to the SP, never reveals the underlying user_id.
async fn resolve_persistent_name_id(
    state: &AppState,
    realm: &geonosis_core::Realm,
    user: &geonosis_core::User,
    sp_entity_id: &str,
) -> Result<String, String> {
    if let Some(row) = state
        .storage
        .get_saml_persistent_id(realm.id, user.id, sp_entity_id)
        .await
        .map_err(|e| e.to_string())?
    {
        return Ok(row.name_id);
    }
    // Mint a fresh opaque identifier. ULID is order-preserving in
    // base32 which lets operators eyeball when the SP first started
    // tracking the user.
    let name_id = format!("g_{}", geonosis_core::id::UserId::new());
    let row = geonosis_storage::SamlPersistentIdRow {
        realm_id: realm.id,
        user_id: user.id,
        sp_entity_id: sp_entity_id.to_string(),
        name_id: name_id.clone(),
        created_at: chrono::Utc::now(),
    };
    state
        .storage
        .save_saml_persistent_id(row)
        .await
        .map_err(|e| e.to_string())?;
    Ok(name_id)
}
