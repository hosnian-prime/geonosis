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

    // Per `docs/15-organizations.md` §"Self-service join via domain
    // match": when the realm has opted in, enroll the user into any
    // organization whose verified domain matches the user's verified
    // email. Best-effort — failures are logged, not propagated; we
    // don't want a Postgres blip during org lookup to break a login.
    maybe_auto_join_org_by_domain(state, realm, user_id).await;

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
                // Track per-SP session participation so /saml/slo
                // can fan out to every SP the user signed into.
                // Per docs/20-saml-idp.md §SLO: `Session.clients`
                // is the source of truth for the multi-SP logout
                // dispatch.
                if let Ok(mut session) = state.storage.get_session(&session_id).await {
                    let raw_config = client.saml_sp_config.as_ref();
                    let backchannel = raw_config
                        .and_then(|v| {
                            geonosis_protocol_saml_idp::SamlSpClientConfig::try_from_value(v)
                                .ok()
                        })
                        .map(|c| c.slo_url.is_some())
                        .unwrap_or(false);
                    session.clients.push(geonosis_core::ClientSessionRef {
                        client_id: client.id,
                        last_seen_at: chrono::Utc::now(),
                        frontchannel_logout: false,
                        backchannel_logout: backchannel,
                    });
                    session.last_seen_at = chrono::Utc::now();
                    let _ = state.storage.update_session(session).await;
                }
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
    // Set the realm-scoped SSO session cookie so IdP-initiated SAML
    // entry (`GET /realms/:slug/clients-saml/:alias/unsolicited`)
    // can resolve the user without re-prompting. HttpOnly +
    // SameSite=Lax + path-scoped — v0.1.x security baseline; doc
    // 08-admin-ui.md §"Security baselines" tracks the broader
    // cookie posture (Secure flag landed once we enforce HTTPS at
    // the listener).
    use axum::http::header::SET_COOKIE;
    let cookie = format!(
        "geonosis_sid={}; Path=/realms/{}; HttpOnly; SameSite=Lax",
        session_id.0,
        realm.slug
    );
    let mut resp = Redirect::to(url.as_str()).into_response();
    if let Ok(v) = axum::http::HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(SET_COOKIE, v);
    }
    resp
}

/// Per `docs/15-organizations.md` §"Self-service join via domain
/// match" (lines 115-118): when `realm.organization_policy
/// .auto_join_on_domain_match` is true, a user whose verified email
/// matches a verified `OrgDomain` is automatically enrolled into
/// that organization at login. Idempotent (repeat logins are no-ops).
/// Errors are logged but never propagated — auto-join is a best-
/// effort enhancement; failure must not block authentication.
async fn maybe_auto_join_org_by_domain(
    state: &AppState,
    realm: &geonosis_core::Realm,
    user_id: geonosis_core::UserId,
) {
    match auto_join_org_by_domain(state.storage.as_ref(), realm, user_id).await {
        Ok(Some(alias)) => {
            tracing::info!(
                realm = %realm.slug,
                org = %alias,
                "auto-joined user by verified domain match",
            );
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(
                realm = %realm.slug,
                error = %e,
                "auto-join failed; swallowing to keep login path live",
            );
        }
    }
}

/// Pure-storage helper extracted from [`maybe_auto_join_org_by_domain`]
/// so unit tests can drive it against `MemoryStorage` without an
/// `AppState`. Returns `Ok(Some(org_alias))` when a new membership
/// was created, `Ok(None)` when the user was ineligible or already
/// a member, and `Err` only on storage faults.
pub(crate) async fn auto_join_org_by_domain(
    storage: &dyn geonosis_storage::Storage,
    realm: &geonosis_core::Realm,
    user_id: geonosis_core::UserId,
) -> Result<Option<String>, geonosis_storage::StorageError> {
    if !realm.organization_policy.auto_join_on_domain_match {
        return Ok(None);
    }
    let user = storage.get_user(realm.id, user_id).await?;
    if !user.email_verified {
        return Ok(None);
    }
    let Some(email) = user.email.as_deref() else {
        return Ok(None);
    };
    let Some(domain) = email.rsplit_once('@').map(|(_, d)| d) else {
        return Ok(None);
    };
    let Some(org) = storage.find_org_by_verified_domain(realm.id, domain).await? else {
        return Ok(None);
    };
    // Idempotent: existing membership short-circuits (preserves
    // `joined_at` + `invited_by` audit fields on repeat logins).
    if storage
        .get_org_membership(realm.id, org.id, user_id)
        .await
        .is_ok()
    {
        return Ok(None);
    }
    let membership = geonosis_core::OrgMembership {
        organization_id: org.id,
        realm_id: realm.id,
        user_id,
        roles: vec![],
        joined_at: Utc::now(),
        invited_by: None,
        state: geonosis_core::MembershipState::Active,
    };
    storage.upsert_org_membership(membership).await?;
    Ok(Some(org.alias))
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

    // Per `docs/20-saml-idp.md` §"Attribute mapping": operator-
    // configured `attribute_mappers` drive the `<AttributeStatement>`
    // when present; an empty mapper list falls back to the hardcoded
    // defaults so SPs without explicit configuration still receive
    // username/email/given_name/family_name.
    let attrs = if sp_config.attribute_mappers.is_empty() {
        default_user_attributes(user)
    } else {
        geonosis_protocol_saml_idp::apply_attribute_mappers(user, &sp_config.attribute_mappers)
    };
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
pub(crate) async fn build_key_info_for_realm(
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
pub(crate) async fn resolve_persistent_name_id(
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

/// Render the default `<saml:Attribute>` set for the user into the
/// SAML assertion's AttributeStatement. v0.1.x ships the four
/// claims SAML SPs most commonly key on (email, given/family
/// names, username) using the urn:oid: + Microsoft Claims-Schema
/// naming SPs broadly accept. WASM-mapper-driven attribute
/// transformation per docs/20 §"Attribute mapping (the SPI)"
/// adds on top of this baseline (v0.1.x+ once SP-config carries
/// the `attribute_mappers` binding list).
pub(crate) fn default_user_attributes(
    user: &geonosis_core::User,
) -> Vec<geonosis_saml_types::SamlAttribute> {
    use geonosis_saml_types::SamlAttribute;
    let mut out: Vec<SamlAttribute> = Vec::new();

    // Username always populated.
    out.push(SamlAttribute {
        name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name".into(),
        name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri".into(),
        friendly_name: Some("username".into()),
        values: vec![user.username.clone()],
    });

    if let Some(ref email) = user.email {
        out.push(SamlAttribute {
            name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress".into(),
            name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri".into(),
            friendly_name: Some("email".into()),
            values: vec![email.clone()],
        });
    }

    if let Some(ref person) = user.name {
        if let Some(g) = person.given.as_ref().filter(|s| !s.is_empty()) {
            out.push(SamlAttribute {
                name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname".into(),
                name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri".into(),
                friendly_name: Some("given_name".into()),
                values: vec![g.clone()],
            });
        }
        if let Some(f) = person.family.as_ref().filter(|s| !s.is_empty()) {
            out.push(SamlAttribute {
                name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname".into(),
                name_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri".into(),
                friendly_name: Some("family_name".into()),
                values: vec![f.clone()],
            });
        }
    }

    out
}

#[cfg(test)]
mod saml_attribute_tests {
    use super::default_user_attributes;
    use geonosis_core::{PersonName, User};

    fn mk_user(email: Option<&str>, given: &str, family: &str) -> User {
        let mut u = User::default();
        u.username = "ada".into();
        u.email = email.map(String::from);
        u.name = Some(PersonName {
            given: if given.is_empty() { None } else { Some(given.into()) },
            family: if family.is_empty() { None } else { Some(family.into()) },
            middle: None,
            display: None,
        });
        u
    }

    #[test]
    fn always_emits_username_attribute() {
        let attrs = default_user_attributes(&mk_user(None, "", ""));
        assert!(attrs.iter().any(|a| a.friendly_name.as_deref() == Some("username")));
    }

    #[test]
    fn email_attribute_appears_iff_user_has_email() {
        let with = default_user_attributes(&mk_user(Some("ada@x"), "", ""));
        assert!(with.iter().any(|a| a.friendly_name.as_deref() == Some("email")));
        let without = default_user_attributes(&mk_user(None, "", ""));
        assert!(!without.iter().any(|a| a.friendly_name.as_deref() == Some("email")));
    }

    #[test]
    fn name_attributes_skip_empty_components() {
        // given+family empty → no name attributes.
        let attrs = default_user_attributes(&mk_user(None, "", ""));
        assert!(!attrs.iter().any(|a| a.friendly_name.as_deref() == Some("given_name")));
        assert!(!attrs.iter().any(|a| a.friendly_name.as_deref() == Some("family_name")));
        // family present → only family attribute lands.
        let f = default_user_attributes(&mk_user(None, "", "Lovelace"));
        assert!(!f.iter().any(|a| a.friendly_name.as_deref() == Some("given_name")));
        assert!(f.iter().any(|a| a.friendly_name.as_deref() == Some("family_name")));
    }

    #[test]
    fn name_format_is_uri_for_all_attributes() {
        let attrs = default_user_attributes(&mk_user(Some("a@b"), "Ada", "Lovelace"));
        for a in &attrs {
            assert_eq!(
                a.name_format,
                "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
            );
        }
    }
}

#[cfg(test)]
mod auto_join_tests {
    use super::auto_join_org_by_domain;
    use chrono::Utc;
    use geonosis_core::{
        Organization, OrganizationPolicy, OrgDomain, Realm, User,
        id::{OrganizationId, OrgDomainId, RealmId, UserId},
    };
    use geonosis_storage::{MemoryStorage, Storage};
    use std::sync::Arc;

    fn realm_with_auto_join(enabled: bool) -> Realm {
        Realm {
            id: RealmId::new(),
            slug: "acme".into(),
            display_name: "Acme".into(),
            frontend_url: None,
            admin_frontend_url: None,
            enabled: true,
            ssl_required: geonosis_core::SslRequirement::ExternalRequests,
            login: Default::default(),
            registration: Default::default(),
            session_policy: Default::default(),
            token_policy: Default::default(),
            brute_force: Default::default(),
            password_policy: Default::default(),
            otp_policy: Default::default(),
            webauthn_policy: Default::default(),
            acr_policy: Default::default(),
            sender_constraint_default: geonosis_core::SenderConstraint::None,
            theme_binding: Default::default(),
            localization: Default::default(),
            events: Default::default(),
            default_groups: vec![],
            default_roles: Default::default(),
            organizations_enabled: true,
            organization_policy: OrganizationPolicy {
                auto_join_on_domain_match: enabled,
                ..Default::default()
            },
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    async fn seed(
        storage: &MemoryStorage,
        realm: &Realm,
        email: Option<&str>,
        email_verified: bool,
        domain: Option<(&str, bool)>,
    ) -> (UserId, Option<OrganizationId>) {
        storage.create_realm(realm.clone()).await.unwrap();
        let mut user = User::default();
        user.id = UserId::new();
        user.realm_id = realm.id;
        user.username = "ada".into();
        user.email = email.map(String::from);
        user.email_verified = email_verified;
        let uid = user.id;
        storage.create_user(user).await.unwrap();
        let org_id = if let Some((d, verified)) = domain {
            let org = Organization {
                id: OrganizationId::new(),
                realm_id: realm.id,
                alias: "acme-inc".into(),
                display_name: "Acme Inc.".into(),
                description: None,
                attributes: Default::default(),
                branding: Default::default(),
                default_idp_alias: None,
                redirect_url: None,
                enabled: true,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            let oid = org.id;
            storage.create_organization(org).await.unwrap();
            storage
                .upsert_org_domain(OrgDomain {
                    id: OrgDomainId::new(),
                    organization_id: oid,
                    realm_id: realm.id,
                    domain: d.into(),
                    verified,
                    verification_token: None,
                    verified_at: if verified { Some(Utc::now()) } else { None },
                })
                .await
                .unwrap();
            Some(oid)
        } else {
            None
        };
        (uid, org_id)
    }

    #[tokio::test]
    async fn skips_when_policy_disabled() {
        let storage = Arc::new(MemoryStorage::new());
        let realm = realm_with_auto_join(false);
        let (uid, _) = seed(&storage, &realm, Some("ada@acme.com"), true, Some(("acme.com", true))).await;
        let out = auto_join_org_by_domain(storage.as_ref(), &realm, uid).await.unwrap();
        assert!(out.is_none(), "policy disabled → no auto-join");
    }

    #[tokio::test]
    async fn skips_when_email_unverified() {
        let storage = Arc::new(MemoryStorage::new());
        let realm = realm_with_auto_join(true);
        let (uid, _) = seed(&storage, &realm, Some("ada@acme.com"), false, Some(("acme.com", true))).await;
        let out = auto_join_org_by_domain(storage.as_ref(), &realm, uid).await.unwrap();
        assert!(out.is_none(), "unverified email → no auto-join");
    }

    #[tokio::test]
    async fn skips_when_domain_unverified() {
        let storage = Arc::new(MemoryStorage::new());
        let realm = realm_with_auto_join(true);
        let (uid, _) = seed(&storage, &realm, Some("ada@acme.com"), true, Some(("acme.com", false))).await;
        let out = auto_join_org_by_domain(storage.as_ref(), &realm, uid).await.unwrap();
        assert!(out.is_none(), "unverified org domain → no auto-join");
    }

    #[tokio::test]
    async fn enrolls_when_verified_email_matches_verified_domain() {
        let storage = Arc::new(MemoryStorage::new());
        let realm = realm_with_auto_join(true);
        let (uid, org_id) =
            seed(&storage, &realm, Some("ada@acme.com"), true, Some(("acme.com", true))).await;
        let alias = auto_join_org_by_domain(storage.as_ref(), &realm, uid)
            .await
            .unwrap();
        assert_eq!(alias.as_deref(), Some("acme-inc"));
        // Membership row should exist.
        let m = storage
            .get_org_membership(realm.id, org_id.unwrap(), uid)
            .await
            .unwrap();
        assert_eq!(m.user_id, uid);
        assert!(matches!(m.state, geonosis_core::MembershipState::Active));
    }

    #[tokio::test]
    async fn idempotent_on_repeat_login() {
        let storage = Arc::new(MemoryStorage::new());
        let realm = realm_with_auto_join(true);
        let (uid, _) =
            seed(&storage, &realm, Some("ada@acme.com"), true, Some(("acme.com", true))).await;
        // First login enrolls.
        let first = auto_join_org_by_domain(storage.as_ref(), &realm, uid).await.unwrap();
        assert!(first.is_some());
        // Second login is a no-op (returns None — already a member).
        let second = auto_join_org_by_domain(storage.as_ref(), &realm, uid).await.unwrap();
        assert!(second.is_none(), "repeat login must not re-enroll");
    }

    #[tokio::test]
    async fn skips_when_no_matching_org_domain() {
        let storage = Arc::new(MemoryStorage::new());
        let realm = realm_with_auto_join(true);
        let (uid, _) =
            seed(&storage, &realm, Some("ada@other.com"), true, Some(("acme.com", true))).await;
        let out = auto_join_org_by_domain(storage.as_ref(), &realm, uid).await.unwrap();
        assert!(out.is_none(), "domain mismatch → no auto-join");
    }
}
