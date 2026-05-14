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
