//! `/realms/{slug}/protocol/openid-connect/auth` — OIDC `/authorize`.
//!
//! Per `docs/03-protocols-oidc.md` §State machine:
//! 1. parse + validate request
//! 2. resolve client + realm
//! 3. enforce client policy (PKCE, redirect-uri exact match)
//! 4. resolve SSO session from browser cookie
//! 5. enforce `prompt` / `max_age` / `id_token_hint` (OIDC Core §3.1.2.1)
//! 6. either shortcircuit (valid session → mint code) or start a flow
//! 7. render the login page (server-side HTML form for v0.1)
//!
//! The login form posts to `/realms/{slug}/login-actions/authenticate`
//! which completes the flow, mints the code, and 302s back to `redirect_uri`
//! with `?code=...&state=...`.

mod sso;

use std::collections::BTreeMap;
use std::time::Duration;

use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};

use geonosis_core::{Client, FlowId, NodeId};
use geonosis_flow::FlowState;
use geonosis_protocol_oidc::{AuthorizeRequest, AuthorizeRequestError};
use geonosis_storage::FlowStateRow;

use crate::state::AppState;

/// `GET /realms/{slug}/protocol/openid-connect/auth`
pub async fn authorize_get(
    Path(slug): Path<String>,
    Query(params): Query<BTreeMap<String, String>>,
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Response {
    handle_authorize(slug, params, headers, state).await
}

/// `POST /realms/{slug}/protocol/openid-connect/auth` — `form_post` mode.
pub async fn authorize_post(
    Path(slug): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(params): Form<BTreeMap<String, String>>,
) -> Response {
    handle_authorize(slug, params, headers, state).await
}

async fn handle_authorize(
    slug: String,
    mut params: BTreeMap<String, String>,
    headers: HeaderMap,
    state: AppState,
) -> Response {
    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        Err(_) => {
            state.metrics.oidc_authorize.inc(&[&slug, "unknown_realm"]);
            return (StatusCode::NOT_FOUND, "realm not found").into_response();
        }
    };
    state.metrics.oidc_authorize.inc(&[&realm.slug, "started"]);

    if params.contains_key("request") {
        return error_redirect(
            &params,
            "request_not_supported",
            "JAR `request` parameter is not yet supported; use PAR instead",
        );
    }

    // Resolve PAR `request_uri` if presented (RFC 9126 §4).
    if let Some(request_uri) = params.remove("request_uri") {
        match state.storage.consume_par_request(&request_uri).await {
            Ok(par) => {
                if par.realm_id != realm.id {
                    return error_redirect(&params, "invalid_request_uri", "realm mismatch");
                }
                params = par.params;
            }
            Err(_) => {
                return error_redirect(
                    &params,
                    "invalid_request_uri",
                    "unknown / expired request_uri",
                );
            }
        }
    }

    let req = match AuthorizeRequest::parse(params.clone()) {
        Ok(r) => r,
        Err(e) => return authorize_error_to_response(&params, &e),
    };

    let client = match state
        .storage
        .get_client_by_client_id(realm.id, &req.client_id)
        .await
    {
        Ok(c) => c,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid_request: unknown client").into_response()
        }
    };
    if !client.enabled {
        return (
            StatusCode::BAD_REQUEST,
            "unauthorized_client: client disabled",
        )
            .into_response();
    }

    if let Err(e) = req.enforce_client_policy(&client) {
        return authorize_error_to_response(&params, &e);
    }

    // ---- SSO session resolution from browser cookie ----
    let sso_session = match sso::extract_session_cookie(&headers) {
        Some(sid) => sso::resolve_session(&state, &sid, realm.id).await,
        None => None,
    };

    // ---- prompt / max_age / id_token_hint (OIDC Core §3.1.2.1) ----
    match sso::enforce_prompt_policy(&req, &sso_session, &realm, &params) {
        sso::PromptDecision::Shortcircuit(session) => {
            return sso::shortcircuit(&state, &realm, &client, session, &params).await;
        }
        sso::PromptDecision::StartFlow(maybe_session) => {
            return start_flow(&state, &realm, &client, &req, &mut params, maybe_session).await;
        }
        sso::PromptDecision::Error { code, description } => {
            return error_redirect(&params, code, description);
        }
    }
}

async fn start_flow(
    state: &AppState,
    realm: &geonosis_core::Realm,
    client: &Client,
    req: &AuthorizeRequest,
    params: &mut BTreeMap<String, String>,
    sso_session: Option<geonosis_core::Session>,
) -> Response {
    if let Some(acr_values) = req.acr_values.as_deref() {
        params.insert("__geonosis_acr_values".into(), acr_values.into());
    }

    let browser_flow = state
        .storage
        .get_auth_flow_by_alias(realm.id, geonosis_flow::builtin::alias::BROWSER)
        .await;
    let (flow_id, flow_version, start_node) = match browser_flow {
        Ok(ref f) => (f.id, f.version, f.start),
        Err(_) => (FlowId::new(), 1, NodeId::new()),
    };

    let mut flow_state = FlowState::fresh(
        realm.id,
        flow_id,
        flow_version,
        start_node,
        Duration::from_secs(realm.session_policy.sso_session_idle.as_secs().min(900)),
    );
    flow_state.context.requested_acr = params.get("__geonosis_acr_values").cloned();
    if let Some(ref session) = sso_session {
        flow_state.context.session_id = Some(session.id.0.clone());
    }

    let row = FlowStateRow {
        state: flow_state.clone(),
        authorize_params: params.clone(),
    };
    if let Err(e) = state.storage.save_flow_state(row).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to save flow state: {e}"),
        )
            .into_response();
    }

    Html(render_login_form(
        &realm.slug,
        &flow_state.id.to_string(),
        client,
    ))
    .into_response()
}

fn render_login_form(slug: &str, flow_state_id: &str, client: &Client) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>Sign in — {client_name}</title>\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<style>body{{font-family:system-ui,sans-serif;max-width:24rem;margin:4rem auto;padding:0 1rem}}\
input,button{{width:100%;padding:.6rem;margin:.4rem 0;font-size:1rem;box-sizing:border-box}}\
button{{background:#1f2937;color:#fff;border:0;border-radius:.25rem;cursor:pointer}}\
h1{{font-size:1.25rem;margin-bottom:1rem}}</style></head><body>\
<h1>Sign in to {client_name}</h1>\
<form method=\"post\" action=\"/realms/{slug}/login-actions/authenticate\">\
<input type=\"hidden\" name=\"flow_state_id\" value=\"{fsid}\">\
<input type=\"text\" name=\"username\" placeholder=\"Username\" autocomplete=\"username\" required autofocus>\
<input type=\"password\" name=\"password\" placeholder=\"Password\" autocomplete=\"current-password\" required>\
<button type=\"submit\">Sign in</button></form></body></html>",
        client_name = html_escape(&client.display_name.clone().unwrap_or_else(|| client.client_id.clone())),
        slug = html_escape(slug),
        fsid = html_escape(flow_state_id),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn authorize_error_to_response(
    params: &BTreeMap<String, String>,
    err: &AuthorizeRequestError,
) -> Response {
    let (code, desc) = match err {
        AuthorizeRequestError::Missing(f) => ("invalid_request", format!("missing parameter: {f}")),
        AuthorizeRequestError::Invalid(f, m) => {
            ("invalid_request", format!("invalid parameter {f}: {m}"))
        }
        AuthorizeRequestError::UnsupportedResponseType => {
            ("unsupported_response_type", err.to_string())
        }
        AuthorizeRequestError::RedirectMismatch => {
            return (StatusCode::BAD_REQUEST, err.to_string()).into_response()
        }
        AuthorizeRequestError::PkceRequired => ("invalid_request", err.to_string()),
        AuthorizeRequestError::PkcePlainRejected => ("invalid_request", err.to_string()),
        AuthorizeRequestError::NonceRequired => ("invalid_request", err.to_string()),
        AuthorizeRequestError::UnsupportedScope(_) => ("invalid_scope", err.to_string()),
    };
    error_redirect(params, code, &desc)
}

pub(crate) fn error_redirect(
    params: &BTreeMap<String, String>,
    code: &str,
    desc: &str,
) -> Response {
    if let Some(redir) = params.get("redirect_uri") {
        if let Ok(mut url) = url::Url::parse(redir) {
            url.query_pairs_mut()
                .append_pair("error", code)
                .append_pair("error_description", desc);
            if let Some(state) = params.get("state") {
                url.query_pairs_mut().append_pair("state", state);
            }
            return axum::response::Redirect::to(url.as_str()).into_response();
        }
    }
    (StatusCode::BAD_REQUEST, format!("{code}: {desc}")).into_response()
}
