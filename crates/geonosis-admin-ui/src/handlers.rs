//! Public admin handlers: assets, login, logout.
//!
//! The admin pages themselves are rendered by `leptos_ui::router`.
//! This module owns the unauthenticated surface (login form, asset
//! serving, logout cookie-clearing) plus the few helpers that the
//! sign-in flow needs.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::state::AdminState;

#[derive(Debug, Deserialize)]
pub struct LangQuery {
    #[serde(default)]
    pub lang: Option<String>,
}

pub async fn admin_css() -> Response {
    let body = geonosis_ui_kit::TOKENS_CSS;
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], body).into_response()
}

/// `/static/admin-chrome.js` — theme toggle, mobile drawer, realm
/// selector. ~2 KB of carefully scoped code that the admin shell
/// needs across every page.
pub async fn admin_chrome_js() -> Response {
    let body = crate::assets::AdminAssets::get("admin-chrome.js")
        .map(|f| f.data.into_owned())
        .unwrap_or_default();
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

/// `/static/logo.svg` — Geonosis planet logo.
pub async fn admin_logo_svg() -> Response {
    let body = crate::assets::AdminAssets::get("logo.svg")
        .map(|f| f.data.into_owned())
        .unwrap_or_default();
    ([(header::CONTENT_TYPE, "image/svg+xml")], body).into_response()
}

/// `/static/favicon.svg` — browser tab icon.
pub async fn admin_favicon_svg() -> Response {
    let body = crate::assets::AdminAssets::get("favicon.svg")
        .map(|f| f.data.into_owned())
        .unwrap_or_default();
    ([(header::CONTENT_TYPE, "image/svg+xml")], body).into_response()
}

/// Serve an embedded JS asset with the correct content-type.
fn js_asset(name: &str) -> Response {
    let body = crate::assets::AdminAssets::get(name)
        .map(|f| f.data.into_owned())
        .unwrap_or_default();
    (
        [(
            header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

/// `/static/flow-editor.js` — orchestrator for the flow editor.
pub async fn admin_flow_editor_js() -> Response {
    js_asset("flow-editor.js")
}

/// `/static/elk.min.js` — vendored ELK graph layout engine.
pub async fn admin_elk_js() -> Response {
    js_asset("elk.min.js")
}

/// `/static/flow-viewport.js` — zoom, pan, minimap.
pub async fn admin_flow_viewport_js() -> Response {
    js_asset("flow-viewport.js")
}

/// `/static/flow-layout.js` — ELK layout integration.
pub async fn admin_flow_layout_js() -> Response {
    js_asset("flow-layout.js")
}

/// `/static/flow-crud.js` — node/edge CRUD operations.
pub async fn admin_flow_crud_js() -> Response {
    js_asset("flow-crud.js")
}

/// `/static/flow-panels.js` — node/edge configuration panels.
pub async fn admin_flow_panels_js() -> Response {
    js_asset("flow-panels.js")
}

/// `/static/flow-dryrun.js` — dry-run integration.
pub async fn admin_flow_dryrun_js() -> Response {
    js_asset("flow-dryrun.js")
}

// ---------------------------------------------------------------------
// Login + logout
// ---------------------------------------------------------------------

pub async fn login_page(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(q): Query<LangQuery>,
) -> Response {
    login_page_inner(&state, &headers, q.lang.as_deref(), None).await
}

async fn login_page_inner(
    _state: &AdminState,
    _headers: &HeaderMap,
    _lang_override: Option<&str>,
    error: Option<&str>,
) -> Response {
    // Inline boot script keeps the theme attribute in sync before any
    // pixels paint, matching the dashboard chrome. The CSS classes
    // (`gn-login-*`) are defined once in `tokens.css`.
    let body = maud::html! {
        (maud::DOCTYPE)
        html lang="en" dir="auto" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                title { "Sign in · Geonosis" }
                link rel="icon" type="image/svg+xml" href="/static/favicon.svg";
                link rel="stylesheet" href="/static/admin.css";
                // Loaded synchronously so the theme bootstrap IIFE in
                // the script applies `data-theme` before the body
                // renders. CSP `script-src 'self'` permits this.
                script src="/static/admin-chrome.js" {}
            }
            body {
                div class="gn-login-page" {
                    div class="gn-login-card" {
                        div class="gn-login-brand" {
                            img class="gn-brand__mark" src="/static/logo.svg" alt="" width="56" height="56";
                            h1 class="gn-login-title" { "Geonosis" }
                        }
                        p class="gn-login-subtitle" { "Sign in to the admin console" }
                        @if let Some(err) = error {
                            div class="gn-alert gn-alert--danger" role="alert" { (err) }
                        }
                        form method="post" action="/admin/login" class="gn-form" {
                            div class="gn-field" {
                                label class="gn-field__label" for="username" { "Username or email" }
                                input
                                    class="gn-input"
                                    type="text"
                                    id="username"
                                    name="username"
                                    autocomplete="username"
                                    required
                                    autofocus;
                            }
                            div class="gn-field" {
                                label class="gn-field__label" for="password" { "Password" }
                                input
                                    class="gn-input"
                                    type="password"
                                    id="password"
                                    name="password"
                                    autocomplete="current-password"
                                    required;
                            }
                            button type="submit" class="gn-btn gn-btn--primary gn-btn--block" {
                                "Sign in"
                            }
                        }
                    }
                }
            }
        }
    };
    html_response(body)
}

#[derive(Debug, Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

pub async fn login_submit(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<LoginForm>,
) -> Response {
    match try_login(&state, &form.username, &form.password).await {
        Ok((session_id, _realm_id)) => {
            let cookie = format!(
                "{}={}; Path=/admin; HttpOnly; SameSite=Lax; Max-Age=86400",
                crate::auth::COOKIE_NAME,
                session_id,
            );
            (
                StatusCode::SEE_OTHER,
                [
                    (header::LOCATION, "/admin/realms"),
                    (header::SET_COOKIE, &cookie),
                ],
            )
                .into_response()
        }
        Err(msg) => login_page_inner(&state, &headers, None, Some(&msg)).await,
    }
}

async fn try_login(
    state: &AdminState,
    username: &str,
    password: &str,
) -> Result<(String, geonosis_core::RealmId), String> {
    let realms = state
        .storage
        .list_realms()
        .await
        .map_err(|_| "internal error".to_string())?;
    let realm = realms.first().ok_or("no realm configured")?;

    let user = match state.storage.get_user_by_username(realm.id, username).await {
        Ok(u) => u,
        Err(_) => state
            .storage
            .get_user_by_email(realm.id, username)
            .await
            .map_err(|_| "Invalid username or password".to_string())?,
    };

    if !user.enabled {
        return Err("Account is disabled".into());
    }

    let is_admin = matches!(
        user.attributes.get("admin"),
        Some(geonosis_core::attribute::AttributeValue::Bool(true))
    );
    if !is_admin {
        return Err("Admin access required".into());
    }

    let hash = state
        .storage
        .get_password_hash(realm.id, user.id)
        .await
        .map_err(|_| "Invalid username or password".to_string())?;
    let valid = geonosis_crypto::verify_password(password, &hash)
        .map_err(|_| "Invalid username or password".to_string())?;
    if !valid {
        return Err("Invalid username or password".into());
    }

    let now = chrono::Utc::now();
    let session = geonosis_core::Session {
        id: geonosis_core::id::SessionId::new_random(),
        realm_id: realm.id,
        user_id: user.id,
        authn_level: geonosis_core::common::AuthnLevel::Single,
        idp_alias: None,
        started_at: now,
        last_seen_at: now,
        expires_at: now + chrono::Duration::hours(24),
        clients: vec![],
    };
    let sid = session.id.to_string();
    state
        .storage
        .create_session(session)
        .await
        .map_err(|_| "internal error".to_string())?;

    Ok((sid, realm.id))
}

pub async fn logout(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    if let Some(sid) = crate::auth::cookie_value_from(&headers) {
        let session_id = geonosis_core::id::SessionId(sid);
        let _ = state.storage.delete_session(&session_id).await;
    }
    let clear_cookie = format!(
        "{}=; Path=/admin; HttpOnly; SameSite=Lax; Max-Age=0",
        crate::auth::COOKIE_NAME,
    );
    (
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, "/admin/login"),
            (header::SET_COOKIE, &clear_cookie),
        ],
    )
        .into_response()
}

fn html_response(markup: maud::Markup) -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        markup.into_string(),
    )
        .into_response()
}
