//! Admin UI HTTP handlers — both the HTML pages and the REST API.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use maud::html;
use serde::Deserialize;

use geonosis_core::RealmId;
use geonosis_i18n::I18n;
use unic_langid::LanguageIdentifier;

use crate::html::{empty_section, flow_editor_mount, page, realms_table, PageCtx};
use crate::state::AdminState;

#[derive(Debug, Deserialize)]
pub struct LangQuery {
    #[serde(default)]
    pub lang: Option<String>,
}

fn negotiate(i18n: &I18n, headers: &HeaderMap, override_: Option<&str>) -> LanguageIdentifier {
    if let Some(l) = override_ {
        if let Ok(lid) = l.parse() {
            return lid;
        }
    }
    let accept = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("en");
    i18n.negotiate_from_header(accept)
}

pub async fn admin_css() -> Response {
    let body = geonosis_ui_kit::TOKENS_CSS;
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], body).into_response()
}

/// `/static/flow-editor.js` — hand-rolled hydrator that attaches
/// drag-to-reposition + save behaviour to the Leptos-rendered SVG
/// flow canvas. Embedded with `rust-embed` so it ships in the same
/// binary as the rest of the admin surface and never relies on an
/// external CDN. The asset is the ONE JS payload `docs/08-admin-ui.md`
/// budgets the admin surface for: ~10 KB of carefully scoped code
/// for the only page that needs client-side interactivity.
pub async fn admin_flow_editor_js() -> Response {
    let body = crate::assets::AdminAssets::get("flow-editor.js")
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

// ---- HTML pages ----

pub async fn page_realms_html(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(q): Query<LangQuery>,
) -> Result<Response, StatusCode> {
    let lang = negotiate(&state.i18n, &headers, q.lang.as_deref());
    let ctx = PageCtx {
        lang,
        i18n: &state.i18n,
        active: "realms",
        realm_slug: None,
    };
    let realms = state
        .storage
        .list_realms()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let body = html! {
        h1 { (ctx.t("admin-realms-heading")) }
        (realms_table(&ctx, &realms))
    };
    Ok(html_response(page(&ctx, &ctx.t("admin-title"), body)))
}

pub async fn page_realm_detail_html(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Query(q): Query<LangQuery>,
) -> Result<Response, StatusCode> {
    let lang = negotiate(&state.i18n, &headers, q.lang.as_deref());
    let ctx = PageCtx {
        lang,
        i18n: &state.i18n,
        active: "realms",
        realm_slug: Some(&slug),
    };
    let realm = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let body = html! {
        h1 { (realm.display_name) }
        p { (ctx.t("admin-realm-slug")) ": " code { (realm.slug) } }
        section class="gn-card" {
            h2 { (ctx.t("nav-clients")) }
            p { a href=(format!("/admin/realms/{}/clients", realm.slug)) { "Open clients" } }
        }
        section class="gn-card" {
            h2 { (ctx.t("nav-flows")) }
            p { a href=(format!("/admin/realms/{}/flows", realm.slug)) { "Open flows" } }
        }
        section class="gn-card" {
            h2 { (ctx.t("nav-spi")) }
            p { a href=(format!("/admin/realms/{}/spi", realm.slug)) { "Open SPI bindings" } }
        }
    };
    Ok(html_response(page(&ctx, &realm.display_name, body)))
}

pub async fn page_clients_html(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Query(q): Query<LangQuery>,
) -> Result<Response, StatusCode> {
    let lang = negotiate(&state.i18n, &headers, q.lang.as_deref());
    let ctx = PageCtx {
        lang,
        i18n: &state.i18n,
        active: "clients",
        realm_slug: Some(&slug),
    };
    let realm = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let clients = state
        .storage
        .list_clients(realm.id)
        .await
        .unwrap_or_default();
    let body = html! {
        h1 { (ctx.t("admin-clients-heading")) }
        @if clients.is_empty() {
            p { (ctx.t("admin-clients-empty")) }
        } @else {
            table class="gn-table" {
                thead {
                    tr { th { "client_id" } th { "kind" } th { "enabled" } }
                }
                tbody {
                    @for c in &clients {
                        tr {
                            td { code { (c.client_id) } }
                            td { (format!("{:?}", c.kind)) }
                            td { @if c.enabled { "yes" } @else { "no" } }
                        }
                    }
                }
            }
        }
    };
    Ok(html_response(page(
        &ctx,
        &ctx.t("admin-clients-heading"),
        body,
    )))
}

pub async fn page_users_html(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Query(q): Query<LangQuery>,
) -> Result<Response, StatusCode> {
    let lang = negotiate(&state.i18n, &headers, q.lang.as_deref());
    let ctx = PageCtx {
        lang,
        i18n: &state.i18n,
        active: "users",
        realm_slug: Some(&slug),
    };
    // v0.1: storage doesn't expose a paginated user-list method; the
    // section is a placeholder until the admin REST gets `/users?cursor=`.
    let body = empty_section(&ctx, "admin-users-heading", "admin-users-empty");
    let _ = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(html_response(page(
        &ctx,
        &ctx.t("admin-users-heading"),
        body,
    )))
}

pub async fn page_flows_html(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Query(q): Query<LangQuery>,
) -> Result<Response, StatusCode> {
    let lang = negotiate(&state.i18n, &headers, q.lang.as_deref());
    let ctx = PageCtx {
        lang,
        i18n: &state.i18n,
        active: "flows",
        realm_slug: Some(&slug),
    };
    let realm = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    // The flow editor mount renders into `#gn-flow-canvas` once the
    // admin fetches the flow document by alias. v0.1 demos the
    // canonical `browser` alias; realm CRUD for additional aliases
    // arrives with `/admin/v1/realms/{slug}/flows`.
    let body = html! {
        h1 { (ctx.t("admin-flows-heading")) " — " (realm.display_name) }
        section class="gn-card" {
            h2 { "browser" }
            (flow_editor_mount(&realm.slug, "browser"))
        }
    };
    Ok(html_response(page(
        &ctx,
        &ctx.t("admin-flows-heading"),
        body,
    )))
}

pub async fn page_spi_html(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Query(q): Query<LangQuery>,
) -> Result<Response, StatusCode> {
    let lang = negotiate(&state.i18n, &headers, q.lang.as_deref());
    let ctx = PageCtx {
        lang,
        i18n: &state.i18n,
        active: "spi",
        realm_slug: Some(&slug),
    };
    let _ = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let body = html! {
        h1 { (ctx.t("admin-spi-heading")) }
        p { "Configured providers across all built-in interfaces will appear here." }
    };
    Ok(html_response(page(&ctx, &ctx.t("admin-spi-heading"), body)))
}

pub async fn page_idps_html(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Query(q): Query<LangQuery>,
) -> Result<Response, StatusCode> {
    let lang = negotiate(&state.i18n, &headers, q.lang.as_deref());
    let ctx = PageCtx {
        lang,
        i18n: &state.i18n,
        active: "idps",
        realm_slug: Some(&slug),
    };
    let _ = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let body = html! {
        h1 { "Identity providers" }
        p { "Per-realm OIDC / SAML brokered IdPs." }
    };
    Ok(html_response(page(&ctx, "Identity providers", body)))
}

pub async fn page_events_html(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    Query(q): Query<LangQuery>,
) -> Result<Response, StatusCode> {
    let lang = negotiate(&state.i18n, &headers, q.lang.as_deref());
    let ctx = PageCtx {
        lang,
        i18n: &state.i18n,
        active: "events",
        realm_slug: Some(&slug),
    };
    let _ = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let body = html! {
        h1 { (ctx.t("admin-events-heading")) }
        p { "Audit events stream lands here once the event reader is wired." }
    };
    Ok(html_response(page(
        &ctx,
        &ctx.t("admin-events-heading"),
        body,
    )))
}

// ---- Login / Logout ----

pub async fn login_page(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(q): Query<LangQuery>,
) -> Response {
    login_page_inner(&state, &headers, q.lang.as_deref(), None).await
}

async fn login_page_inner(
    state: &AdminState,
    headers: &HeaderMap,
    lang_override: Option<&str>,
    error: Option<&str>,
) -> Response {
    let lang = negotiate(&state.i18n, headers, lang_override);
    let lang_str = lang.to_string();
    let body = maud::html! {
        (maud::DOCTYPE)
        html lang=(lang_str) dir="auto" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                title { "Sign in · Geonosis" }
                link rel="stylesheet" href="/static/admin.css";
            }
            body {
                div class="gn-login-page" {
                    div class="gn-login-card" {
                        h1 { "Geonosis" }
                        p class="gn-login-subtitle" { "Sign in to the admin console" }
                        @if let Some(err) = error {
                            div class="gn-login-error" { (err) }
                        }
                        form method="post" action="/admin/login" {
                            label class="gn-field" {
                                span class="gn-field-label" { "Username or email" }
                                input class="gn-input" type="text" name="username"
                                    autocomplete="username" required autofocus;
                            }
                            label class="gn-field" {
                                span class="gn-field-label" { "Password" }
                                input class="gn-input" type="password" name="password"
                                    autocomplete="current-password" required;
                            }
                            button type="submit" class="gn-button gn-button--primary" {
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
    // v0.1: look up the first realm. Multi-realm admin auth follows.
    let realms = state
        .storage
        .list_realms()
        .await
        .map_err(|_| "internal error".to_string())?;
    let realm = realms.first().ok_or("no realm configured")?;

    // Try by username, then by email.
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

    // Check admin attribute.
    let is_admin = matches!(
        user.attributes.get("admin"),
        Some(geonosis_core::attribute::AttributeValue::Bool(true))
    );
    if !is_admin {
        return Err("Admin access required".into());
    }

    // Verify password.
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

    // Create session.
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

pub async fn logout(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Response {
    // Try to delete the session.
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

// ---- REST API ----

pub async fn api_realms_list(
    State(state): State<Arc<AdminState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let realms = state
        .storage
        .list_realms()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let body: Vec<_> = realms
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id.to_string(),
                "slug": r.slug,
                "display_name": r.display_name,
                "enabled": r.enabled,
                "created_at": r.created_at.to_rfc3339(),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "realms": body })))
}

pub async fn api_realm_get(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let realm = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(serde_json::to_value(realm).unwrap()))
}

pub async fn api_clients_list(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let realm = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let clients = state
        .storage
        .list_clients(realm.id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "clients": clients })))
}

pub async fn api_users_list(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let _ = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    // v0.1: paginated user listing follows once the storage trait
    // exposes `list_users(realm, cursor)`. The endpoint returns an
    // empty page for now so admin tooling can hit it without 500-ing.
    Ok(Json(
        serde_json::json!({ "users": [], "next_cursor": null }),
    ))
}

pub async fn api_spi_list(
    State(state): State<Arc<AdminState>>,
    Path(slug): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let _ = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(serde_json::json!({ "bindings": [] })))
}

pub async fn api_flow_get(
    State(state): State<Arc<AdminState>>,
    Path((slug, alias)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let _ = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    // v0.1 shim: stored flow definitions live alongside realm config.
    // The endpoint returns a small placeholder graph so the flow editor
    // demo loads end-to-end; full retrieval lands with the flow-storage
    // CRUD migration.
    let _ = alias;
    Ok(Json(serde_json::json!({
        "nodes": [
            { "id": "start",   "display_name": "Start",  "kind": "start" },
            { "id": "pw",      "display_name": "Password", "kind": "authenticator" },
            { "id": "otp",     "display_name": "OTP",      "kind": "authenticator" },
            { "id": "success", "display_name": "Success",  "kind": "success" }
        ],
        "edges": [
            { "from": "start", "to": "pw"      },
            { "from": "pw",    "to": "otp"     },
            { "from": "otp",   "to": "success" }
        ]
    })))
}

pub async fn api_flow_put(
    State(state): State<Arc<AdminState>>,
    Path((slug, _alias)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let _ = state
        .storage
        .get_realm_by_slug(&slug)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    // v0.1: validate offline by trying to compile the flow definition.
    if let Ok(def) = serde_json::from_value::<geonosis_flow::FlowDefinition>(body.clone()) {
        if geonosis_flow::compile(def).is_err() {
            return Err(StatusCode::from_u16(422).unwrap_or(StatusCode::BAD_REQUEST));
        }
    }
    let _ = body;
    Ok(Json(serde_json::json!({ "ok": true })))
}

fn html_response(markup: maud::Markup) -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        markup.into_string(),
    )
        .into_response()
}

// Keep RealmId import alive (used through transparent serde value
// conversion).
const _UNUSED_REALM_ID: Option<RealmId> = None;
