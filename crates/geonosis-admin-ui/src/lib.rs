//! Server-side rendered admin console + REST API.
//!
//! The admin surface is split into:
//!
//! - **HTML pages** under `/admin/...` rendered by the Leptos
//!   `leptos_ui::router` (per `docs/08-admin-ui.md`). Every page is
//!   server-rendered SSR; only the flow editor ships a hydration
//!   island via `/static/flow-editor.js`.
//! - **Public assets** `/static/admin.css` (design tokens) and
//!   `/static/admin-chrome.js` (theme toggle, mobile drawer, realm
//!   selector) plus `/static/flow-editor.js` for the canvas.
//! - **REST API** under `/admin/v1/...` returning JSON for `geoctl`
//!   and third-party integrations.
//! - **Login/logout** under `/admin/login` and `/admin/logout`
//!   (Maud-rendered for now since they are the un-authenticated
//!   surface and have no chrome dependencies).

pub mod assets;
pub mod audit_emit;
pub mod auth;
pub mod handlers;
pub mod handlers_v1;
pub mod html;
pub mod leptos_ui;
pub mod org_flow;
pub mod state;

use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;

pub use state::{AdminError, AdminState};

pub fn router(state: AdminState) -> Router {
    let shared = Arc::new(state);

    // Public routes — no auth required.
    let public_routes = Router::new()
        .route("/static/admin.css", get(handlers::admin_css))
        .route("/static/admin-chrome.js", get(handlers::admin_chrome_js))
        .route("/static/logo.svg", get(handlers::admin_logo_svg))
        .route("/static/favicon.svg", get(handlers::admin_favicon_svg))
        .route("/favicon.svg", get(handlers::admin_favicon_svg))
        .route(
            "/static/flow-editor.js",
            get(handlers::admin_flow_editor_js),
        )
        .route("/static/elk.min.js", get(handlers::admin_elk_js))
        .route(
            "/static/flow-viewport.js",
            get(handlers::admin_flow_viewport_js),
        )
        .route(
            "/static/flow-layout.js",
            get(handlers::admin_flow_layout_js),
        )
        .route("/static/flow-crud.js", get(handlers::admin_flow_crud_js))
        .route(
            "/static/flow-panels.js",
            get(handlers::admin_flow_panels_js),
        )
        .route(
            "/static/flow-dryrun.js",
            get(handlers::admin_flow_dryrun_js),
        )
        .route(
            "/admin/login",
            get(handlers::login_page).post(handlers::login_submit),
        )
        .route("/admin/logout", post(handlers::logout))
        .with_state(shared.clone());

    let protected_leptos = leptos_ui::leptos_router(shared.clone()).layer(
        axum::middleware::from_fn_with_state(shared.clone(), auth::require_admin),
    );

    let protected_v1 = handlers_v1::router(shared.clone()).layer(
        axum::middleware::from_fn_with_state(shared.clone(), auth::require_admin),
    );

    public_routes.merge(protected_leptos).merge(protected_v1)
}
