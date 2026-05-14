//! Server-side rendered admin console + REST API.
//!
//! Per `docs/08-admin-ui.md` v0.1 ships:
//! - **HTML** routes under `/admin/...` that render Maud templates
//!   composed of `geonosis-ui-kit` primitives.
//! - **REST** routes under `/admin/v1/...` returning JSON for the
//!   future Leptos-island hydration + the third-party tooling (Terraform
//!   provider, geoctl) that consumes the admin API.
//! - **Static asset** route `/static/admin.css` serving the design
//!   tokens stylesheet embedded with `rust-embed`.
//!
//! The Leptos-native component-override path (the *power-user escape
//! hatch* in the doc) is wired up in v0.1.x once the WASM SPI runtime
//! has its `geonosis:ui-component` interface plumbed end-to-end.

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
        .route(
            "/static/flow-editor.js",
            get(handlers::admin_flow_editor_js),
        )
        .route(
            "/admin/login",
            get(handlers::login_page).post(handlers::login_submit),
        )
        .route("/admin/logout", post(handlers::logout))
        .with_state(shared.clone());

    // Protected HTML pages — require admin auth.
    let protected_html = Router::new()
        .route("/admin", get(handlers::page_realms_html))
        .route("/admin/realms", get(handlers::page_realms_html))
        .route("/admin/realms/:slug", get(handlers::page_realm_detail_html))
        .route(
            "/admin/realms/:slug/clients",
            get(handlers::page_clients_html),
        )
        .route("/admin/realms/:slug/users", get(handlers::page_users_html))
        .route("/admin/realms/:slug/flows", get(handlers::page_flows_html))
        .route("/admin/realms/:slug/spi", get(handlers::page_spi_html))
        .route("/admin/realms/:slug/idps", get(handlers::page_idps_html))
        .route(
            "/admin/realms/:slug/events",
            get(handlers::page_events_html),
        )
        .layer(axum::middleware::from_fn_with_state(
            shared.clone(),
            auth::require_admin,
        ))
        .with_state(shared.clone());

    // Protected REST API routes.
    let protected_api = Router::new()
        .route("/admin/v1/realms/:slug/spi", get(handlers::api_spi_list))
        .route(
            "/admin/v1/realms/:slug/flows/:alias",
            get(handlers::api_flow_get).put(handlers::api_flow_put),
        )
        .layer(axum::middleware::from_fn_with_state(
            shared.clone(),
            auth::require_admin,
        ))
        .with_state(shared.clone());

    let protected_leptos = leptos_ui::leptos_router(shared.clone()).layer(
        axum::middleware::from_fn_with_state(shared.clone(), auth::require_admin),
    );

    let protected_v1 = handlers_v1::router(shared.clone()).layer(
        axum::middleware::from_fn_with_state(shared.clone(), auth::require_admin),
    );

    public_routes
        .merge(protected_html)
        .merge(protected_api)
        .merge(protected_leptos)
        .merge(protected_v1)
}
