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
pub mod handlers;
pub mod handlers_v1;
pub mod html;
pub mod leptos_ui;
pub mod org_flow;
pub mod state;

use std::sync::Arc;

use axum::routing::get;
use axum::Router;

pub use state::{AdminError, AdminState};

pub fn router(state: AdminState) -> Router {
    let shared = Arc::new(state);
    let maud_routes = Router::new()
        // Static assets.
        .route("/static/admin.css", get(handlers::admin_css))
        // HTML pages.
        .route("/admin", get(handlers::page_realms_html))
        .route("/admin/realms", get(handlers::page_realms_html))
        .route(
            "/admin/realms/:slug",
            get(handlers::page_realm_detail_html),
        )
        .route(
            "/admin/realms/:slug/clients",
            get(handlers::page_clients_html),
        )
        .route(
            "/admin/realms/:slug/users",
            get(handlers::page_users_html),
        )
        .route(
            "/admin/realms/:slug/flows",
            get(handlers::page_flows_html),
        )
        .route("/admin/realms/:slug/spi", get(handlers::page_spi_html))
        .route("/admin/realms/:slug/idps", get(handlers::page_idps_html))
        .route(
            "/admin/realms/:slug/events",
            get(handlers::page_events_html),
        )
        // REST API — only the routes not yet superseded by
        // handlers_v1 live here. realms/clients/users have moved
        // into handlers_v1 (full CRUD); the legacy list-only
        // handlers stay reachable only via the Maud-rendered HTML
        // pages above. /spi list + /flows GET/PUT remain here until
        // handlers_v1 absorbs them.
        .route(
            "/admin/v1/realms/:slug/spi",
            get(handlers::api_spi_list),
        )
        .route(
            "/admin/v1/realms/:slug/flows/:alias",
            get(handlers::api_flow_get)
                .put(handlers::api_flow_put),
        )
        .with_state(shared.clone());

    maud_routes
        .merge(leptos_ui::leptos_router(shared.clone()))
        .merge(handlers_v1::router(shared))
}
