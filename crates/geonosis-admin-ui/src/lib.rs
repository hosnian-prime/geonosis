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
pub mod handlers;
pub mod html;
pub mod state;

use std::sync::Arc;

use axum::routing::get;
use axum::Router;

pub use state::{AdminError, AdminState};

pub fn router(state: AdminState) -> Router {
    Router::new()
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
        // REST API.
        .route("/admin/v1/realms", get(handlers::api_realms_list))
        .route(
            "/admin/v1/realms/:slug",
            get(handlers::api_realm_get),
        )
        .route(
            "/admin/v1/realms/:slug/clients",
            get(handlers::api_clients_list),
        )
        .route(
            "/admin/v1/realms/:slug/users",
            get(handlers::api_users_list),
        )
        .route(
            "/admin/v1/realms/:slug/spi",
            get(handlers::api_spi_list),
        )
        .route(
            "/admin/v1/realms/:slug/flows/:alias",
            get(handlers::api_flow_get)
                .put(handlers::api_flow_put),
        )
        .with_state(Arc::new(state))
}
