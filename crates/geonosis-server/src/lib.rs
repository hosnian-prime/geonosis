//! Geonosis HTTP server.
//!
//! Wires:
//! - axum router with the OIDC + admin + health surface.
//! - Storage + cache + KMS + SPI registry as application state.
//! - tracing JSON logger + request_id middleware.
//!
//! v0.1 ships only the in-memory `MemoryStorage` so the 5-minute
//! quickstart works without Postgres. The Postgres backend lands once
//! `geonosis-migrate` provides the schema.

pub mod app;
pub mod authenticators;
pub mod broker;
pub mod handlers;
pub mod ldap;
pub mod metrics;
pub mod security_headers;
pub mod state;
pub mod token_verify;

pub use app::router;
pub use state::AppState;
