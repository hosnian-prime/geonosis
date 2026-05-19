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
pub mod audit_emit;
pub mod authenticators;
pub mod bootstrap;
pub mod broker;
pub mod flow_runtime;
pub mod handlers;
pub mod ldap;
pub mod metrics;
pub mod rate_limit;
pub mod security_headers;
pub mod state;
pub mod telemetry;
pub mod token_verify;

pub use app::router;
pub use state::AppState;

#[cfg(any(test, feature = "test-fixtures"))]
pub mod test_fixtures;
