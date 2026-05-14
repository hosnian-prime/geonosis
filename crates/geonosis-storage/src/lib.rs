//! Storage abstraction for Geonosis.
//!
//! Per `docs/01-architecture.md`, Postgres is the system of record. The
//! trait surface here is structured by entity (realm / user / client /
//! flow / key / refresh-token / code / session) — each method maps to one
//! Postgres query in the production impl.
//!
//! v0.1 ships an in-memory implementation suitable for the 5-minute
//! quickstart and end-to-end tests. The Postgres impl is feature-gated
//! and lives in `sqlx_postgres.rs` once the migrations land.

pub mod error;
pub mod memory;
pub mod traits;

pub use error::StorageError;
pub use memory::MemoryStorage;
pub use traits::{DeviceGrant, DeviceGrantStatus, FlowStateRow, ParRequest, Storage};
