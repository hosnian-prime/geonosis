//! Storage abstraction for Geonosis.
//!
//! Per `docs/01-architecture.md`, Postgres is the system of record. The
//! trait surface here is structured by entity (realm / user / client /
//! flow / key / refresh-token / code / session) — each method maps to
//! one Postgres query in the production impl.
//!
//! v0.1 ships:
//! - `MemoryStorage` — always-built, used for unit + integration tests
//!   and the 5-minute quickstart.
//! - `PostgresStorage` — behind the `postgres` feature. Server boots
//!   with this when `GEONOSIS_DATABASE_URL` is set; otherwise falls
//!   back to `MemoryStorage` (the dev default).
//!
//! Both backends satisfy the same `Storage` trait so handlers and
//! authenticators are storage-blind (see `docs/01-architecture.md`
//! §Dependency Inversion).

pub mod error;
pub mod memory;
pub mod traits;

pub use error::StorageError;
pub use memory::MemoryStorage;
pub use traits::{
    ConsentGrant, DeviceGrant, DeviceGrantStatus, FlowStateRow, OrgIdpBinding, ParRequest,
    SpiBindingRow, Storage, WasmModule, WasmModuleHeader,
};

#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "postgres")]
pub use postgres::PostgresStorage;
