//! Wasmtime-backed SPI runtime.
//!
//! Per `docs/07-spi-wasm.md`:
//! - Single shared `wasmtime::Engine` per host process (amortizes JIT).
//! - Epoch interruption + fuel + memory cap enforced per call.
//! - Module compilation cache: in-memory `Component` cache keyed by
//!   SHA-256, plus an on-disk `cwasm` cache at the configured root.
//! - Host imports: `geonosis:host/logging`, `secrets`, `http-client` —
//!   each call is allowlist-gated.
//!
//! This module ships the engine + `WasmMapperRuntime` (the worked example
//! from doc §"Dispatch semantics"). The other WIT worlds (authn,
//! user-storage, event, broker-adapter) reuse the same engine + sandbox
//! semantics; their typed wrappers land alongside the matching server
//! handlers — keeping the per-interface dispatch glue close to the
//! consumer.

pub mod allowlist;
pub mod engine;
pub mod host_state;
pub mod limits;
pub mod mapper;
pub mod store;

pub use allowlist::HostAllowlist;
pub use engine::{RuntimeError, WasmEngine};
pub use host_state::HostState;
pub use limits::{ResourceLimits, SandboxConfig};
pub use mapper::WasmMapperRuntime;
pub use store::ModuleStore;
