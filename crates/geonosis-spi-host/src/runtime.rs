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
//! v0.1 ships typed runtimes for four WIT worlds (the ones with
//! concrete v0.1 consumers): `mapper`, `authn`, `event`, `policy`.
//! The other four (`user-storage`, `broker-adapter`,
//! `user-profile-validator`, `ui-component`) reuse the same engine +
//! `ModuleStore`; their typed wrappers land with the matching server
//! handler in v0.1.x (no plugin author needs them until then).
//!
//! Internal helpers shared across the per-WIT runtimes:
//! - `wire_error` — the `plugin-error` record (one decoder for all).
//! - `call_error` — fuel / epoch / trap classification of the raw
//!   `anyhow::Error` returned from `func.call_async`.

pub mod allowlist;
pub mod authn;
pub(crate) mod call_error;
pub mod engine;
pub mod event;
pub mod host_state;
pub mod limits;
pub mod mapper;
pub mod policy;
pub mod store;
pub(crate) mod wire_error;

pub use allowlist::HostAllowlist;
pub use authn::WasmAuthnRuntime;
pub use engine::{RuntimeError, WasmEngine};
pub use event::WasmEventRuntime;
pub use host_state::HostState;
pub use limits::{ResourceLimits, SandboxConfig};
pub use mapper::WasmMapperRuntime;
pub use policy::WasmPolicyRuntime;
pub use store::ModuleStore;
