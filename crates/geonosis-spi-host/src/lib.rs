//! SPI host: provider registry + WASM runtime scaffolding.
//!
//! Per `docs/07-spi-wasm.md`:
//! - Provider registry indexes `SpiBinding`s by WIT interface name.
//! - Dispatch mode is fixed per interface (FirstMatch / NamedSelect /
//!   Chain / FireForget / FirstDecision / NamedAttach).
//! - Built-ins register with a `builtin:` URN; WASM plugins with `wasm:`.
//!
//! The wasmtime / WIT integration lives behind the `wasm-runtime` feature
//! (deferred — large optional dep, see v0.1.x follow-up). v0.1 ships:
//!
//! - Stable `ProviderUrn` / `SpiBinding` types
//! - Built-in provider registration helpers
//! - Dispatch-mode enum
//! - `ProviderRegistry` with first-match + named-select dispatch
//!
//! Replacement of any built-in by URN works through `SpiBinding.replaces`.

pub mod dispatch;
pub mod error;
pub mod registry;

#[cfg(feature = "wasm-runtime")]
pub mod runtime;

pub use dispatch::{DispatchMode, WitInterfaceName};
pub use error::{ProviderError, ProviderResult};
pub use registry::{LookupOutcome, ProviderBinding, ProviderCapabilities, ProviderRegistry};

#[cfg(feature = "wasm-runtime")]
pub use runtime::{
    HostAllowlist, HostState, ModuleStore, ResourceLimits, RuntimeError, SandboxConfig,
    WasmEngine, WasmMapperRuntime,
};
