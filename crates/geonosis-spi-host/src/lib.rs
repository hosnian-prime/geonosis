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
pub mod manifest;
pub mod registry;
pub mod router;

#[cfg(feature = "wasm-runtime")]
pub mod runtime;

pub use dispatch::{DispatchMode, WitInterfaceName};
pub use error::{ProviderError, ProviderResult};
pub use manifest::{
    check_trusted, verify_bytecode_sha256, verify_signature, ManifestError, PluginManifest,
};
pub use registry::{LookupOutcome, ProviderBinding, ProviderCapabilities, ProviderRegistry};
pub use router::{
    active_bindings, chain, fire_forget, first_decision, first_match, named_attach, named_select,
    Decision, DispatchError,
};

#[cfg(feature = "wasm-runtime")]
pub use runtime::{
    HostAllowlist, HostState, ModuleStore, ResourceLimits, RuntimeError, SandboxConfig,
    WasmAuthnRuntime, WasmBrokerAdapterRuntime, WasmEngine, WasmEventRuntime, WasmMapperRuntime,
    WasmPolicyRuntime, WasmUiComponentRuntime, WasmUserProfileValidatorRuntime,
    WasmUserStorageRuntime,
};
