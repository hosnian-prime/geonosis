//! `geonosis:mapper@0.1.0` invocation glue.
//!
//! Per `wit/mapper.wit`, the export signature is:
//!
//! ```wit
//! map-claims: func(
//!     ctx-realm: string,
//!     input: list<u8>,            // claim-set as JSON bytes
//!     config: list<u8>,
//! ) -> result<list<u8>, plugin-error>;
//! ```
//!
//! We do NOT pull in `wasmtime::component::bindgen!` for v0.1 — the
//! macro needs the WIT package files at compile time relative to a
//! fixed root, which complicates the workspace layout. Instead the
//! runtime looks up the export by name and pins the signature to the
//! published WIT contract. A version drift surfaces as
//! `RuntimeError::Plugin("export not found")`.

use std::sync::Arc;

use wasmtime::component::{Component, Linker};
use wasmtime::Store;

use crate::runtime::engine::{RuntimeError, WasmEngine};
use crate::runtime::host_state::HostState;
use crate::runtime::limits::ResourceLimits;

pub struct WasmMapperRuntime {
    engine: Arc<WasmEngine>,
    component: Component,
    component_sha256: String,
    limits: ResourceLimits,
}

impl WasmMapperRuntime {
    pub fn compile(
        engine: Arc<WasmEngine>,
        wasm_bytes: &[u8],
        limits: ResourceLimits,
    ) -> Result<Self, RuntimeError> {
        let (component_sha256, component) = engine.modules.load(engine.engine(), wasm_bytes)?;
        Ok(Self {
            engine,
            component,
            component_sha256,
            limits,
        })
    }

    pub fn component_sha256(&self) -> &str {
        &self.component_sha256
    }

    /// Apply the mapper to `claim-set` bytes. The plugin owns the wire
    /// shape; v0.1 standardises on JSON-encoded UTF-8 so the host
    /// stays struct-agnostic.
    pub async fn map_claims(
        &self,
        host_state: HostState,
        realm: &str,
        input: &[u8],
        config: &[u8],
    ) -> Result<Vec<u8>, RuntimeError> {
        let mut store = self.fresh_store(host_state)?;
        let linker: Linker<HostState> = Linker::new(self.engine.engine());
        // v0.1 mapper world doesn't import http-client; the canonical
        // mappers are pure transforms. Logging + secrets imports are
        // added behind their own feature switch when we wire up the
        // typed bindgen pipeline.

        let instance = linker
            .instantiate_async(&mut store, &self.component)
            .await
            .map_err(|e| RuntimeError::Instantiate(e.to_string()))?;

        let func = instance
            .get_typed_func::<
                (String, Vec<u8>, Vec<u8>),
                (Result<Vec<u8>, super::wire_error::Wire>,),
            >(&mut store, "map-claims")
            .map_err(|e| RuntimeError::Plugin(format!("export not found: {e}")))?;

        let call = func.call_async(
            &mut store,
            (realm.to_string(), input.to_vec(), config.to_vec()),
        );
        let res = tokio::time::timeout(self.limits.wall_clock(), call)
            .await
            .map_err(|_| RuntimeError::Timeout {
                ms: self.limits.wall_clock_ms,
            })?
            .map_err(|e| super::call_error::classify(e, &self.limits))?;

        func.post_return_async(&mut store)
            .await
            .map_err(|e: anyhow::Error| RuntimeError::Call(e.to_string()))?;

        match res.0 {
            Ok(bytes) => Ok(bytes),
            Err(w) => Err(RuntimeError::Plugin(format!(
                "{}: {} (retryable={})",
                w.kind, w.message, w.retryable
            ))),
        }
    }

    fn fresh_store(&self, mut state: HostState) -> Result<Store<HostState>, RuntimeError> {
        state.memory_cap_bytes = self.limits.memory_bytes;
        state.limiter.cap = self.limits.memory_bytes;
        let mut store = Store::new(self.engine.engine(), state);
        store
            .set_fuel(self.limits.fuel)
            .map_err(|e| RuntimeError::Engine(e.to_string()))?;
        store.epoch_deadline_trap();
        // Compute the deadline tick count from the configured tick
        // period so the wall-clock budget bounds the call regardless
        // of how slow the underlying instruction stream is.
        let tick_ms = self.engine.config().epoch_tick_ms.max(1);
        let ticks_needed = self.limits.wall_clock_ms.div_ceil(tick_ms);
        store.set_epoch_deadline(ticks_needed.max(1));
        store.limiter(|s: &mut HostState| -> &mut dyn wasmtime::ResourceLimiter { &mut s.limiter });
        Ok(store)
    }
}
