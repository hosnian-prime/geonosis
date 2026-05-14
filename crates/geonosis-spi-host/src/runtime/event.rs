//! `geonosis:event@0.1.0` invocation glue.
//!
//! Per `wit/event.wit`:
//!
//! ```wit
//! on-event: func(event-bytes: list<u8>) -> result<_, plugin-error>;
//! ```
//!
//! Dispatch mode: FireForget — every listener runs, failures logged,
//! never propagated. The router-level fire-forget loop lives in
//! `crate::router::fire_forget`; this runtime only knows how to call
//! ONE listener's `on-event` export.

use std::sync::Arc;

use wasmtime::component::{Component, Linker};
use wasmtime::Store;

use crate::runtime::engine::{RuntimeError, WasmEngine};
use crate::runtime::host_state::HostState;
use crate::runtime::limits::ResourceLimits;

pub struct WasmEventRuntime {
    engine: Arc<WasmEngine>,
    component: Component,
    component_sha256: String,
    limits: ResourceLimits,
}

impl WasmEventRuntime {
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

    /// Invoke `event-listener.on-event` with the bincode-encoded
    /// `AuditEvent` bytes. Returns `Ok(())` whether the plugin
    /// returned ok or err; the router fire-forget loop is what logs
    /// the typed error.
    pub async fn on_event(
        &self,
        host_state: HostState,
        event_bytes: &[u8],
    ) -> Result<(), RuntimeError> {
        let mut store = self.fresh_store(host_state)?;
        let linker: Linker<HostState> = Linker::new(self.engine.engine());

        let instance = linker
            .instantiate_async(&mut store, &self.component)
            .await
            .map_err(|e| RuntimeError::Instantiate(e.to_string()))?;

        let func = instance
            .get_typed_func::<
                (Vec<u8>,),
                (Result<(), super::wire_error::Wire>,),
            >(&mut store, "on-event")
            .map_err(|e| RuntimeError::Plugin(format!("export not found: {e}")))?;

        let call = func.call_async(&mut store, (event_bytes.to_vec(),));
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
            Ok(()) => Ok(()),
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
        let tick_ms = self.engine.config().epoch_tick_ms.max(1);
        let ticks_needed = (self.limits.wall_clock_ms + tick_ms - 1) / tick_ms;
        store.set_epoch_deadline(ticks_needed.max(1));
        store.limiter(|s: &mut HostState| -> &mut dyn wasmtime::ResourceLimiter {
            &mut s.limiter
        });
        Ok(store)
    }
}
