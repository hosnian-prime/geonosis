//! `geonosis:user-profile-validator@0.1.0` invocation glue.
//!
//! Single export `validate(attribute, values, config) -> result<_, validation-error>`.
//! Dispatch mode: NamedAttach — validators bind to specific attribute
//! names via `AttributeValidator::Custom`; the router runs each
//! validator once per attribute it's attached to.

use std::sync::Arc;

use wasmtime::component::{Component, Linker};
use wasmtime::Store;

use crate::runtime::engine::{RuntimeError, WasmEngine};
use crate::runtime::host_state::HostState;
use crate::runtime::limits::ResourceLimits;

pub struct WasmUserProfileValidatorRuntime {
    engine: Arc<WasmEngine>,
    component: Component,
    component_sha256: String,
    limits: ResourceLimits,
}

impl WasmUserProfileValidatorRuntime {
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

    /// Returns `Ok(None)` on success; `Ok(Some(error))` when the
    /// plugin's validation logic rejected the value. The host distinguishes
    /// these so a localized `validation-error` can flow into the form
    /// error display without raising a 5xx.
    pub async fn validate(
        &self,
        host_state: HostState,
        attribute: &str,
        values: Vec<String>,
        config: &[u8],
    ) -> Result<Option<wire::ValidationError>, RuntimeError> {
        let mut store = self.fresh_store(host_state)?;
        let linker: Linker<HostState> = Linker::new(self.engine.engine());
        let instance = linker
            .instantiate_async(&mut store, &self.component)
            .await
            .map_err(|e| RuntimeError::Instantiate(e.to_string()))?;

        let func = instance
            .get_typed_func::<(String, Vec<String>, Vec<u8>), (Result<(), wire::ValidationError>,)>(
                &mut store, "validate",
            )
            .map_err(|e| RuntimeError::Plugin(format!("export not found: {e}")))?;

        let call = func.call_async(&mut store, (attribute.to_string(), values, config.to_vec()));
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
            Ok(()) => Ok(None),
            Err(ve) => Ok(Some(ve)),
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
        let ticks_needed = self.limits.wall_clock_ms.div_ceil(tick_ms);
        store.set_epoch_deadline(ticks_needed.max(1));
        store.limiter(|s: &mut HostState| -> &mut dyn wasmtime::ResourceLimiter { &mut s.limiter });
        Ok(store)
    }
}

pub mod wire {
    use wasmtime::component::{ComponentType, Lift, Lower};

    #[derive(Debug, Clone, ComponentType, Lift, Lower)]
    #[component(record)]
    pub struct ValidationError {
        pub attribute: String,
        pub kind: String,
        pub message: String,
    }
}
