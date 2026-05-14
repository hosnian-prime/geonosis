//! `geonosis:authn@0.1.0` invocation glue.
//!
//! Per `wit/authn.wit`, the export signature is:
//!
//! ```wit
//! process: func(
//!     realm: string,
//!     input: step-input,
//!     config: list<u8>,
//! ) -> result<step-output, plugin-error>;
//! ```
//!
//! Mirrors `WasmMapperRuntime` — same engine + module cache + store
//! lifecycle. The only difference is the WIT export name + typed
//! signature; everything else (fuel, epoch deadline, memory limiter,
//! cwasm cache reuse) is identical.

use std::sync::Arc;

use wasmtime::component::{Component, Linker};
use wasmtime::Store;

use crate::runtime::engine::{RuntimeError, WasmEngine};
use crate::runtime::host_state::HostState;
use crate::runtime::limits::ResourceLimits;

pub struct WasmAuthnRuntime {
    engine: Arc<WasmEngine>,
    component: Component,
    component_sha256: String,
    limits: ResourceLimits,
}

impl WasmAuthnRuntime {
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

    /// Invoke `authenticator.process`. `flow_context_json` and
    /// `submitted_form_json` are JSON-encoded UTF-8 (per the WIT
    /// contract); the host caller serializes whatever Rust-native
    /// shape it already has.
    pub async fn process(
        &self,
        host_state: HostState,
        realm: &str,
        flow_context_json: &[u8],
        submitted_form_json: &[u8],
        config: &[u8],
    ) -> Result<wire::StepOutput, RuntimeError> {
        let mut store = self.fresh_store(host_state)?;
        let linker: Linker<HostState> = Linker::new(self.engine.engine());

        let instance = linker
            .instantiate_async(&mut store, &self.component)
            .await
            .map_err(|e| RuntimeError::Instantiate(e.to_string()))?;

        let input = wire::StepInput {
            flow_context_json: flow_context_json.to_vec(),
            submitted_form_json: submitted_form_json.to_vec(),
        };

        let func = instance
            .get_typed_func::<
                (String, wire::StepInput, Vec<u8>),
                (Result<wire::StepOutput, super::wire_error::Wire>,),
            >(&mut store, "process")
            .map_err(|e| RuntimeError::Plugin(format!("export not found: {e}")))?;

        let call = func.call_async(&mut store, (realm.to_string(), input, config.to_vec()));
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
            Ok(step_output) => Ok(step_output),
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
        let ticks_needed = self.limits.wall_clock_ms.div_ceil(tick_ms);
        store.set_epoch_deadline(ticks_needed.max(1));
        store.limiter(|s: &mut HostState| -> &mut dyn wasmtime::ResourceLimiter { &mut s.limiter });
        Ok(store)
    }
}

/// Wire shapes for the authn WIT records/variants. Field order
/// mirrors `wit/authn.wit` so the component-model layout matches
/// without bindgen.
pub mod wire {
    use wasmtime::component::{ComponentType, Lift, Lower};

    #[derive(Debug, Clone, ComponentType, Lift, Lower)]
    #[component(record)]
    pub struct StepInput {
        #[component(name = "flow-context-json")]
        pub flow_context_json: Vec<u8>,
        #[component(name = "submitted-form-json")]
        pub submitted_form_json: Vec<u8>,
    }

    #[derive(Debug, Clone, ComponentType, Lift, Lower)]
    #[component(record)]
    pub struct SuccessPayload {
        pub amr: Vec<String>,
        pub attributes: Vec<u8>,
    }

    #[derive(Debug, Clone, ComponentType, Lift, Lower)]
    #[component(record)]
    pub struct ChallengePayload {
        pub template: String,
        pub locals: Vec<u8>,
    }

    #[derive(Debug, Clone, ComponentType, Lift, Lower)]
    #[component(variant)]
    pub enum StepOutput {
        #[component(name = "success")]
        Success(SuccessPayload),
        #[component(name = "challenge")]
        Challenge(ChallengePayload),
        #[component(name = "failure")]
        Failure(String),
        #[component(name = "skip")]
        Skip,
    }
}
