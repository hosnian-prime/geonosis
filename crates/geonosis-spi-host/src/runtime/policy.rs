//! `geonosis:policy@0.1.0` invocation glue.
//!
//! Per `wit/policy.wit`:
//!
//! ```wit
//! evaluate: func(
//!     ctx: policy-context,
//!     config: list<u8>,
//! ) -> result<decision, plugin-error>;
//! ```
//!
//! Dispatch mode: FirstDecision — caller iterates priority-sorted
//! providers, takes the first non-Skip decision. The router loop
//! lives in `crate::router::first_decision`; this runtime calls
//! exactly one provider.

use std::sync::Arc;

use wasmtime::component::{Component, Linker};
use wasmtime::Store;

use crate::runtime::engine::{RuntimeError, WasmEngine};
use crate::runtime::host_state::HostState;
use crate::runtime::limits::ResourceLimits;

pub struct WasmPolicyRuntime {
    engine: Arc<WasmEngine>,
    component: Component,
    component_sha256: String,
    limits: ResourceLimits,
}

impl WasmPolicyRuntime {
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

    /// Invoke `policy.evaluate`. `ctx_bytes` is the bincode-encoded
    /// per-decision-point context (`serde_json::Value`); the plugin
    /// is responsible for tolerant deserialization.
    pub async fn evaluate(
        &self,
        host_state: HostState,
        realm: &str,
        decision_point: &str,
        subject: Option<&str>,
        ctx_bytes: &[u8],
        config: &[u8],
    ) -> Result<wire::Decision, RuntimeError> {
        let mut store = self.fresh_store(host_state)?;
        let linker: Linker<HostState> = Linker::new(self.engine.engine());

        let instance = linker
            .instantiate_async(&mut store, &self.component)
            .await
            .map_err(|e| RuntimeError::Instantiate(e.to_string()))?;

        let policy_ctx = wire::PolicyContext {
            realm: realm.to_string(),
            decision_point: decision_point.to_string(),
            subject: subject.map(str::to_string),
            ctx_bytes: ctx_bytes.to_vec(),
        };

        let func = instance
            .get_typed_func::<
                (wire::PolicyContext, Vec<u8>),
                (Result<wire::Decision, super::wire_error::Wire>,),
            >(&mut store, "evaluate")
            .map_err(|e| RuntimeError::Plugin(format!("export not found: {e}")))?;

        let call = func.call_async(&mut store, (policy_ctx, config.to_vec()));
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
            Ok(decision) => Ok(decision),
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

/// Wire shapes for the policy WIT records/variants.
pub mod wire {
    use wasmtime::component::{ComponentType, Lift, Lower};

    #[derive(Debug, Clone, ComponentType, Lift, Lower)]
    #[component(record)]
    pub struct PolicyContext {
        pub realm: String,
        #[component(name = "decision-point")]
        pub decision_point: String,
        pub subject: Option<String>,
        #[component(name = "ctx-bytes")]
        pub ctx_bytes: Vec<u8>,
    }

    #[derive(Debug, Clone, ComponentType, Lift, Lower)]
    #[component(variant)]
    pub enum Decision {
        /// Bincode-encoded optional reasons/obligations.
        #[component(name = "permit")]
        Permit(Vec<u8>),
        /// Human-readable deny reason.
        #[component(name = "deny")]
        Deny(String),
        /// Defer to the next provider in the FirstDecision chain.
        #[component(name = "skip")]
        Skip,
    }
}
