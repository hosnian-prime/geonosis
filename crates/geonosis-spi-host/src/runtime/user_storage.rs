//! `geonosis:user-storage@0.1.0` invocation glue.
//!
//! Four exports per WIT:
//! - find-by-username, find-by-id, find-by-email
//! - validate-credential
//!
//! Dispatch mode: FirstMatch — the router iterates priority-sorted
//! providers; each runtime call resolves ONE provider's lookup. The
//! `LookupOutcome::NotFound` short-circuit happens in the router.

use std::sync::Arc;

use wasmtime::component::{Component, Linker};
use wasmtime::Store;

use crate::runtime::engine::{RuntimeError, WasmEngine};
use crate::runtime::host_state::HostState;
use crate::runtime::limits::ResourceLimits;

pub struct WasmUserStorageRuntime {
    engine: Arc<WasmEngine>,
    component: Component,
    component_sha256: String,
    limits: ResourceLimits,
}

impl WasmUserStorageRuntime {
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

    pub async fn find_by_username(
        &self,
        host_state: HostState,
        realm: &str,
        username: &str,
    ) -> Result<wire::LookupOutcome, RuntimeError> {
        self.lookup(host_state, "find-by-username", realm, username)
            .await
    }

    pub async fn find_by_id(
        &self,
        host_state: HostState,
        realm: &str,
        id: &str,
    ) -> Result<wire::LookupOutcome, RuntimeError> {
        self.lookup(host_state, "find-by-id", realm, id).await
    }

    pub async fn find_by_email(
        &self,
        host_state: HostState,
        realm: &str,
        email: &str,
    ) -> Result<wire::LookupOutcome, RuntimeError> {
        self.lookup(host_state, "find-by-email", realm, email).await
    }

    async fn lookup(
        &self,
        host_state: HostState,
        export: &str,
        realm: &str,
        key: &str,
    ) -> Result<wire::LookupOutcome, RuntimeError> {
        let mut store = self.fresh_store(host_state)?;
        let linker: Linker<HostState> = Linker::new(self.engine.engine());

        let instance = linker
            .instantiate_async(&mut store, &self.component)
            .await
            .map_err(|e| RuntimeError::Instantiate(e.to_string()))?;

        let func = instance
            .get_typed_func::<
                (String, String),
                (Result<wire::LookupOutcome, super::wire_error::Wire>,),
            >(&mut store, export)
            .map_err(|e| RuntimeError::Plugin(format!("export not found: {e}")))?;

        let call = func.call_async(&mut store, (realm.to_string(), key.to_string()));
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
            Ok(outcome) => Ok(outcome),
            Err(w) => Err(RuntimeError::Plugin(format!(
                "{}: {} (retryable={})",
                w.kind, w.message, w.retryable
            ))),
        }
    }

    pub async fn validate_credential(
        &self,
        host_state: HostState,
        realm: &str,
        id: &str,
        credential_bytes: &[u8],
    ) -> Result<wire::ValidationResult, RuntimeError> {
        let mut store = self.fresh_store(host_state)?;
        let linker: Linker<HostState> = Linker::new(self.engine.engine());

        let instance = linker
            .instantiate_async(&mut store, &self.component)
            .await
            .map_err(|e| RuntimeError::Instantiate(e.to_string()))?;

        let func = instance
            .get_typed_func::<
                (String, String, Vec<u8>),
                (Result<wire::ValidationResult, super::wire_error::Wire>,),
            >(&mut store, "validate-credential")
            .map_err(|e| RuntimeError::Plugin(format!("export not found: {e}")))?;

        let call = func.call_async(
            &mut store,
            (realm.to_string(), id.to_string(), credential_bytes.to_vec()),
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
            Ok(result) => Ok(result),
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

pub mod wire {
    use wasmtime::component::{ComponentType, Lift, Lower};

    #[derive(Debug, Clone, ComponentType, Lift, Lower)]
    #[component(variant)]
    pub enum LookupOutcome {
        #[component(name = "not-found")]
        NotFound,
        /// Bincode-encoded ExternalUser.
        #[component(name = "found")]
        Found(Vec<u8>),
    }

    #[derive(Debug, Clone, ComponentType, Lift, Lower)]
    #[component(record)]
    pub struct ValidationResult {
        pub ok: bool,
        pub reason: String,
    }
}
