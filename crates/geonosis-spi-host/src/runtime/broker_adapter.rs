//! `geonosis:broker-adapter@0.1.0` invocation glue.
//!
//! Four lifecycle exports per WIT:
//! - build-authn-url
//! - parse-callback
//! - validate-assertion
//! - enrich-claims
//!
//! Dispatch mode: NamedSelect — caller passes the IdP's adapter URN
//! (`builtin:broker-adapter:google`, `wasm:my-vendor:...`); exactly
//! one adapter runs per phase.

use std::sync::Arc;

use wasmtime::component::{Component, Linker};
use wasmtime::Store;

use crate::runtime::engine::{RuntimeError, WasmEngine};
use crate::runtime::host_state::HostState;
use crate::runtime::limits::ResourceLimits;

pub struct WasmBrokerAdapterRuntime {
    engine: Arc<WasmEngine>,
    component: Component,
    component_sha256: String,
    limits: ResourceLimits,
}

impl WasmBrokerAdapterRuntime {
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

    pub async fn build_authn_url(
        &self,
        host_state: HostState,
        req: wire::AuthnRequest,
        config: &[u8],
    ) -> Result<String, RuntimeError> {
        let mut store = self.fresh_store(host_state)?;
        let linker: Linker<HostState> = Linker::new(self.engine.engine());
        let instance = linker
            .instantiate_async(&mut store, &self.component)
            .await
            .map_err(|e| RuntimeError::Instantiate(e.to_string()))?;

        let func = instance
            .get_typed_func::<
                (wire::AuthnRequest, Vec<u8>),
                (Result<String, super::wire_error::Wire>,),
            >(&mut store, "build-authn-url")
            .map_err(|e| RuntimeError::Plugin(format!("export not found: {e}")))?;

        let call = func.call_async(&mut store, (req, config.to_vec()));
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
            Ok(url) => Ok(url),
            Err(w) => Err(RuntimeError::Plugin(format!(
                "{}: {} (retryable={})",
                w.kind, w.message, w.retryable
            ))),
        }
    }

    pub async fn parse_callback(
        &self,
        host_state: HostState,
        raw: wire::RawCallback,
        config: &[u8],
    ) -> Result<wire::BrokerAssertion, RuntimeError> {
        self.assertion_phase(host_state, "parse-callback", raw, config).await
    }

    pub async fn validate_assertion(
        &self,
        host_state: HostState,
        assertion: wire::BrokerAssertion,
        config: &[u8],
    ) -> Result<wire::BrokerAssertion, RuntimeError> {
        self.assertion_phase(host_state, "validate-assertion", assertion, config).await
    }

    async fn assertion_phase<In>(
        &self,
        host_state: HostState,
        export: &str,
        input: In,
        config: &[u8],
    ) -> Result<wire::BrokerAssertion, RuntimeError>
    where
        In: wasmtime::component::Lower
            + wasmtime::component::ComponentType
            + Send
            + Sync
            + 'static,
    {
        let mut store = self.fresh_store(host_state)?;
        let linker: Linker<HostState> = Linker::new(self.engine.engine());
        let instance = linker
            .instantiate_async(&mut store, &self.component)
            .await
            .map_err(|e| RuntimeError::Instantiate(e.to_string()))?;

        let func = instance
            .get_typed_func::<
                (In, Vec<u8>),
                (Result<wire::BrokerAssertion, super::wire_error::Wire>,),
            >(&mut store, export)
            .map_err(|e| RuntimeError::Plugin(format!("export not found: {e}")))?;

        let call = func.call_async(&mut store, (input, config.to_vec()));
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
            Ok(out) => Ok(out),
            Err(w) => Err(RuntimeError::Plugin(format!(
                "{}: {} (retryable={})",
                w.kind, w.message, w.retryable
            ))),
        }
    }

    pub async fn enrich_claims(
        &self,
        host_state: HostState,
        assertion: wire::BrokerAssertion,
        config: &[u8],
    ) -> Result<Vec<u8>, RuntimeError> {
        let mut store = self.fresh_store(host_state)?;
        let linker: Linker<HostState> = Linker::new(self.engine.engine());
        let instance = linker
            .instantiate_async(&mut store, &self.component)
            .await
            .map_err(|e| RuntimeError::Instantiate(e.to_string()))?;

        let func = instance
            .get_typed_func::<
                (wire::BrokerAssertion, Vec<u8>),
                (Result<Vec<u8>, super::wire_error::Wire>,),
            >(&mut store, "enrich-claims")
            .map_err(|e| RuntimeError::Plugin(format!("export not found: {e}")))?;

        let call = func.call_async(&mut store, (assertion, config.to_vec()));
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
            Ok(claims) => Ok(claims),
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

pub mod wire {
    use wasmtime::component::{ComponentType, Lift, Lower};

    #[derive(Debug, Clone, ComponentType, Lift, Lower)]
    #[component(record)]
    pub struct AuthnRequest {
        pub realm: String,
        #[component(name = "idp-alias")]
        pub idp_alias: String,
        #[component(name = "redirect-uri")]
        pub redirect_uri: String,
        pub state: String,
        pub nonce: Option<String>,
        pub scopes: Vec<String>,
        #[component(name = "pkce-challenge")]
        pub pkce_challenge: Option<String>,
    }

    #[derive(Debug, Clone, ComponentType, Lift, Lower)]
    #[component(record)]
    pub struct RawCallback {
        pub params: Vec<(String, String)>,
        pub body: Option<Vec<u8>>,
    }

    #[derive(Debug, Clone, ComponentType, Lift, Lower)]
    #[component(record)]
    pub struct BrokerAssertion {
        pub subject: String,
        #[component(name = "idp-alias")]
        pub idp_alias: String,
        pub attributes: Vec<(String, String)>,
        #[component(name = "raw-claims")]
        pub raw_claims: Vec<u8>,
        #[component(name = "issued-at")]
        pub issued_at: u64,
        #[component(name = "expires-at")]
        pub expires_at: Option<u64>,
    }
}
