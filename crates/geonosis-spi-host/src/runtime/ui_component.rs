//! `geonosis:ui-component@0.1.0` invocation glue.
//!
//! Single export `render(ctx, locals) -> result<rendered-html, plugin-error>`.
//! Dispatch mode: NamedSelect — the theme overlay binds each slot to
//! exactly one component URN; the renderer asks that one component
//! for HTML.
//!
//! Security note: the host emits the `csp-nonce` value the plugin
//! MUST echo on inline `<script>` tags. The host's response-rewrite
//! middleware strips scripts with mismatched nonces; plugin-side
//! escaping is still required for any user-controlled `locals`.

use std::sync::Arc;

use wasmtime::component::{Component, Linker};
use wasmtime::Store;

use crate::runtime::engine::{RuntimeError, WasmEngine};
use crate::runtime::host_state::HostState;
use crate::runtime::limits::ResourceLimits;

pub struct WasmUiComponentRuntime {
    engine: Arc<WasmEngine>,
    component: Component,
    component_sha256: String,
    limits: ResourceLimits,
}

impl WasmUiComponentRuntime {
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

    pub async fn render(
        &self,
        host_state: HostState,
        ctx: wire::ComponentContext,
        locals: &[u8],
    ) -> Result<wire::RenderedHtml, RuntimeError> {
        let mut store = self.fresh_store(host_state)?;
        let linker: Linker<HostState> = Linker::new(self.engine.engine());
        let instance = linker
            .instantiate_async(&mut store, &self.component)
            .await
            .map_err(|e| RuntimeError::Instantiate(e.to_string()))?;

        let func = instance
            .get_typed_func::<
                (wire::ComponentContext, Vec<u8>),
                (Result<wire::RenderedHtml, super::wire_error::Wire>,),
            >(&mut store, "render")
            .map_err(|e| RuntimeError::Plugin(format!("export not found: {e}")))?;

        let call = func.call_async(&mut store, (ctx, locals.to_vec()));
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
    pub struct ComponentContext {
        pub realm: String,
        pub slot: String,
        pub locale: String,
        #[component(name = "csp-nonce")]
        pub csp_nonce: String,
    }

    #[derive(Debug, Clone, ComponentType, Lift, Lower)]
    #[component(record)]
    pub struct RenderedHtml {
        pub html: String,
        #[component(name = "csp-extra")]
        pub csp_extra: Vec<(String, String)>,
    }
}
