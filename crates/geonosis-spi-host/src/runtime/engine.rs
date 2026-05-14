//! Shared wasmtime engine + sandbox plumbing.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use thiserror::Error;
use wasmtime::{Config, Engine};

use crate::runtime::limits::SandboxConfig;
use crate::runtime::store::ModuleStore;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("wasmtime engine build: {0}")]
    Engine(String),
    #[error("compile: {0}")]
    Compile(String),
    #[error("instantiate: {0}")]
    Instantiate(String),
    #[error("call: {0}")]
    Call(String),
    #[error("trap: {0}")]
    Trap(String),
    #[error("fuel exhausted")]
    FuelExhausted,
    #[error("wall-clock timeout after {ms}ms")]
    Timeout { ms: u64 },
    #[error("memory cap exceeded")]
    MemoryExceeded,
    #[error("egress denied for {0}")]
    EgressDenied(String),
    #[error("secret not found: {0}")]
    SecretMissing(String),
    #[error("plugin error: {0}")]
    Plugin(String),
}

/// Wraps the process-wide wasmtime Engine + module cache. The ticker
/// thread is spawned once and stays alive for the whole process.
pub struct WasmEngine {
    engine: Engine,
    pub modules: ModuleStore,
    cfg: SandboxConfig,
}

impl WasmEngine {
    pub fn new(cfg: SandboxConfig) -> Result<Arc<Self>, RuntimeError> {
        let mut c = Config::new();
        c.async_support(true);
        c.wasm_component_model(true);
        c.consume_fuel(true);
        c.epoch_interruption(true);
        let engine = Engine::new(&c).map_err(|e| RuntimeError::Engine(e.to_string()))?;
        let modules = ModuleStore::new(&cfg);
        let me = Arc::new(Self {
            engine: engine.clone(),
            modules,
            cfg,
        });
        spawn_ticker(engine, me.cfg.epoch_tick_ms);
        Ok(me)
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub fn config(&self) -> &SandboxConfig {
        &self.cfg
    }
}

/// Spawn a tick thread that bumps the engine's epoch on a 1 ms interval
/// (configurable). Every Store has an epoch deadline; per-call code
/// computes the deadline as `engine.epoch() + (wall_clock_ms /
/// epoch_tick_ms)` so the call traps when the wall-clock budget is
/// exhausted. The thread runs for the lifetime of the engine.
fn spawn_ticker(engine: Engine, period_ms: u64) {
    thread::Builder::new()
        .name("wasmtime-epoch-ticker".into())
        .spawn(move || {
            let dur = Duration::from_millis(period_ms.max(1));
            loop {
                thread::sleep(dur);
                engine.increment_epoch();
            }
        })
        .expect("epoch ticker spawn");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_builds_with_defaults() {
        let _e = WasmEngine::new(SandboxConfig::default()).expect("engine builds");
    }

    #[test]
    fn epoch_ticks_forward() {
        let e = WasmEngine::new(SandboxConfig {
            epoch_tick_ms: 1,
            ..Default::default()
        })
        .unwrap();
        let _ = e.engine().clone();
    }
}
