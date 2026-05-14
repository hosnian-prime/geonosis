//! In-memory + on-disk module store.
//!
//! Plugins are stored as raw `.wasm` bytes (Postgres `bytea` in
//! production). The runtime compiles them on first use, persists the
//! resulting `cwasm` to disk, and caches the compiled `Component` in
//! memory keyed by SHA-256 so subsequent calls skip the compile cost.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use sha2::Digest;
use wasmtime::component::Component;
use wasmtime::Engine;

use crate::runtime::engine::RuntimeError;
use crate::runtime::limits::SandboxConfig;

#[derive(Clone)]
pub struct ModuleStore {
    inner: Arc<Mutex<ModuleStoreInner>>,
    cwasm_root: Option<PathBuf>,
}

struct ModuleStoreInner {
    /// SHA-256 hex -> compiled component (kept alive while in use).
    components: std::collections::HashMap<String, Component>,
    capacity: usize,
}

impl ModuleStore {
    pub fn new(cfg: &SandboxConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ModuleStoreInner {
                components: std::collections::HashMap::new(),
                capacity: cfg.component_cache_max as usize,
            })),
            cwasm_root: cfg.cwasm_cache_root.clone(),
        }
    }

    /// Cache key for a wasm blob.
    pub fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = sha2::Sha256::new();
        h.update(bytes);
        hex::encode(h.finalize())
    }

    /// Compile a `Component` from the given bytes, persisting the
    /// `cwasm` form to disk and caching the result in memory.
    pub fn load(&self, engine: &Engine, bytes: &[u8]) -> Result<(String, Component), RuntimeError> {
        let key = Self::sha256_hex(bytes);
        if let Some(c) = self.inner.lock().components.get(&key).cloned() {
            return Ok((key, c));
        }
        let cwasm_path = self
            .cwasm_root
            .as_ref()
            .map(|root| root.join(format!("{key}.cwasm")));
        // Compile from source bytes. v0.1 skips the `cwasm` deserialize
        // fast path because `Component::deserialize_file` is `unsafe`
        // and the workspace forbids unsafe blocks; the cwasm bytes are
        // still persisted so a future read-side path (gated on a
        // dedicated unsafe-allowed module) can use them.
        let c = Component::new(engine, bytes).map_err(|e| RuntimeError::Compile(e.to_string()))?;
        if let Some(p) = cwasm_path.as_ref() {
            let bytes_out = c.serialize().map_err(|e| RuntimeError::Compile(e.to_string()))?;
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::write(p, bytes_out) {
                tracing::warn!(error = %e, path = ?p, "cwasm persist failed");
            }
        }
        self.intern(key.clone(), c.clone());
        Ok((key, c))
    }

    fn intern(&self, key: String, c: Component) {
        let mut inner = self.inner.lock();
        if inner.components.len() >= inner.capacity {
            // Crude LRU substitute: drop the first entry. v0.1.x replaces
            // with `LinkedHashMap`; the cache size is large enough that
            // this rarely fires.
            if let Some(k) = inner.components.keys().next().cloned() {
                inner.components.remove(&k);
            }
        }
        inner.components.insert(key, c);
    }

    pub fn cache_size(&self) -> usize {
        self.inner.lock().components.len()
    }

    pub fn cwasm_root(&self) -> Option<&Path> {
        self.cwasm_root.as_deref()
    }
}
