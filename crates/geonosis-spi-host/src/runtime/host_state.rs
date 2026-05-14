//! Per-call wasmtime `Store` payload.

use std::collections::HashMap;

use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiView};

use crate::runtime::allowlist::HostAllowlist;

/// Payload carried by every `Store`. Wires the WASI context + the
/// host's per-call secrets, allowlist, and http client.
pub struct HostState {
    pub wasi: WasiCtx,
    pub table: ResourceTable,
    pub secrets: HashMap<String, Vec<u8>>,
    pub egress: HostAllowlist,
    pub http: reqwest::Client,
    pub provider_urn: String,
    /// Per-call memory cap enforced via `wasmtime::ResourceLimiter`.
    /// Owned by HostState so its lifetime matches the Store's.
    pub memory_cap_bytes: u64,
    pub(crate) limiter: MemoryLimiter,
}

#[derive(Debug)]
pub struct MemoryLimiter {
    pub cap: u64,
}

impl wasmtime::ResourceLimiter for MemoryLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok((desired as u64) <= self.cap)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        Ok(true)
    }
}

impl HostState {
    pub fn builder(provider_urn: impl Into<String>) -> HostStateBuilder {
        HostStateBuilder {
            secrets: HashMap::new(),
            egress: HostAllowlist::default(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .user_agent(format!("geonosis-spi-host/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("reqwest client"),
            provider_urn: provider_urn.into(),
        }
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
}

pub struct HostStateBuilder {
    secrets: HashMap<String, Vec<u8>>,
    egress: HostAllowlist,
    http: reqwest::Client,
    provider_urn: String,
}

impl HostStateBuilder {
    pub fn secret(mut self, key: impl Into<String>, value: Vec<u8>) -> Self {
        self.secrets.insert(key.into(), value);
        self
    }

    pub fn egress(mut self, allowlist: HostAllowlist) -> Self {
        self.egress = allowlist;
        self
    }

    pub fn http(mut self, client: reqwest::Client) -> Self {
        self.http = client;
        self
    }

    pub fn build(self) -> HostState {
        // Build a deliberately bare WASI context — no stdio, no
        // filesystem, no environment.
        let wasi = WasiCtxBuilder::new().build();
        HostState {
            wasi,
            table: ResourceTable::new(),
            secrets: self.secrets,
            egress: self.egress,
            http: self.http,
            provider_urn: self.provider_urn,
            memory_cap_bytes: 0,
            limiter: MemoryLimiter { cap: 0 },
        }
    }
}
