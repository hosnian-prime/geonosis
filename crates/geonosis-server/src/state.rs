//! Application state injected into axum handlers.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use url::Url;

use geonosis_audit::Publisher;
use geonosis_broker::BuiltinAdapters;
use geonosis_cache::LocalCache;
use geonosis_crypto::SoftwareKms;
use geonosis_spi_host::runtime::WasmEngine;
use geonosis_spi_host::ProviderRegistry;
use geonosis_storage::Storage;

use crate::authenticators::BuiltinAuthenticators;
use crate::broker::BrokerRuntime;
use crate::ldap::LdapRuntime;
use crate::metrics::SharedMetrics;
use crate::rate_limit::SharedRateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub cache: Arc<LocalCache>,
    pub kms: Arc<SoftwareKms>,
    pub providers: Arc<ProviderRegistry>,
    /// Shared wasmtime engine for SPI plugin dispatch. Built once at
    /// boot and threaded into the per-WIT runtimes (WasmAuthnRuntime,
    /// WasmEventRuntime, ...) that resolve Wasm-origin bindings.
    pub wasm_engine: Arc<WasmEngine>,
    pub audit: Arc<Publisher>,
    /// Public base URL for issuer / discovery construction (e.g. `https://geonosis.example`).
    pub public_base_url: Url,
    /// BLAKE3-keyed base key for refresh-token storage. Per-realm keys
    /// are derived via `derive_realm_key(base, realm_id, b"refresh")`.
    pub refresh_hash_key: [u8; 32],
    /// BLAKE3-keyed base key for client_secret storage. Per-realm keys
    /// are derived via `derive_realm_key(base, realm_id, b"client-secret")`.
    pub client_secret_hash_key: [u8; 32],
    /// Built-in authenticator runtimes (singletons; per-realm config is
    /// passed through `AuthnContext` at dispatch time).
    pub authenticators: Arc<BuiltinAuthenticators>,
    /// First-party broker-adapter implementations (Google / GitHub / Apple /
    /// Microsoft + the generic OIDC adapter). Selected per IdP via
    /// `IdentityProvider.adapter_urn`.
    pub broker_adapters: Arc<BuiltinAdapters>,
    /// Long-lived broker runtime: discovery + JWKS cache + reqwest pool.
    pub broker: Arc<BrokerRuntime>,
    /// LDAP federation runtime — per-realm pool registry. `None` when
    /// the deployment hasn't configured any LDAP source.
    pub ldap: Arc<LdapRuntime>,
    /// Prometheus counter registry mounted on `/metrics`.
    pub metrics: SharedMetrics,
    /// Per-realm rate limiter. v0.1.x supports two tiers: per-pod
    /// token bucket (always) + cluster-wide Redis sliding window
    /// (when configured via `redis-rate-limit` feature).
    pub rate_limiter: SharedRateLimiter,
    /// Per-pod drain flag. `POST /-/drain` flips this to `true`; the
    /// readiness probe then returns 503 so the ingress controller can
    /// pull the pod out of rotation before the `preStop` sleep
    /// elapses. Liveness deliberately ignores it — draining must not
    /// trigger a restart. Per `docs/11-deployment-k8s.md` §"Rolling
    /// updates".
    pub draining: Arc<AtomicBool>,
}
