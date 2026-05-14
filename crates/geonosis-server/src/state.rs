//! Application state injected into axum handlers.

use std::sync::Arc;

use url::Url;

use geonosis_audit::Publisher;
use geonosis_cache::LocalCache;
use geonosis_crypto::SoftwareKms;
use geonosis_spi_host::ProviderRegistry;
use geonosis_storage::Storage;

use crate::authenticators::BuiltinAuthenticators;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub cache: Arc<LocalCache>,
    pub kms: Arc<SoftwareKms>,
    pub providers: Arc<ProviderRegistry>,
    pub audit: Arc<Publisher>,
    /// Public base URL for issuer / discovery construction (e.g. `https://geonosis.example`).
    pub public_base_url: Url,
    /// BLAKE3-keyed hash key for refresh-token storage (per-realm derivation
    /// is the v0.1.x follow-up; this is a single deployment-wide key).
    pub refresh_hash_key: [u8; 32],
    /// BLAKE3-keyed hash key for client_secret storage (separate domain
    /// from refresh tokens).
    pub client_secret_hash_key: [u8; 32],
    /// Built-in authenticator runtimes (singletons; per-realm config is
    /// passed through `AuthnContext` at dispatch time).
    pub authenticators: Arc<BuiltinAuthenticators>,
}
