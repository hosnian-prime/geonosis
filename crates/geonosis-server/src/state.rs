//! Application state injected into axum handlers.

use std::sync::Arc;

use url::Url;

use geonosis_audit::Publisher;
use geonosis_cache::LocalCache;
use geonosis_crypto::SoftwareKms;
use geonosis_spi_host::ProviderRegistry;
use geonosis_storage::Storage;

#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub cache: Arc<LocalCache>,
    pub kms: Arc<SoftwareKms>,
    pub providers: Arc<ProviderRegistry>,
    pub audit: Arc<Publisher>,
    /// Public base URL for issuer / discovery construction (e.g. `https://geonosis.example`).
    pub public_base_url: Url,
}
