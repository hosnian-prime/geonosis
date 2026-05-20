//! Application state for the admin UI.

use std::sync::Arc;

use thiserror::Error;

use geonosis_audit::Publisher;
use geonosis_crypto::SoftwareKms;
use geonosis_i18n::I18n;
use geonosis_storage::Storage;
use geonosis_theme::TemplateOverlay;
use url::Url;

#[derive(Clone)]
pub struct AdminState {
    pub storage: Arc<dyn Storage>,
    pub i18n: Arc<I18n>,
    pub theme: Arc<TemplateOverlay>,
    /// Audit publisher shared with the OIDC request path. Every
    /// state-changing admin handler emits an `AuditEvent` via
    /// [`crate::audit_emit`] so the audit log stays the durable
    /// trace of admin activity (per `docs/13-observability.md`
    /// §"Audit events").
    pub audit: Arc<Publisher>,
    /// KMS for bearer token verification on the admin API path.
    pub kms: Arc<SoftwareKms>,
    /// Public base URL (e.g. `https://geonosis.example`) for issuer
    /// validation when verifying bearer tokens.
    pub public_base_url: Url,
    /// BLAKE3-keyed hash key for client secret hashing. Shared with
    /// the OIDC token endpoint so secrets created by the admin API
    /// are verifiable at the token endpoint.
    pub client_secret_hash_key: [u8; 32],
    /// Optional static API key for headless admin access (CI, CLI).
    /// When set, requests with `X-Admin-Key: <value>` bypass bearer
    /// / session authentication. Set via `GEONOSIS_ADMIN_API_KEY`.
    pub admin_api_key: Option<String>,
}

impl AdminState {
    /// Build an admin state backed by a no-op audit publisher. Used
    /// by tests and the legacy quickstart path that doesn't carry a
    /// real audit pipeline yet.
    pub fn new(storage: Arc<dyn Storage>) -> Result<Self, AdminError> {
        use geonosis_crypto::MasterKey;
        Self::with_audit(
            storage,
            Arc::new(Publisher::new(vec![])),
            Arc::new(SoftwareKms::new(MasterKey::generate())),
            Url::parse("http://localhost:8080").unwrap(),
            [0u8; 32],
            None,
        )
    }

    /// Build an admin state with the supplied audit publisher. The
    /// server's `app.rs` uses this so admin REST writes share the
    /// same fan-out (Postgres + webhook + any future sink) as the
    /// OIDC request path.
    pub fn with_audit(
        storage: Arc<dyn Storage>,
        audit: Arc<Publisher>,
        kms: Arc<SoftwareKms>,
        public_base_url: Url,
        client_secret_hash_key: [u8; 32],
        admin_api_key: Option<String>,
    ) -> Result<Self, AdminError> {
        let i18n = Arc::new(I18n::load_embedded().map_err(|e| AdminError::I18n(e.to_string()))?);
        let theme = Arc::new(TemplateOverlay::new());
        Ok(Self {
            storage,
            i18n,
            theme,
            audit,
            kms,
            public_base_url,
            client_secret_hash_key,
            admin_api_key,
        })
    }
}

#[derive(Debug, Error)]
pub enum AdminError {
    #[error("storage: {0}")]
    Storage(String),
    #[error("i18n: {0}")]
    I18n(String),
    #[error("not found")]
    NotFound,
    /// Realm policy rejected the supplied input (e.g. password
    /// policy violation). The `Vec<String>` is the list of stable
    /// rule codes that failed — clients render them into a
    /// human-readable list.
    #[error("policy violation: {0:?}")]
    PasswordPolicy(Vec<String>),
    /// Client-correctable input error — registration-time validators
    /// reject malformed input (bad redirect_uri scheme, malformed
    /// JSON, etc.) with a 400.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

impl From<geonosis_storage::StorageError> for AdminError {
    fn from(e: geonosis_storage::StorageError) -> Self {
        match e {
            geonosis_storage::StorageError::NotFound => AdminError::NotFound,
            other => AdminError::Storage(other.to_string()),
        }
    }
}

impl axum::response::IntoResponse for AdminError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        match self {
            AdminError::NotFound => {
                (StatusCode::NOT_FOUND, "not found".to_string()).into_response()
            }
            // Policy violations are client-correctable input errors,
            // not server faults — surface them as 400 with the
            // structured violation list so callers can render a
            // useful message per failed rule.
            AdminError::PasswordPolicy(violations) => {
                let body = serde_json::json!({
                    "error": "password_policy_violation",
                    "violations": violations,
                });
                (StatusCode::BAD_REQUEST, axum::Json(body)).into_response()
            }
            AdminError::InvalidInput(msg) => {
                let body = serde_json::json!({
                    "error": "invalid_input",
                    "message": msg,
                });
                (StatusCode::BAD_REQUEST, axum::Json(body)).into_response()
            }
            err => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
        }
    }
}
