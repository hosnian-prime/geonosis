//! Application state for the admin UI.

use std::sync::Arc;

use thiserror::Error;

use geonosis_audit::Publisher;
use geonosis_i18n::I18n;
use geonosis_storage::Storage;
use geonosis_theme::TemplateOverlay;

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
}

impl AdminState {
    /// Build an admin state backed by a no-op audit publisher. Used
    /// by tests and the legacy quickstart path that doesn't carry a
    /// real audit pipeline yet.
    pub fn new(storage: Arc<dyn Storage>) -> Result<Self, AdminError> {
        Self::with_audit(storage, Arc::new(Publisher::new(vec![])))
    }

    /// Build an admin state with the supplied audit publisher. The
    /// server's `app.rs` uses this so admin REST writes share the
    /// same fan-out (Postgres + webhook + any future sink) as the
    /// OIDC request path.
    pub fn with_audit(
        storage: Arc<dyn Storage>,
        audit: Arc<Publisher>,
    ) -> Result<Self, AdminError> {
        let i18n = Arc::new(I18n::load_embedded().map_err(|e| AdminError::I18n(e.to_string()))?);
        let theme = Arc::new(TemplateOverlay::new());
        Ok(Self {
            storage,
            i18n,
            theme,
            audit,
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
        let status = match &self {
            AdminError::NotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.to_string()).into_response()
    }
}
