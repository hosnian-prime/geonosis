//! Application state for the admin UI.

use std::sync::Arc;

use thiserror::Error;

use geonosis_i18n::I18n;
use geonosis_storage::Storage;
use geonosis_theme::TemplateOverlay;

#[derive(Clone)]
pub struct AdminState {
    pub storage: Arc<dyn Storage>,
    pub i18n: Arc<I18n>,
    pub theme: Arc<TemplateOverlay>,
}

impl AdminState {
    pub fn new(storage: Arc<dyn Storage>) -> Result<Self, AdminError> {
        let i18n = Arc::new(I18n::load_embedded().map_err(|e| AdminError::I18n(e.to_string()))?);
        let theme = Arc::new(TemplateOverlay::new());
        Ok(Self { storage, i18n, theme })
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
