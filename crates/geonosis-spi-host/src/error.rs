use thiserror::Error;

pub type ProviderResult<T> = Result<T, ProviderError>;

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("provider {0} not found")]
    NotFound(String),
    #[error("provider {0} quarantined: {1}")]
    Quarantined(String, String),
    #[error("provider {0} error: {1}")]
    Backend(String, String),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
}
