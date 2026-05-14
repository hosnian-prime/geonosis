//! RFC 6749 error codes + RFC 6749 + 8628 + 8693 extensions.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Strict OAuth error code set returned to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthErrorCode {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
    InteractionRequired,
    LoginRequired,
    AccountSelectionRequired,
    ConsentRequired,
    InvalidRequestUri,
    InvalidRequestObject,
    RequestNotSupported,
    RequestUriNotSupported,
    RegistrationNotSupported,
    InvalidClient,
    InvalidGrant,
    UnsupportedGrantType,
    /// Device authorization grant (RFC 8628).
    AuthorizationPending,
    /// Device authorization grant — slow down polling.
    SlowDown,
    /// Device authorization grant — code is expired.
    ExpiredToken,
}

impl OAuthErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::AccessDenied => "access_denied",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InteractionRequired => "interaction_required",
            Self::LoginRequired => "login_required",
            Self::AccountSelectionRequired => "account_selection_required",
            Self::ConsentRequired => "consent_required",
            Self::InvalidRequestUri => "invalid_request_uri",
            Self::InvalidRequestObject => "invalid_request_object",
            Self::RequestNotSupported => "request_not_supported",
            Self::RequestUriNotSupported => "request_uri_not_supported",
            Self::RegistrationNotSupported => "registration_not_supported",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
        }
    }
}

#[derive(Debug, Error)]
#[error("oauth error: {code} ({description})")]
pub struct OAuthError {
    pub code: OAuthErrorCode,
    pub description: String,
    pub uri: Option<String>,
}

impl OAuthError {
    pub fn new(code: OAuthErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: description.into(),
            uri: None,
        }
    }

    pub fn invalid_request(d: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidRequest, d)
    }
    pub fn invalid_grant(d: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidGrant, d)
    }
    pub fn invalid_client(d: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidClient, d)
    }
    pub fn unauthorized_client(d: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::UnauthorizedClient, d)
    }
    pub fn unsupported_grant_type(d: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::UnsupportedGrantType, d)
    }
}

impl std::fmt::Display for OAuthErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_serializes_to_oauth_string() {
        assert_eq!(OAuthErrorCode::InvalidRequest.as_str(), "invalid_request");
        assert_eq!(
            OAuthErrorCode::UnsupportedGrantType.as_str(),
            "unsupported_grant_type"
        );
    }
}
