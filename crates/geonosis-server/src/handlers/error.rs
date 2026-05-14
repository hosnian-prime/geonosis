//! RFC 6749 §5.2 error response shape.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use geonosis_protocol_oauth::OAuthError;

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
}

impl From<&OAuthError> for ErrorBody {
    fn from(e: &OAuthError) -> Self {
        Self {
            error: e.code.as_str().to_string(),
            error_description: Some(e.description.clone()),
            error_uri: e.uri.clone(),
        }
    }
}

/// Map an `OAuthError` to an HTTP response with the right status. Per
/// RFC 6749 §5.2 most errors land at 400; `invalid_client` is 401.
pub fn oauth_error_response(err: &OAuthError) -> Response {
    use geonosis_protocol_oauth::OAuthErrorCode::*;
    let status = match err.code {
        InvalidClient => StatusCode::UNAUTHORIZED,
        ServerError => StatusCode::INTERNAL_SERVER_ERROR,
        TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_REQUEST,
    };
    let body: ErrorBody = err.into();
    (status, Json(body)).into_response()
}

/// RFC 7807-shaped problem document for non-OAuth endpoints (broker,
/// admin). Keeps the contract narrow so failures stay grep-able.
#[derive(Debug, Serialize)]
pub struct JsonProblem {
    #[serde(skip)]
    pub status: u16,
    pub error: String,
    pub message: String,
}

impl JsonProblem {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: 400,
            error: "invalid_request".into(),
            message: msg.into(),
        }
    }
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: 404,
            error: "not_found".into(),
            message: msg.into(),
        }
    }
    pub fn bad_gateway(msg: impl Into<String>) -> Self {
        Self {
            status: 502,
            error: "upstream_failure".into(),
            message: msg.into(),
        }
    }
    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            status: 500,
            error: "internal_error".into(),
            message: msg.into(),
        }
    }
}

impl IntoResponse for JsonProblem {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(self)).into_response()
    }
}
