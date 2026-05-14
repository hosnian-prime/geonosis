//! `/realms/{slug}/protocol/openid-connect/par` (RFC 9126).
//!
//! Authenticates the client, validates the embedded authorize-request
//! parameters using the same parser as `/authorize`, stores them under
//! a fresh `request_uri`, and returns the URI + TTL.

use std::collections::BTreeMap;

use axum::extract::{Form, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};

use geonosis_protocol_oidc::{
    generate_request_uri, AuthorizeRequest, ParResponse, PAR_DEFAULT_TTL_SECS,
};
use geonosis_storage::ParRequest;

use crate::handlers::client_auth::authenticate_client;
use crate::handlers::error::oauth_error_response;
use crate::state::AppState;

pub async fn par(
    Path(slug): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> Response {
    let realm = match state.storage.get_realm_by_slug(&slug).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::NOT_FOUND, "realm not found").into_response(),
    };
    let authed = match authenticate_client(&state, realm.id, &headers, &form).await {
        Ok(a) => a,
        Err(e) => return oauth_error_response(&e),
    };

    // Validate the embedded authorize request (without enforcing redirect-
    // uri exact-match here; that runs at /authorize when the URI is
    // dereferenced).
    let mut params = form.clone();
    // Strip client_secret to avoid persisting it.
    params.remove("client_secret");
    let req = match AuthorizeRequest::parse(params.clone()) {
        Ok(r) => r,
        Err(e) => {
            return oauth_error_response(&geonosis_protocol_oauth::OAuthError::invalid_request(
                e.to_string(),
            ))
        }
    };
    if req.client_id != authed.client.client_id {
        return oauth_error_response(&geonosis_protocol_oauth::OAuthError::invalid_request(
            "client_id mismatch between auth and request body",
        ));
    }

    let uri = generate_request_uri();
    let row = ParRequest {
        request_uri: uri.clone(),
        realm_id: realm.id,
        client_id: authed.client.id,
        params,
        created_at: Utc::now(),
        expires_at: Utc::now() + Duration::seconds(PAR_DEFAULT_TTL_SECS),
    };
    if let Err(e) = state.storage.save_par_request(row).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    (
        StatusCode::CREATED,
        Json(ParResponse {
            request_uri: uri,
            expires_in: PAR_DEFAULT_TTL_SECS,
        }),
    )
        .into_response()
}
