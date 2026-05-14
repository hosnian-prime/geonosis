//! Client authentication helper used by `/token`, `/revoke`, `/introspect`,
//! `/par`. Per `docs/03-protocols-oidc.md` §Client authentication, the
//! method MUST match the client's `auth_method` setting.
//!
//! v0.1 supports:
//! - `client_secret_basic` — Authorization: Basic base64(id:secret)
//! - `client_secret_post`  — `client_id` + `client_secret` form fields
//! - `none`                — public clients, PKCE-only (no secret)
//!
//! `client_secret_jwt` and `private_key_jwt` types are recognized for
//! discovery but rejected at runtime with `invalid_client` (assertion
//! verification lands in v0.1.x).

use std::collections::BTreeMap;

use axum::http::HeaderMap;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use geonosis_core::{Client, ClientAuthMethod, ClientKind, RealmId};
use geonosis_crypto::hash::{ct_eq, token_hash};
use geonosis_protocol_oauth::{OAuthError, OAuthErrorCode};

use crate::state::AppState;

/// Result of resolving + authenticating the client. `subject_to_client_auth`
/// is true when authentication was actually performed; for public clients
/// it is false (PKCE in the grant layer is the substitute).
#[derive(Debug, Clone)]
pub struct AuthenticatedClient {
    pub client: Client,
    pub method_used: ClientAuthMethod,
}

pub async fn authenticate_client(
    state: &AppState,
    realm_id: RealmId,
    headers: &HeaderMap,
    form: &BTreeMap<String, String>,
) -> Result<AuthenticatedClient, OAuthError> {
    // Pull credentials from header OR body.
    let (presented_id, presented_secret) = match parse_basic_auth(headers) {
        Some((id, secret)) => (id, Some(secret)),
        None => {
            let id = form
                .get("client_id")
                .cloned()
                .ok_or_else(|| OAuthError::invalid_client("missing client_id"))?;
            let secret = form.get("client_secret").cloned();
            (id, secret)
        }
    };

    let client = state
        .storage
        .get_client_by_client_id(realm_id, &presented_id)
        .await
        .map_err(|_| OAuthError::invalid_client("unknown client"))?;
    if !client.enabled {
        return Err(OAuthError::invalid_client("client disabled"));
    }

    match client.auth_method {
        ClientAuthMethod::None => {
            if client.kind != ClientKind::Public {
                return Err(OAuthError::invalid_client(
                    "auth_method=none only valid for public clients",
                ));
            }
            Ok(AuthenticatedClient {
                client,
                method_used: ClientAuthMethod::None,
            })
        }
        method @ (ClientAuthMethod::ClientSecretBasic | ClientAuthMethod::ClientSecretPost) => {
            let secret = presented_secret
                .ok_or_else(|| OAuthError::invalid_client("client_secret required"))?;
            let stored_hash = state
                .storage
                .get_client_secret_hash(realm_id, client.id)
                .await
                .map_err(|_| OAuthError::invalid_client("client has no secret configured"))?;
            let presented_hash =
                hex::encode(token_hash(&state.client_secret_hash_key, secret.as_bytes()));
            if !ct_eq(stored_hash.as_bytes(), presented_hash.as_bytes()) {
                return Err(OAuthError::invalid_client("client_secret mismatch"));
            }
            Ok(AuthenticatedClient {
                client,
                method_used: method,
            })
        }
        ClientAuthMethod::ClientSecretJwt | ClientAuthMethod::PrivateKeyJwt => {
            // JWT assertion verification lands in v0.1.x. Reject explicitly
            // until the path is wired (per RFC 6749, return invalid_client).
            Err(OAuthError::invalid_client(
                "JWT-based client auth not yet wired in v0.1",
            ))
        }
        ClientAuthMethod::TlsClientAuth => Err(OAuthError::invalid_client(
            "tls_client_auth is v0.2",
        )),
    }
}

fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let h = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let rest = h.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(rest.trim()).ok()?;
    let s = std::str::from_utf8(&decoded).ok()?;
    let (id, secret) = s.split_once(':')?;
    let id = percent_decode(id);
    let secret = percent_decode(secret);
    Some((id, secret))
}

fn percent_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Bearer token extraction for `/userinfo` + `/introspect` introspection auth.
pub fn bearer_from(headers: &HeaderMap) -> Option<String> {
    let h = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    h.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

/// Wrap a non-OAuth-shaped error.
pub fn server_err(msg: impl Into<String>) -> OAuthError {
    OAuthError::new(OAuthErrorCode::ServerError, msg)
}
