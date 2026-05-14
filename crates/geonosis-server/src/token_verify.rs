//! Verify a Geonosis-issued access token (JWS) using the realm's
//! active signing key. Used by `/userinfo` + `/introspect`.

use thiserror::Error;

use geonosis_core::{AccessTokenClaims, Realm};
use geonosis_crypto::base64url;
use geonosis_crypto::jwt::{verify_jwt, JwsHeader};
use geonosis_crypto::KeyManagementService;

use crate::state::AppState;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("malformed jwt: {0}")]
    Malformed(String),
    #[error("signature invalid: {0}")]
    Signature(String),
    #[error("expired")]
    Expired,
    #[error("issuer mismatch: token={0}")]
    IssuerMismatch(String),
    #[error("kms: {0}")]
    Kms(String),
}

/// Verify a presented bearer token: split, parse header, look up the
/// signing key by `kid`, verify signature, check `exp`/`iat`, return
/// the parsed claims.
pub async fn verify_access_token(
    state: &AppState,
    realm: &Realm,
    token: &str,
) -> Result<AccessTokenClaims, VerifyError> {
    let mut parts = token.split('.');
    let h_b64 = parts
        .next()
        .ok_or_else(|| VerifyError::Malformed("no header".into()))?;
    let _ = parts
        .next()
        .ok_or_else(|| VerifyError::Malformed("no payload".into()))?;
    let _ = parts
        .next()
        .ok_or_else(|| VerifyError::Malformed("no sig".into()))?;
    let header_bytes =
        base64url::decode(h_b64).map_err(|e| VerifyError::Malformed(e.to_string()))?;
    let header: JwsHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| VerifyError::Malformed(e.to_string()))?;

    let kid: geonosis_core::KeyId = header
        .kid
        .parse()
        .map_err(|e: geonosis_core::id::IdParseError| VerifyError::Malformed(e.to_string()))?;
    let alg = match header.alg.as_str() {
        "RS256" => geonosis_core::JwsAlgorithm::RS256,
        "ES256" => geonosis_core::JwsAlgorithm::ES256,
        "EdDSA" => geonosis_core::JwsAlgorithm::EdDSA,
        other => return Err(VerifyError::Signature(format!("alg {other} not supported"))),
    };

    let public = state
        .kms
        .load_public(&kid)
        .await
        .map_err(|e| VerifyError::Kms(e.to_string()))?;

    let claims: AccessTokenClaims = verify_jwt(token, alg, &header.kid, &public)
        .map_err(|e| VerifyError::Signature(e.to_string()))?;

    let now = chrono::Utc::now().timestamp();
    if claims.exp < now {
        return Err(VerifyError::Expired);
    }

    let expected_iss = format!(
        "{}/realms/{}",
        state.public_base_url.as_str().trim_end_matches('/'),
        realm.slug
    );
    if claims.iss != expected_iss {
        return Err(VerifyError::IssuerMismatch(claims.iss.clone()));
    }

    Ok(claims)
}
