//! JAR (RFC 9101) — signed `request` parameter processing.
//!
//! Decodes the JWT header to discover `kid` + `alg`, looks up the
//! matching public key from the client's registered authentication
//! keys via the KMS, verifies the signature, then extracts claims
//! and merges them into the authorize params (JWT claims override
//! query params per RFC 9101 §6.3).

use std::collections::BTreeMap;

use geonosis_core::{Client, JwsAlgorithm, KeyId};
use geonosis_crypto::jwt::JwsHeader;
use geonosis_crypto::KeyManagementService;

use crate::state::AppState;

/// Resolve and verify a JAR `request` JWT, returning the merged params.
/// On failure, returns `(error_code, description)`.
pub async fn resolve_request_object(
    state: &AppState,
    client: &Client,
    request_jwt: &str,
    mut query_params: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, (&'static str, String)> {
    // 1. Decode header (unverified) to get kid + alg.
    let header = decode_jwt_header(request_jwt)
        .map_err(|e| ("invalid_request_object", format!("malformed request JWT: {e}")))?;

    let kid = header.kid.clone();
    if kid.is_empty() {
        return Err(("invalid_request_object", "request JWT missing kid".into()));
    }

    let alg = parse_alg(&header.alg)
        .map_err(|e| ("invalid_request_object", format!("unsupported alg: {e}")))?;

    // 2. Verify the kid is registered on this client.
    if !client.client_authentication_keys.is_empty()
        && !client.client_authentication_keys.iter().any(|k| k == &kid)
    {
        return Err((
            "invalid_request_object",
            "request JWT kid not registered on client".into(),
        ));
    }

    // 3. Load public key from KMS.
    let key_id: KeyId = kid
        .parse()
        .map_err(|_| ("invalid_request_object", format!("invalid kid: {kid}")))?;
    let public_key = state
        .kms
        .load_public(&key_id)
        .await
        .map_err(|e| ("invalid_request_object", format!("key lookup failed: {e}")))?;

    // 4. Verify JWT and extract claims.
    let claims: BTreeMap<String, serde_json::Value> =
        geonosis_crypto::verify_jwt(request_jwt, alg, &kid, &public_key)
            .map_err(|e| ("invalid_request_object", format!("signature verification failed: {e}")))?;

    // 5. RFC 9101 §6.3: JWT claims override query params.
    //    `client_id` MUST match if present in both.
    if let Some(jwt_client_id) = claims.get("client_id").and_then(|v| v.as_str()) {
        if let Some(query_client_id) = query_params.get("client_id") {
            if jwt_client_id != query_client_id {
                return Err((
                    "invalid_request_object",
                    "client_id mismatch between query and request object".into(),
                ));
            }
        }
    }

    // Merge: JWT claims override query params.
    for (k, v) in &claims {
        if let Some(s) = v.as_str() {
            query_params.insert(k.clone(), s.to_string());
        } else if let Some(n) = v.as_i64() {
            query_params.insert(k.clone(), n.to_string());
        }
        // Arrays/objects (e.g. `claims` parameter) are skipped for now;
        // they'd need JSON serialization which is a v0.2 concern.
    }

    // Remove the `request` param itself — it's been consumed.
    query_params.remove("request");

    Ok(query_params)
}

fn decode_jwt_header(jwt: &str) -> Result<JwsHeader, String> {
    let header_b64 = jwt.split('.').next().ok_or("no header segment")?;
    let bytes =
        geonosis_crypto::base64url::decode(header_b64).map_err(|e| format!("base64: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("json: {e}"))
}

fn parse_alg(alg: &str) -> Result<JwsAlgorithm, String> {
    match alg {
        "RS256" => Ok(JwsAlgorithm::RS256),
        "ES256" => Ok(JwsAlgorithm::ES256),
        "EdDSA" => Ok(JwsAlgorithm::EdDSA),
        other => Err(format!("unsupported: {other}")),
    }
}

