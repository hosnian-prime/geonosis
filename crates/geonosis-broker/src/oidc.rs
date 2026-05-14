//! OIDC RP runtime: discovery, JWKS, code exchange, id_token verify.
//!
//! Per `docs/05-identity-broker.md`:
//! - `code` flow (RFC 6749) with PKCE S256 (RFC 7636)
//! - id_token signature validated against JWKS keyed by `kid`
//! - `nonce` checked against the stored `BrokerAuthnState`
//! - `iss`, `aud`, `exp`, `iat`, `nbf` validated strictly
//! - Clock skew tolerance 5 minutes (configurable per realm later)

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine;
use moka::future::Cache;
use parking_lot::Mutex;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};

use geonosis_core::attribute::AttributeValue;
use geonosis_core::common::JwsAlgorithm;
use geonosis_crypto::jwk::Jwk;
use geonosis_crypto::jwt::{verify_jwt, JwsHeader, PublicMaterial};

use crate::types::{BrokerAssertion, BrokerAuthnState, BrokerError, OidcIdpConfig};

const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(8);
const DISCOVERY_TTL: Duration = Duration::from_secs(600);
const JWKS_TTL: Duration = Duration::from_secs(300);
const CLOCK_SKEW_SECS: i64 = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: serde_json::Value,
    pub exp: i64,
    pub iat: i64,
    #[serde(default)]
    pub nbf: Option<i64>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub azp: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Cached `OidcDiscovery` + `JwkSet`. Sharing a single instance across
/// IdPs avoids per-request fetches.
pub struct DiscoveryCache {
    discovery: Cache<String, OidcDiscovery>,
    jwks: Cache<String, Vec<Jwk>>,
    http: reqwest::Client,
    fixtures: Mutex<BTreeMap<String, (OidcDiscovery, Vec<Jwk>)>>,
}

impl Default for DiscoveryCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryCache {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .timeout(DEFAULT_HTTP_TIMEOUT)
            .user_agent(format!("geonosis-broker/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .expect("reqwest client");
        Self {
            discovery: Cache::builder()
                .time_to_live(DISCOVERY_TTL)
                .max_capacity(256)
                .build(),
            jwks: Cache::builder()
                .time_to_live(JWKS_TTL)
                .max_capacity(256)
                .build(),
            http,
            fixtures: Mutex::new(BTreeMap::new()),
        }
    }

    /// Install a synthetic `(discovery, jwks)` for an alias. Used by tests
    /// to bypass network calls.
    pub fn install_fixture(&self, alias: &str, discovery: OidcDiscovery, jwks: Vec<Jwk>) {
        self.fixtures
            .lock()
            .insert(alias.to_string(), (discovery, jwks));
    }

    pub async fn discovery(
        &self,
        alias: &str,
        cfg: &OidcIdpConfig,
    ) -> Result<OidcDiscovery, BrokerError> {
        if let Some((d, _)) = self.fixtures.lock().get(alias).cloned() {
            return Ok(d);
        }
        let key = alias.to_string();
        if let Some(d) = self.discovery.get(&key).await {
            return Ok(d);
        }
        let d = fetch_discovery(&self.http, cfg).await?;
        self.discovery.insert(key, d.clone()).await;
        Ok(d)
    }

    pub async fn jwks(&self, alias: &str, jwks_uri: &str) -> Result<Vec<Jwk>, BrokerError> {
        if let Some((_, j)) = self.fixtures.lock().get(alias).cloned() {
            return Ok(j);
        }
        let key = format!("{alias}|{jwks_uri}");
        if let Some(v) = self.jwks.get(&key).await {
            return Ok(v);
        }
        let v = fetch_jwks(&self.http, jwks_uri).await?;
        self.jwks.insert(key, v.clone()).await;
        Ok(v)
    }

    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }
}

/// Fetch `<issuer>/.well-known/openid-configuration` (or the explicit
/// `discovery_url` when configured).
pub async fn fetch_discovery(
    http: &reqwest::Client,
    cfg: &OidcIdpConfig,
) -> Result<OidcDiscovery, BrokerError> {
    let url = match (&cfg.discovery_url, &cfg.authorization_endpoint) {
        (Some(u), _) => u.clone(),
        (None, _) => format!(
            "{}/.well-known/openid-configuration",
            cfg.issuer.trim_end_matches('/')
        ),
    };
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| BrokerError::Discovery(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(BrokerError::Discovery(format!(
            "{} returned {}",
            url,
            resp.status()
        )));
    }
    let d: OidcDiscovery = resp
        .json()
        .await
        .map_err(|e| BrokerError::Discovery(e.to_string()))?;
    if d.issuer != cfg.issuer {
        return Err(BrokerError::Discovery(format!(
            "issuer mismatch: doc {} cfg {}",
            d.issuer, cfg.issuer
        )));
    }
    Ok(d)
}

pub async fn fetch_jwks(http: &reqwest::Client, jwks_uri: &str) -> Result<Vec<Jwk>, BrokerError> {
    #[derive(Deserialize)]
    struct JwksWire {
        keys: Vec<Jwk>,
    }
    let resp = http
        .get(jwks_uri)
        .send()
        .await
        .map_err(|e| BrokerError::Discovery(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(BrokerError::Discovery(format!(
            "{} returned {}",
            jwks_uri,
            resp.status()
        )));
    }
    let j: JwksWire = resp
        .json()
        .await
        .map_err(|e| BrokerError::Discovery(e.to_string()))?;
    Ok(j.keys)
}

/// Build the canonical `/authorize` URL for the IdP.
pub fn authorization_url(
    discovery: &OidcDiscovery,
    cfg: &OidcIdpConfig,
    redirect_uri: &str,
    state: &str,
    nonce: &str,
    pkce_challenge: Option<&str>,
    extra: &[(&str, &str)],
) -> String {
    let mut url = discovery.authorization_endpoint.clone();
    let mut q = vec![
        ("response_type", "code"),
        ("client_id", cfg.client_id.as_str()),
        ("redirect_uri", redirect_uri),
        ("scope", ""), // overwritten below
        ("state", state),
        ("nonce", nonce),
    ];
    let scope_joined = cfg.scopes.join(" ");
    q[3].1 = &scope_joined;
    if let Some(c) = pkce_challenge {
        q.push(("code_challenge", c));
        q.push(("code_challenge_method", "S256"));
    }
    q.extend_from_slice(extra);

    let qs = q
        .iter()
        .map(|(k, v)| format!("{}={}", k, utf8_percent_encode(v, NON_ALPHANUMERIC)))
        .collect::<Vec<_>>()
        .join("&");
    if url.contains('?') {
        url.push('&');
    } else {
        url.push('?');
    }
    url.push_str(&qs);
    url
}

/// Exchange an authorization code for the OIDC token set.
pub async fn exchange_code(
    http: &reqwest::Client,
    discovery: &OidcDiscovery,
    cfg: &OidcIdpConfig,
    code: &str,
    redirect_uri: &str,
    pkce_verifier: Option<&str>,
) -> Result<TokenResponse, BrokerError> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", cfg.client_id.as_str()),
    ];
    if let Some(v) = pkce_verifier {
        form.push(("code_verifier", v));
    }
    let mut req = http.post(&discovery.token_endpoint).form(&form);
    // Confidential client → HTTP Basic with client_id:client_secret.
    if let Some(secret) = cfg.client_secret.as_ref() {
        req = req.basic_auth(&cfg.client_id, Some(secret.expose()));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| BrokerError::TokenExchange(e.to_string()))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| BrokerError::TokenExchange(e.to_string()))?;
    if !status.is_success() {
        return Err(BrokerError::TokenExchange(format!("{status}: {body}")));
    }
    let token: TokenResponse = serde_json::from_str(&body)
        .map_err(|e| BrokerError::TokenExchange(format!("decode: {e}; body={body}")))?;
    Ok(token)
}

/// Verify an id_token against a JWKS keyed by `kid`, then return the
/// parsed claims. Checks signature, issuer, audience, expiry,
/// not-before, and nonce.
pub fn verify_id_token(
    id_token: &str,
    expected_issuer: &str,
    expected_aud: &str,
    expected_nonce: Option<&str>,
    jwks: &[Jwk],
    now_unix: i64,
) -> Result<IdTokenClaims, BrokerError> {
    let mut parts = id_token.split('.');
    let h_b64 = parts
        .next()
        .ok_or_else(|| BrokerError::Signature("no header".into()))?;
    let _ = parts
        .next()
        .ok_or_else(|| BrokerError::Signature("no payload".into()))?;
    let _ = parts
        .next()
        .ok_or_else(|| BrokerError::Signature("no signature".into()))?;
    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(h_b64)
        .map_err(|e| BrokerError::Signature(e.to_string()))?;
    let header: JwsHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| BrokerError::Signature(e.to_string()))?;
    let alg = match header.alg.as_str() {
        "RS256" => JwsAlgorithm::RS256,
        "ES256" => JwsAlgorithm::ES256,
        "EdDSA" => JwsAlgorithm::EdDSA,
        other => return Err(BrokerError::Signature(format!("unsupported alg: {other}"))),
    };
    let jwk = jwks
        .iter()
        .find(|j| j.kid == header.kid)
        .ok_or_else(|| BrokerError::Signature(format!("no jwk for kid {}", header.kid)))?;
    let public = jwk_to_public(jwk)?;

    let claims: IdTokenClaims = verify_jwt(id_token, alg, &header.kid, &public)
        .map_err(|e| BrokerError::Signature(e.to_string()))?;

    if claims.iss != expected_issuer {
        return Err(BrokerError::InvalidAssertion(format!(
            "iss mismatch: {} vs {}",
            claims.iss, expected_issuer
        )));
    }
    if !audience_matches(&claims.aud, expected_aud) {
        return Err(BrokerError::InvalidAssertion("aud mismatch".into()));
    }
    if claims.exp + CLOCK_SKEW_SECS < now_unix {
        return Err(BrokerError::InvalidAssertion("expired id_token".into()));
    }
    if claims.iat > now_unix + CLOCK_SKEW_SECS {
        return Err(BrokerError::ClockSkew {
            age_secs: claims.iat - now_unix,
        });
    }
    if let Some(nbf) = claims.nbf {
        if nbf > now_unix + CLOCK_SKEW_SECS {
            return Err(BrokerError::InvalidAssertion("nbf in future".into()));
        }
    }
    if let Some(expected) = expected_nonce {
        match claims.nonce.as_deref() {
            Some(got) if got == expected => {}
            _ => return Err(BrokerError::NonceMismatch),
        }
    }

    Ok(claims)
}

fn audience_matches(aud: &serde_json::Value, expected: &str) -> bool {
    match aud {
        serde_json::Value::String(s) => s == expected,
        serde_json::Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some(expected)),
        _ => false,
    }
}

fn jwk_to_public(j: &Jwk) -> Result<PublicMaterial, BrokerError> {
    match (j.kty.as_str(), j.alg.as_str()) {
        ("RSA", "RS256") => {
            let n = j
                .params
                .get("n")
                .and_then(|v| v.as_str())
                .ok_or_else(|| BrokerError::Signature("rsa: missing n".into()))?;
            let e = j
                .params
                .get("e")
                .and_then(|v| v.as_str())
                .ok_or_else(|| BrokerError::Signature("rsa: missing e".into()))?;
            let n_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(n)
                .map_err(|e| BrokerError::Signature(format!("n decode: {e}")))?;
            let e_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(e)
                .map_err(|e| BrokerError::Signature(format!("e decode: {e}")))?;
            let pk = rsa::RsaPublicKey::new(
                rsa::BigUint::from_bytes_be(&n_bytes),
                rsa::BigUint::from_bytes_be(&e_bytes),
            )
            .map_err(|e| BrokerError::Signature(format!("rsa: {e}")))?;
            Ok(PublicMaterial::Rs256(Box::new(pk)))
        }
        ("EC", "ES256") => {
            let x = j
                .params
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| BrokerError::Signature("ec: missing x".into()))?;
            let y = j
                .params
                .get("y")
                .and_then(|v| v.as_str())
                .ok_or_else(|| BrokerError::Signature("ec: missing y".into()))?;
            let x_b = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|e| BrokerError::Signature(format!("x decode: {e}")))?;
            let y_b = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(y)
                .map_err(|e| BrokerError::Signature(format!("y decode: {e}")))?;
            if x_b.len() != 32 || y_b.len() != 32 {
                return Err(BrokerError::Signature("ec: bad coord length".into()));
            }
            let mut sec1 = vec![0x04];
            sec1.extend_from_slice(&x_b);
            sec1.extend_from_slice(&y_b);
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|e| BrokerError::Signature(format!("ec: {e}")))?;
            Ok(PublicMaterial::Es256(vk))
        }
        ("OKP", "EdDSA") => {
            let x = j
                .params
                .get("x")
                .and_then(|v| v.as_str())
                .ok_or_else(|| BrokerError::Signature("okp: missing x".into()))?;
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(x)
                .map_err(|e| BrokerError::Signature(format!("x decode: {e}")))?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| BrokerError::Signature("okp: bad length".into()))?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr)
                .map_err(|e| BrokerError::Signature(format!("okp: {e}")))?;
            Ok(PublicMaterial::EdDsa(vk))
        }
        (kty, alg) => Err(BrokerError::Signature(format!(
            "unsupported jwk: kty={kty} alg={alg}"
        ))),
    }
}

/// Project an `IdTokenClaims` into the canonical `BrokerAssertion`. Vendor
/// adapters extend this with vendor-specific claim mapping.
pub fn assertion_from_claims(
    alias: &str,
    claims: &IdTokenClaims,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) -> BrokerAssertion {
    let mut map: BTreeMap<String, AttributeValue> = BTreeMap::new();
    if let Some(v) = &claims.preferred_username {
        map.insert(
            "preferred_username".into(),
            AttributeValue::String(v.clone()),
        );
    }
    if let Some(v) = &claims.email {
        map.insert("email".into(), AttributeValue::String(v.clone()));
    }
    if let Some(v) = claims.email_verified {
        map.insert("email_verified".into(), AttributeValue::Bool(v));
    }
    if let Some(v) = &claims.given_name {
        map.insert("given_name".into(), AttributeValue::String(v.clone()));
    }
    if let Some(v) = &claims.family_name {
        map.insert("family_name".into(), AttributeValue::String(v.clone()));
    }
    if let Some(v) = &claims.name {
        map.insert("name".into(), AttributeValue::String(v.clone()));
    }
    BrokerAssertion {
        idp_alias: alias.into(),
        external_id: claims.sub.clone(),
        issuer: claims.iss.clone(),
        claims: map,
        received_at: chrono::Utc::now(),
        expires_at,
    }
}

pub fn use_for_nonce_check(state: &BrokerAuthnState) -> Option<&str> {
    state.nonce.as_deref()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audience_string_and_array() {
        assert!(audience_matches(&serde_json::json!("x"), "x"));
        assert!(audience_matches(&serde_json::json!(["a", "x"]), "x"));
        assert!(!audience_matches(&serde_json::json!(["a", "b"]), "x"));
    }

    #[test]
    fn authorization_url_carries_pkce_and_state() {
        let cfg = OidcIdpConfig {
            issuer: "https://idp".into(),
            discovery_url: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
            client_id: "abc".into(),
            client_secret: None,
            scopes: vec!["openid".into(), "email".into()],
            pkce: true,
            accept_unsigned_userinfo: false,
            client_auth: crate::ClientAuthMethod::None,
            client_assertion_key: None,
            prompt: None,
            response_mode: None,
        };
        let d = OidcDiscovery {
            issuer: "https://idp".into(),
            authorization_endpoint: "https://idp/auth".into(),
            token_endpoint: "https://idp/token".into(),
            userinfo_endpoint: None,
            jwks_uri: "https://idp/jwks".into(),
            end_session_endpoint: None,
            code_challenge_methods_supported: vec!["S256".into()],
            id_token_signing_alg_values_supported: vec!["RS256".into()],
        };
        let u = authorization_url(
            &d,
            &cfg,
            "https://g.example/cb",
            "STATE1",
            "N1",
            Some("CHAL"),
            &[],
        );
        assert!(u.starts_with("https://idp/auth?"));
        assert!(u.contains("state=STATE1"));
        assert!(u.contains("nonce=N1"));
        assert!(u.contains("code_challenge=CHAL"));
        assert!(u.contains("code_challenge_method=S256"));
        assert!(u.contains("scope=openid%20email"));
    }
}
