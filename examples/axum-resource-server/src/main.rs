//! Minimal axum resource server that validates Geonosis-issued
//! access tokens against the realm's JWKS.
//!
//! Boot:
//!
//! ```sh
//! GEONOSIS_ISSUER=http://localhost:8080/realms/acme \
//! GEONOSIS_AUDIENCE=acme-web \
//!     cargo run --manifest-path examples/axum-resource-server/Cargo.toml
//! ```
//!
//! Try it:
//!
//! ```sh
//! curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:7000/me
//! ```
//!
//! Per `docs/21-dx-package.md` §"Framework example apps" this stays
//! minimal: one route, one verify path, JWKS cached for 10 minutes.
//! Production resource servers should add structured logging,
//! per-route scope checks, and key-rotation-aware cache eviction.

use std::{collections::HashMap, env, sync::Arc, time::{Duration, Instant}};

use axum::{
    extract::State, http::{header, StatusCode}, routing::get, Json, Router,
};
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Clone)]
struct AppState {
    issuer: String,
    audience: String,
    http: reqwest::Client,
    jwks_cache: Arc<RwLock<JwksCache>>,
}

struct JwksCache {
    keys: HashMap<String, Jwk>,
    fetched_at: Option<Instant>,
}

#[derive(Clone, Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<Jwk>,
}

#[derive(Clone, Debug, Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    aud: serde_json::Value,
    iss: String,
    exp: i64,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
}

#[derive(Debug, Serialize)]
struct MeResponse {
    sub: String,
    email: Option<String>,
    preferred_username: Option<String>,
}

const JWKS_TTL: Duration = Duration::from_secs(600);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let issuer = env::var("GEONOSIS_ISSUER")
        .unwrap_or_else(|_| "http://localhost:8080/realms/acme".into());
    let audience = env::var("GEONOSIS_AUDIENCE").unwrap_or_else(|_| "acme-web".into());

    let state = AppState {
        issuer,
        audience,
        http: reqwest::Client::builder().build()?,
        jwks_cache: Arc::new(RwLock::new(JwksCache {
            keys: HashMap::new(),
            fetched_at: None,
        })),
    };

    let app = Router::new().route("/me", get(me)).with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:7000").await?;
    tracing::info!("listening on http://0.0.0.0:7000 (try /me with a Bearer token)");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn me(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<MeResponse>, (StatusCode, String)> {
    let token = bearer(&headers)?;
    let claims = verify(&state, &token).await?;
    Ok(Json(MeResponse {
        sub: claims.sub,
        email: claims.email,
        preferred_username: claims.preferred_username,
    }))
}

fn bearer(headers: &axum::http::HeaderMap) -> Result<String, (StatusCode, String)> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or((StatusCode::UNAUTHORIZED, "missing Authorization header".into()))?
        .to_str()
        .map_err(|_| (StatusCode::UNAUTHORIZED, "non-ascii auth header".into()))?;
    value
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
        .ok_or((StatusCode::UNAUTHORIZED, "expected Bearer scheme".into()))
}

async fn verify(state: &AppState, token: &str) -> Result<Claims, (StatusCode, String)> {
    let header = decode_header(token).map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    let kid = header
        .kid
        .ok_or((StatusCode::UNAUTHORIZED, "id token missing kid header".into()))?;
    let alg = header.alg;

    let jwk = lookup_jwk(state, &kid).await?;
    let key = decoding_key(&jwk).map_err(|e| (StatusCode::UNAUTHORIZED, e))?;

    let mut validation = Validation::new(alg);
    validation.set_issuer(&[&state.issuer]);
    validation.set_audience(&[&state.audience]);
    let data =
        decode::<Claims>(token, &key, &validation).map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;
    Ok(data.claims)
}

async fn lookup_jwk(state: &AppState, kid: &str) -> Result<Jwk, (StatusCode, String)> {
    {
        let cache = state.jwks_cache.read().await;
        if let Some(ts) = cache.fetched_at {
            if ts.elapsed() < JWKS_TTL {
                if let Some(jwk) = cache.keys.get(kid).cloned() {
                    return Ok(jwk);
                }
            }
        }
    }
    let url = format!("{}/protocol/openid-connect/jwks", state.issuer.trim_end_matches('/'));
    let doc: JwksDocument = state
        .http
        .get(&url)
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("jwks fetch: {e}")))?
        .error_for_status()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("jwks status: {e}")))?
        .json()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("jwks json: {e}")))?;
    let mut cache = state.jwks_cache.write().await;
    cache.keys = doc.keys.iter().map(|k| (k.kid.clone(), k.clone())).collect();
    cache.fetched_at = Some(Instant::now());
    cache
        .keys
        .get(kid)
        .cloned()
        .ok_or((StatusCode::UNAUTHORIZED, "kid not in JWKS".into()))
}

fn decoding_key(jwk: &Jwk) -> Result<DecodingKey, String> {
    match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk.n.as_deref().ok_or("RSA jwk missing n")?;
            let e = jwk.e.as_deref().ok_or("RSA jwk missing e")?;
            DecodingKey::from_rsa_components(n, e).map_err(|e| e.to_string())
        }
        "EC" => {
            let x = jwk.x.as_deref().ok_or("EC jwk missing x")?;
            let y = jwk.y.as_deref().ok_or("EC jwk missing y")?;
            DecodingKey::from_ec_components(x, y).map_err(|e| e.to_string())
        }
        other => Err(format!("unsupported kty `{other}`")),
    }
}

