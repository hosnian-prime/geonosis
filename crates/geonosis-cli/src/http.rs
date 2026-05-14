//! Shared HTTP client for the admin REST API.
//!
//! Every CLI command that mutates entities (`realms`, `clients`,
//! `users`, `orgs`, `agents`, `keys`, `events`, `flows`) goes through
//! [`AdminClient`]. SPI / Migrate / Federation keep their direct
//! Postgres path because those are database-administrator operations,
//! not entity-management — see `commands/` for the per-family wiring.
//!
//! Design choices that pin v0.1 — senior-engineer SOLID/DRY rules
//! the audit explicitly asked for:
//!
//! - **One client, one config** — `AdminClient::new(base_url, token)`
//!   returns a reusable client. Each command holds a reference, not
//!   a per-request `reqwest::Client::new()`.
//! - **Bearer auth in one place** — the helper injects
//!   `Authorization: Bearer <token>` if configured; commands never
//!   touch headers.
//! - **One error mapper** — admin REST errors come back as
//!   `{ "error": "...", "message": "..." }`; the helper decodes them
//!   into the local [`AdminApiError`] so every command surfaces the
//!   same exit message.
//! - **Typed requests** — `get<T>()`, `post<I, O>(...)`,
//!   `put<I, O>(...)`, `delete()`. Each command writes a small
//!   request/response struct and stays out of `reqwest::Request`
//!   plumbing.

use std::time::Duration;

use anyhow::Context;
use reqwest::{Method, StatusCode, Url};
use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

const USER_AGENT: &str = concat!("geoctl/", env!("CARGO_PKG_VERSION"));
const DEFAULT_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Error)]
pub enum AdminApiError {
    #[error("admin api: {status} {body}")]
    Status { status: StatusCode, body: String },
    #[error("transport: {0}")]
    Transport(String),
    #[error("invalid response shape: {0}")]
    Decode(String),
}

#[derive(Clone)]
pub struct AdminClient {
    inner: reqwest::Client,
    base: Url,
    token: Option<String>,
}

impl AdminClient {
    /// Build a client against `base_url` (e.g. `http://localhost:8080`).
    /// `token` is the bearer credential the server's admin API expects.
    /// v0.1 ships the token via `--token <T>` / `GEONOSIS_ADMIN_TOKEN`;
    /// the OAuth client-credentials login flow that mints it lives in
    /// `commands::login` (deferred — v0.1 bootstrap reads the token
    /// from the env directly).
    pub fn new(base_url: &str, token: Option<String>) -> anyhow::Result<Self> {
        let base = Url::parse(base_url)
            .with_context(|| format!("invalid admin URL: {base_url}"))?;
        let inner = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .context("reqwest client")?;
        Ok(Self { inner, base, token })
    }

    /// GET <path> and decode the JSON body as `T`.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, AdminApiError> {
        self.request(Method::GET, path, None::<&()>).await
    }

    /// POST JSON body and decode the JSON response as `O`.
    pub async fn post<I: Serialize, O: DeserializeOwned>(
        &self,
        path: &str,
        body: &I,
    ) -> Result<O, AdminApiError> {
        self.request(Method::POST, path, Some(body)).await
    }

    /// PUT JSON body and decode the JSON response as `O`.
    pub async fn put<I: Serialize, O: DeserializeOwned>(
        &self,
        path: &str,
        body: &I,
    ) -> Result<O, AdminApiError> {
        self.request(Method::PUT, path, Some(body)).await
    }

    /// PUT JSON body with no response body. Used for endpoints that
    /// return 204 No Content (verify-email, set-password).
    pub async fn put_no_response<I: Serialize>(
        &self,
        path: &str,
        body: &I,
    ) -> Result<(), AdminApiError> {
        let url = self.url(path)?;
        let mut req = self.inner.put(url).json(body);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        check_status(resp).await.map(|_| ())
    }

    /// POST with no request body and no response decode (e.g.
    /// verify-email, accept-invitation).
    pub async fn post_empty(&self, path: &str) -> Result<(), AdminApiError> {
        let url = self.url(path)?;
        let mut req = self.inner.post(url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        check_status(resp).await.map(|_| ())
    }

    /// DELETE <path>. Returns Ok(()) on 204 No Content, error otherwise.
    pub async fn delete(&self, path: &str) -> Result<(), AdminApiError> {
        let url = self.url(path)?;
        let mut req = self.inner.delete(url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        check_status(resp).await.map(|_| ())
    }

    fn url(&self, path: &str) -> Result<Url, AdminApiError> {
        self.base.join(path).map_err(|e| {
            AdminApiError::Transport(format!("invalid path {path}: {e}"))
        })
    }

    async fn request<I, O>(
        &self,
        method: Method,
        path: &str,
        body: Option<&I>,
    ) -> Result<O, AdminApiError>
    where
        I: Serialize,
        O: DeserializeOwned,
    {
        let url = self.url(path)?;
        let mut req = self.inner.request(method, url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| AdminApiError::Transport(e.to_string()))?;
        let body = check_status(resp).await?;
        serde_json::from_slice(&body)
            .map_err(|e| AdminApiError::Decode(format!("body: {e}")))
    }
}

/// Decode admin REST error shape and surface as `AdminApiError`. The
/// admin handlers return `text/plain` error bodies today (see
/// `AdminError::into_response`); v0.1.x will move to a structured
/// envelope but the helper keeps backward compatibility either way.
async fn check_status(resp: reqwest::Response) -> Result<bytes::Bytes, AdminApiError> {
    let status = resp.status();
    let body = resp
        .bytes()
        .await
        .map_err(|e| AdminApiError::Transport(e.to_string()))?;
    if status.is_success() {
        return Ok(body);
    }
    let body_str = String::from_utf8_lossy(&body).into_owned();
    Err(AdminApiError::Status {
        status,
        body: body_str,
    })
}
