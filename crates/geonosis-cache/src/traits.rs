//! Cache trait.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use crate::key::{CacheKey, CacheKeyPrefix};

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("loader error: {0}")]
    Loader(String),
    #[error("serialization error: {0}")]
    Serde(String),
    #[error("backend error: {0}")]
    Backend(String),
}

/// Returned value plus the metadata callers need for staleness checks.
#[derive(Debug, Clone)]
pub struct Cached<T> {
    pub value: Arc<T>,
    pub fetched_at: Instant,
    pub ttl: Duration,
}

impl<T> Cached<T> {
    pub fn new(value: T, ttl: Duration) -> Self {
        Self {
            value: Arc::new(value),
            fetched_at: Instant::now(),
            ttl,
        }
    }
}

#[async_trait]
pub trait Cache: Send + Sync {
    /// Look up a key. Returns `None` on miss.
    async fn get_raw(&self, key: &CacheKey) -> Option<Vec<u8>>;

    /// Insert a serialized value with a TTL.
    async fn put_raw(&self, key: CacheKey, bytes: Vec<u8>, ttl: Duration);

    /// Record a negative-cache marker — used so a missing entity doesn't
    /// round-trip the database on every retry.
    async fn put_negative(&self, key: CacheKey, ttl: Duration);

    async fn invalidate(&self, key: &CacheKey);

    async fn invalidate_prefix(&self, prefix: &CacheKeyPrefix);
}

/// Higher-level helpers built on the raw byte interface. Default-implemented
/// so backends only need to provide the four byte methods.
#[async_trait]
#[allow(dead_code)]
pub trait CacheExt: Cache {
    async fn get<T>(&self, key: &CacheKey) -> Option<Cached<T>>
    where
        T: Send + Sync + DeserializeOwned + 'static,
    {
        let bytes = self.get_raw(key).await?;
        let value: T = serde_json::from_slice(&bytes).ok()?;
        Some(Cached::new(value, Duration::from_secs(0)))
    }

    async fn put<T>(&self, key: CacheKey, value: &T, ttl: Duration)
    where
        T: Send + Sync + Serialize + 'static,
    {
        match serde_json::to_vec(value) {
            Ok(b) => self.put_raw(key, b, ttl).await,
            Err(e) => {
                tracing::warn!(error = %e, "cache put serialization failed");
            }
        }
    }

    async fn get_or_load<T, F, Fut>(
        &self,
        key: CacheKey,
        ttl: Duration,
        loader: F,
    ) -> Result<Cached<T>, CacheError>
    where
        T: Send + Sync + Serialize + DeserializeOwned + 'static,
        F: Send + FnOnce() -> Fut,
        Fut: Send + Future<Output = Result<T, CacheError>>,
    {
        if let Some(c) = self.get::<T>(&key).await {
            return Ok(c);
        }
        let v = loader().await?;
        self.put(key, &v, ttl).await;
        Ok(Cached::new(v, ttl))
    }
}

impl<T: Cache + ?Sized> CacheExt for T {}
