//! Cache that always misses. Used in unit tests.

use std::time::Duration;

use async_trait::async_trait;

use crate::key::{CacheKey, CacheKeyPrefix};
use crate::traits::Cache;

#[derive(Debug, Default)]
pub struct NoopCache;

#[async_trait]
impl Cache for NoopCache {
    async fn get_raw(&self, _key: &CacheKey) -> Option<Vec<u8>> {
        None
    }
    async fn put_raw(&self, _key: CacheKey, _bytes: Vec<u8>, _ttl: Duration) {}
    async fn put_negative(&self, _key: CacheKey, _ttl: Duration) {}
    async fn invalidate(&self, _key: &CacheKey) {}
    async fn invalidate_prefix(&self, _prefix: &CacheKeyPrefix) {}
}
