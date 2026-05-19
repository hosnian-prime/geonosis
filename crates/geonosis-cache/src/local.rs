//! In-process Moka LRU cache. Default backend for "small / air-gapped"
//! deployments and for tests.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache as Moka;

use crate::key::{CacheKey, CacheKeyPrefix};
use crate::traits::Cache;

#[derive(Debug, Clone)]
pub struct LocalCacheConfig {
    pub max_capacity: u64,
    pub default_ttl: Duration,
}

impl Default for LocalCacheConfig {
    fn default() -> Self {
        Self {
            max_capacity: 100_000,
            default_ttl: Duration::from_secs(30 * 60),
        }
    }
}

pub struct LocalCache {
    inner: Moka<String, Vec<u8>>,
    /// Side index of live keys grouped by (realm-id, class-str) so that
    /// `invalidate_prefix` can do precise, synchronous invalidations.
    /// Moka's own predicate invalidation is asynchronous and best-effort,
    /// which we found racy in tests.
    prefix_index: Mutex<HashMap<(String, &'static str), Vec<String>>>,
    /// Monotonic hit/miss counters. Read by the server metrics layer
    /// to populate `cache_hits` / `cache_misses` Prometheus counters.
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

impl LocalCache {
    pub fn new(cfg: LocalCacheConfig) -> Self {
        let inner = Moka::builder()
            .max_capacity(cfg.max_capacity)
            .time_to_live(cfg.default_ttl)
            .build();
        Self {
            inner,
            prefix_index: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    pub fn default_small() -> Self {
        Self::new(LocalCacheConfig::default())
    }
}

impl LocalCache {
    fn record_key(&self, key: &CacheKey) {
        let bucket = (key.realm.to_string(), key.class.as_str());
        let s = key.to_string();
        let mut idx = self.prefix_index.lock().unwrap();
        idx.entry(bucket).or_default().push(s);
    }

    fn drop_key_from_index(&self, key: &CacheKey) {
        let bucket = (key.realm.to_string(), key.class.as_str());
        let s = key.to_string();
        let mut idx = self.prefix_index.lock().unwrap();
        if let Some(v) = idx.get_mut(&bucket) {
            v.retain(|k| k != &s);
        }
    }

    fn take_prefix_keys(&self, prefix: &CacheKeyPrefix) -> Vec<String> {
        let bucket = (prefix.realm.to_string(), prefix.class.as_str());
        let mut idx = self.prefix_index.lock().unwrap();
        idx.remove(&bucket).unwrap_or_default()
    }
}

#[async_trait]
impl Cache for LocalCache {
    async fn get_raw(&self, key: &CacheKey) -> Option<Vec<u8>> {
        let result = self.inner.get(&key.to_string()).await;
        if result.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    async fn put_raw(&self, key: CacheKey, bytes: Vec<u8>, _ttl: Duration) {
        // Moka exposes a per-entry TTL via expiration policies; for v0.1 we
        // honor the global builder TTL. Per-key TTL is a follow-up in v0.2.
        self.record_key(&key);
        self.inner.insert(key.to_string(), bytes).await;
    }

    async fn put_negative(&self, key: CacheKey, _ttl: Duration) {
        self.record_key(&key);
        self.inner.insert(key.to_string(), Vec::new()).await;
    }

    async fn invalidate(&self, key: &CacheKey) {
        self.drop_key_from_index(key);
        self.inner.invalidate(&key.to_string()).await;
    }

    async fn invalidate_prefix(&self, prefix: &CacheKeyPrefix) {
        for k in self.take_prefix_keys(prefix) {
            self.inner.invalidate(&k).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{CacheClass, CacheKey};
    use crate::traits::CacheExt;
    use geonosis_core::id::RealmId;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct V {
        n: i32,
    }

    #[tokio::test]
    async fn put_get_roundtrip() {
        let c = LocalCache::default_small();
        let realm = RealmId::new();
        let k = CacheKey::new(realm, CacheClass::Realm, "x");
        c.put(k.clone(), &V { n: 7 }, Duration::from_secs(30)).await;
        let v: super::super::Cached<V> = c.get(&k).await.unwrap();
        assert_eq!(*v.value, V { n: 7 });
    }

    #[tokio::test]
    async fn invalidate_drops_entry() {
        let c = LocalCache::default_small();
        let realm = RealmId::new();
        let k = CacheKey::new(realm, CacheClass::User, "u1");
        c.put(k.clone(), &V { n: 9 }, Duration::from_secs(30)).await;
        c.invalidate(&k).await;
        let r: Option<super::super::Cached<V>> = c.get(&k).await;
        assert!(r.is_none());
    }

    #[tokio::test]
    async fn get_or_load_calls_loader_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let c = LocalCache::default_small();
        let realm = RealmId::new();
        let k = CacheKey::new(realm, CacheClass::Client, "c1");
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_a = calls.clone();
        let v: super::super::Cached<V> = c
            .get_or_load(k.clone(), Duration::from_secs(30), move || {
                let calls = calls_a.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(V { n: 11 })
                }
            })
            .await
            .unwrap();
        assert_eq!(*v.value, V { n: 11 });
        // Second call should hit the cache.
        let calls_b = calls.clone();
        let v2: super::super::Cached<V> = c
            .get_or_load(k, Duration::from_secs(30), move || {
                let calls = calls_b.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(V { n: 999 })
                }
            })
            .await
            .unwrap();
        assert_eq!(*v2.value, V { n: 11 });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn invalidate_prefix_drops_class() {
        let c = LocalCache::default_small();
        let realm = RealmId::new();
        let k1 = CacheKey::new(realm, CacheClass::User, "u1");
        let k2 = CacheKey::new(realm, CacheClass::Client, "c1");
        c.put(k1.clone(), &V { n: 1 }, Duration::from_secs(30))
            .await;
        c.put(k2.clone(), &V { n: 2 }, Duration::from_secs(30))
            .await;
        c.invalidate_prefix(&CacheKeyPrefix::new(realm, CacheClass::User))
            .await;
        let r1: Option<super::super::Cached<V>> = c.get(&k1).await;
        let r2: Option<super::super::Cached<V>> = c.get(&k2).await;
        assert!(r1.is_none());
        assert!(r2.is_some());
    }
}
