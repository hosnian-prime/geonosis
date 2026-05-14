//! Request coalescing wrapper — single-flight loader dedupe.
//!
//! Doc 09 §"Single-flight per-key dedupe" calls for thundering-herd
//! protection on cold cache misses. The `RequestCoalescer` wraps any
//! `Cache` implementation and ensures that, when N concurrent callers
//! ask for the same missing key, only one runs the loader; the rest
//! wait for the first one's result.
//!
//! The coalescer is intentionally in-process — cross-pod
//! coordination (Redis SETNX-based leases) lands in v0.1.x and rides
//! on top of this same primitive.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::broadcast;

use crate::key::CacheKey;
use crate::traits::{Cache, CacheError, CacheExt, Cached};

/// In-flight loader broadcast channel. We send the serialized payload
/// so every waiter can deserialize independently without sharing the
/// loader's typed result (which may not be `Clone`).
type LoaderBroadcast = broadcast::Sender<Result<Vec<u8>, String>>;

#[derive(Default, Clone)]
pub struct InflightRegistry {
    inner: Arc<Mutex<HashMap<String, LoaderBroadcast>>>,
}

impl InflightRegistry {
    /// Register an in-flight loader OR subscribe to one that already
    /// exists. Returns:
    /// - `(true, sender, receiver)` if this caller is the leader
    /// - `(false, sender, receiver)` if this caller is a waiter
    fn enter(&self, key: &str) -> (bool, LoaderBroadcast, broadcast::Receiver<Result<Vec<u8>, String>>) {
        let mut guard = self.inner.lock();
        if let Some(tx) = guard.get(key).cloned() {
            let rx = tx.subscribe();
            return (false, tx, rx);
        }
        let (tx, rx) = broadcast::channel(8);
        guard.insert(key.to_string(), tx.clone());
        (true, tx, rx)
    }

    fn exit(&self, key: &str) {
        let mut guard = self.inner.lock();
        guard.remove(key);
    }
}

/// Single-flight wrapper around any `Cache`. Coalesces concurrent
/// `get_or_load` calls for the same key so the loader fires exactly
/// once per cache miss.
pub struct RequestCoalescer<C> {
    inner: Arc<C>,
    registry: InflightRegistry,
}

impl<C> RequestCoalescer<C> {
    pub fn new(inner: Arc<C>) -> Self {
        Self {
            inner,
            registry: InflightRegistry::default(),
        }
    }

    pub fn inner(&self) -> &Arc<C> {
        &self.inner
    }
}

impl<C: Cache + 'static> RequestCoalescer<C> {
    /// Coalesced `get_or_load`. Same shape as `CacheExt::get_or_load`
    /// but waiters subscribe to the leader's result via a broadcast
    /// channel.
    pub async fn get_or_load<T, F, Fut>(
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
        // Fast path — cache hit avoids registry entirely.
        if let Some(c) = self.inner.get::<T>(&key).await {
            return Ok(c);
        }
        let key_s = key.to_string();
        let (is_leader, tx, mut rx) = self.registry.enter(&key_s);
        if is_leader {
            // Run loader, broadcast, evict from registry.
            let result = loader().await;
            // Build the wire-form result for waiters. Loader errors get
            // converted to a String so the broadcast item is `Clone`.
            let payload: Result<Vec<u8>, String> = match &result {
                Ok(v) => serde_json::to_vec(v).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            // Best-effort broadcast — waiters that already dropped get
            // their own error.
            let _ = tx.send(payload);
            self.registry.exit(&key_s);
            let v = result?;
            self.inner.put(key, &v, ttl).await;
            return Ok(Cached::new(v, ttl));
        }
        // Waiter path: block on the broadcast channel.
        match rx.recv().await {
            Ok(Ok(bytes)) => {
                let v: T = serde_json::from_slice(&bytes)
                    .map_err(|e| CacheError::Serde(e.to_string()))?;
                Ok(Cached::new(v, ttl))
            }
            Ok(Err(e)) => Err(CacheError::Loader(e)),
            Err(_lagged_or_closed) => {
                // Leader either crashed or the registry entry got
                // recycled before we could read. Fall back to a fresh
                // get attempt — the leader's put is in cache by now
                // if it succeeded.
                match self.inner.get::<T>(&key).await {
                    Some(c) => Ok(c),
                    None => Err(CacheError::Loader(
                        "coalesced leader produced no value".into(),
                    )),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{CacheClass, CacheKey};
    use crate::local::LocalCache;
    use geonosis_core::id::RealmId;
    use serde::Deserialize;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct V {
        n: u32,
    }

    #[tokio::test]
    async fn single_loader_fires_for_concurrent_callers() {
        let cache = Arc::new(LocalCache::default_small());
        let coalescer = Arc::new(RequestCoalescer::new(cache.clone()));
        let realm = RealmId::new();
        let key = CacheKey::new(realm, CacheClass::Client, "shared");
        let calls = Arc::new(AtomicUsize::new(0));

        let mut handles = vec![];
        for _ in 0..20 {
            let coalescer = coalescer.clone();
            let key = key.clone();
            let calls = calls.clone();
            handles.push(tokio::spawn(async move {
                let c: Cached<V> = coalescer
                    .get_or_load(key, Duration::from_secs(30), move || {
                        let calls = calls.clone();
                        async move {
                            // Yield so all callers register before the
                            // leader runs.
                            tokio::task::yield_now().await;
                            calls.fetch_add(1, Ordering::SeqCst);
                            Ok(V { n: 42 })
                        }
                    })
                    .await
                    .unwrap();
                assert_eq!(*c.value, V { n: 42 });
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        // Only one loader call across all 20 concurrent callers.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cache_hit_skips_registry() {
        let cache = Arc::new(LocalCache::default_small());
        let coalescer = RequestCoalescer::new(cache.clone());
        let realm = RealmId::new();
        let key = CacheKey::new(realm, CacheClass::Client, "warm");
        cache
            .put(key.clone(), &V { n: 1 }, Duration::from_secs(30))
            .await;
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let c: Cached<V> = coalescer
            .get_or_load(key, Duration::from_secs(30), move || {
                let calls = calls_clone.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(V { n: 99 })
                }
            })
            .await
            .unwrap();
        assert_eq!(*c.value, V { n: 1 });
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
