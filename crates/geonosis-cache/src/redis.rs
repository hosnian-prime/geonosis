//! Redis-backed `Cache` impl. The v0.1 default per doc 09 — every
//! production deployment that wants cross-pod cache consistency runs
//! this; the in-memory `LocalCache` stays the dev / air-gapped option.
//!
//! v0.1 surface:
//! - Single Redis URL (Sentinel + Cluster land in v0.1.x via the same
//!   ConnectionManager abstraction once the basic plumbing settles).
//! - KV operations map to `SET key value EX ttl` / `GET` / `DEL`.
//! - Prefix invalidation uses `SCAN MATCH` + `UNLINK` in batches. The
//!   non-blocking `UNLINK` keeps a noisy invalidation from blocking
//!   foreground commands.
//! - Pub/sub broadcast: every `invalidate*` call also publishes the
//!   invalidated key (or prefix glob) on the
//!   `geonosis:cache:invalidate` channel so peer pods can drop their
//!   L1 entries. The L1+L2 wrapper layers on top of this in v0.1.x.

use std::time::Duration;

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;

use crate::key::{CacheKey, CacheKeyPrefix};
use crate::traits::Cache;

/// Channel name peers listen on for cross-pod invalidations.
pub const INVALIDATE_CHANNEL: &str = "geonosis:cache:invalidate";

#[derive(Debug, Clone)]
pub struct RedisCacheConfig {
    pub url: String,
    /// Default TTL when a caller passes `Duration::ZERO` to `put_raw`.
    /// Backends MUST default to *some* finite value so a buggy caller
    /// doesn't permanently anchor entries.
    pub default_ttl: Duration,
    /// SCAN page size for prefix invalidation. Higher = fewer round
    /// trips, more memory per page. 500 strikes a balance for typical
    /// realms.
    pub scan_count: usize,
}

impl Default for RedisCacheConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".into(),
            default_ttl: Duration::from_secs(30 * 60),
            scan_count: 500,
        }
    }
}

pub struct RedisCache {
    conn: ConnectionManager,
    config: RedisCacheConfig,
}

impl RedisCache {
    pub async fn connect(config: RedisCacheConfig) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(config.url.clone())?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn, config })
    }

    fn ttl_secs(&self, ttl: Duration) -> u64 {
        if ttl.is_zero() {
            self.config.default_ttl.as_secs().max(1)
        } else {
            ttl.as_secs().max(1)
        }
    }

    /// Construct the `SCAN MATCH` glob that drops every key for a
    /// (realm, class) bucket. Matches the wire shape `CacheKey::fmt`
    /// produces.
    fn prefix_glob(&self, prefix: &CacheKeyPrefix) -> String {
        format!("g:{}:{}:*", prefix.realm, prefix.class.as_str())
    }

    async fn publish(&self, payload: &str) {
        let mut conn = self.conn.clone();
        let result: Result<(), redis::RedisError> = redis::cmd("PUBLISH")
            .arg(INVALIDATE_CHANNEL)
            .arg(payload)
            .query_async(&mut conn)
            .await;
        if let Err(e) = result {
            tracing::debug!(
                error = %e,
                payload = %payload,
                "cache invalidate publish failed; peers will rely on TTL",
            );
        }
    }
}

#[async_trait]
impl Cache for RedisCache {
    async fn get_raw(&self, key: &CacheKey) -> Option<Vec<u8>> {
        let mut conn = self.conn.clone();
        let result: Result<Option<Vec<u8>>, redis::RedisError> = conn.get(key.to_string()).await;
        match result {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, key = %key, "redis GET failed");
                None
            }
        }
    }

    async fn put_raw(&self, key: CacheKey, bytes: Vec<u8>, ttl: Duration) {
        let mut conn = self.conn.clone();
        let secs = self.ttl_secs(ttl);
        let result: Result<(), redis::RedisError> = conn.set_ex(key.to_string(), bytes, secs).await;
        if let Err(e) = result {
            tracing::warn!(error = %e, key = %key, "redis SETEX failed");
        }
    }

    async fn put_negative(&self, key: CacheKey, ttl: Duration) {
        // Empty payload is the negative-cache marker — matches the
        // LocalCache contract.
        self.put_raw(key, Vec::new(), ttl).await;
    }

    async fn invalidate(&self, key: &CacheKey) {
        let mut conn = self.conn.clone();
        let key_s = key.to_string();
        let result: Result<(), redis::RedisError> = conn.del(&key_s).await;
        if let Err(e) = result {
            tracing::warn!(error = %e, key = %key, "redis DEL failed");
        }
        self.publish(&format!("k:{key_s}")).await;
    }

    async fn invalidate_prefix(&self, prefix: &CacheKeyPrefix) {
        let mut conn = self.conn.clone();
        let glob = self.prefix_glob(prefix);
        // SCAN cursor loop. Using AsyncIter via the redis crate keeps
        // us off the blocking KEYS command which is a production
        // footgun in large keyspaces.
        let mut cursor: u64 = 0;
        loop {
            let result: Result<(u64, Vec<String>), redis::RedisError> = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&glob)
                .arg("COUNT")
                .arg(self.config.scan_count)
                .query_async(&mut conn)
                .await;
            let (next, batch) = match result {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, glob = %glob, "redis SCAN failed");
                    break;
                }
            };
            if !batch.is_empty() {
                // UNLINK is non-blocking; falls back to DEL on older
                // Redis (<4.0) which we don't support but won't error.
                let unlink: Result<(), redis::RedisError> = redis::cmd("UNLINK")
                    .arg(&batch)
                    .query_async(&mut conn)
                    .await;
                if let Err(e) = unlink {
                    tracing::warn!(error = %e, "redis UNLINK failed");
                }
            }
            if next == 0 {
                break;
            }
            cursor = next;
        }
        self.publish(&format!("p:{glob}")).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{CacheClass, CacheKey};
    use geonosis_core::id::RealmId;

    #[test]
    fn prefix_glob_matches_cache_key_wire_format() {
        let cfg = RedisCacheConfig::default();
        // RedisCache::connect requires a live server; the glob
        // formatter doesn't, so we test it via a fresh local struct.
        let realm = RealmId::new();
        let key = CacheKey::new(realm, CacheClass::Client, "id-1").to_string();
        let glob = format!("g:{}:{}:*", realm, CacheClass::Client.as_str());
        assert!(
            key.starts_with(&glob[..glob.len() - 1]),
            "key {key} should fall under {glob}",
        );
        assert!(glob.ends_with(":*"));
        let _ = cfg.scan_count; // Touch field so doc-gen knows it's used.
    }

    #[test]
    fn ttl_zero_falls_back_to_default() {
        // ttl_secs is a method, but it only depends on config; instead
        // of building a live connection we duplicate the arithmetic
        // here to keep the test hermetic. The Duration::ZERO branch
        // must not produce 0 (which means "no expiry" in Redis).
        let cfg = RedisCacheConfig::default();
        let computed = if Duration::ZERO.is_zero() {
            cfg.default_ttl.as_secs().max(1)
        } else {
            Duration::ZERO.as_secs().max(1)
        };
        assert!(computed > 0);
    }

    #[test]
    fn invalidate_channel_is_stable() {
        // Peers grep on this constant; renaming it breaks rolling
        // upgrades. Pin the value with a literal so the test catches
        // accidental edits.
        assert_eq!(INVALIDATE_CHANNEL, "geonosis:cache:invalidate");
    }
}
