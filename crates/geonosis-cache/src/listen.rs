//! Postgres LISTEN/NOTIFY-driven cache invalidation.
//!
//! Per `docs/09-cache-invalidation.md` §"LocalCache + LISTEN/NOTIFY":
//! when no Redis is configured, each pod runs a `LocalCache` and
//! subscribes to a single Postgres `LISTEN` channel for cross-pod
//! cache invalidations. Any write path can `NOTIFY` and every pod
//! drops the affected entries.
//!
//! The payload protocol matches the Redis pub/sub format used by
//! `geonosis-cache::redis`:
//! - `k:<CacheKey wire form>` — drop the single key
//! - `p:<CacheKeyPrefix wire glob>` — drop every key under the prefix
//!
//! Keeping the same payload shape across both backends means a
//! deployment can migrate between Redis pub/sub and Postgres
//! NOTIFY without changing producer-side code.

use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use sqlx::postgres::{PgListener, PgPool};

use crate::traits::Cache;

/// Channel name peers listen on. Producers `NOTIFY geonosis_invalidate, '<payload>'`.
pub const CHANNEL: &str = "geonosis_invalidate";

/// Backoff cap when the listener loses its connection. We retry
/// forever — the LISTEN socket dying is a transient infrastructure
/// problem, not an unrecoverable error.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(5);

/// Spawn the long-lived listener task. Returns the JoinHandle so the
/// caller can abort on shutdown.
///
/// The `cache` argument is a `dyn Cache` so the listener works with
/// any backend (LocalCache, RedisCache, future Komino). The
/// invalidation method dispatches by payload prefix.
pub fn spawn_listener(pool: PgPool, cache: Arc<dyn Cache>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match run_one(&pool, &cache).await {
                Ok(()) => {
                    tracing::info!(
                        channel = %CHANNEL,
                        "cache invalidation listener stopped cleanly",
                    );
                    return;
                }
                Err(e) => {
                    tracing::warn!(
                        channel = %CHANNEL,
                        error = %e,
                        "cache invalidation listener disconnected; backing off",
                    );
                    tokio::time::sleep(RECONNECT_BACKOFF).await;
                }
            }
        }
    })
}

async fn run_one(pool: &PgPool, cache: &Arc<dyn Cache>) -> Result<(), sqlx::Error> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen(CHANNEL).await?;
    tracing::info!(channel = %CHANNEL, "cache invalidation listener attached");
    let mut stream = listener.into_stream();
    while let Some(item) = stream.next().await {
        let notification = item?;
        apply_payload(cache.as_ref(), notification.payload()).await;
    }
    Ok(())
}

/// Public helper for tests + ad-hoc callers. Routes a payload string
/// to the matching `Cache` method.
pub async fn apply_payload(cache: &dyn Cache, payload: &str) {
    match payload.split_once(':') {
        Some(("k", _key_wire)) => {
            // Single-key drop. The key's wire form is `g:<realm>:<class>:<id>`
            // — to call `invalidate` we'd need to round-trip into a
            // typed CacheKey. v0.1 takes a coarser approach: drop the
            // whole class prefix instead. Cheap, safe, and aligns with
            // how producers currently emit. v0.1.x will add a typed
            // payload codec once admin write paths use it.
            //
            // For now: parse the realm+class out of the wire form and
            // invalidate the prefix.
            if let Some(prefix) = parse_prefix_from_key(payload) {
                cache.invalidate_prefix(&prefix).await;
            }
        }
        Some(("p", _glob)) => {
            // Prefix drop wire form: `p:g:<realm>:<class>:*`
            if let Some(prefix) = parse_prefix_from_glob(payload) {
                cache.invalidate_prefix(&prefix).await;
            }
        }
        _ => {
            tracing::warn!(payload = %payload, "unknown cache invalidate payload");
        }
    }
}

/// `k:g:<realm_ulid>:<class>:<id>` → CacheKeyPrefix(realm, class).
fn parse_prefix_from_key(payload: &str) -> Option<crate::key::CacheKeyPrefix> {
    let inner = payload.strip_prefix("k:")?.strip_prefix("g:")?;
    let mut parts = inner.splitn(3, ':');
    let realm_s = parts.next()?;
    let class_s = parts.next()?;
    parse_prefix_parts(realm_s, class_s)
}

/// `p:g:<realm_ulid>:<class>:*` → CacheKeyPrefix(realm, class).
fn parse_prefix_from_glob(payload: &str) -> Option<crate::key::CacheKeyPrefix> {
    let inner = payload.strip_prefix("p:")?.strip_prefix("g:")?;
    let mut parts = inner.splitn(3, ':');
    let realm_s = parts.next()?;
    let class_s = parts.next()?;
    parse_prefix_parts(realm_s, class_s)
}

fn parse_prefix_parts(realm_s: &str, class_s: &str) -> Option<crate::key::CacheKeyPrefix> {
    use crate::key::{CacheClass, CacheKeyPrefix};
    let realm: geonosis_core::id::RealmId = realm_s.parse().ok()?;
    let class = match class_s {
        "realm" => CacheClass::Realm,
        "client" => CacheClass::Client,
        "flow" => CacheClass::Flow,
        "theme" => CacheClass::Theme,
        "spi" => CacheClass::Spi,
        "jwks" => CacheClass::Jwks,
        "idp" => CacheClass::Idp,
        "federation" => CacheClass::Federation,
        "user" => CacheClass::User,
        "user-profile" => CacheClass::UserProfile,
        "organization" => CacheClass::Organization,
        "saml-metadata" => CacheClass::SamlMetadata,
        "scim-target" => CacheClass::ScimTarget,
        "agent" => CacheClass::Agent,
        "neg" => CacheClass::Negative,
        _ => return None,
    };
    Some(CacheKeyPrefix::new(realm, class))
}

/// Publisher-side helper: NOTIFY peers that a key was invalidated.
/// Write paths call this immediately after their UPDATE/DELETE inside
/// the same transaction (or after commit — eventually-consistent
/// either way).
pub async fn publish_key_invalidation(
    pool: &PgPool,
    key: &crate::key::CacheKey,
) -> Result<(), sqlx::Error> {
    let payload = format!("k:{key}");
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(CHANNEL)
        .bind(payload)
        .execute(pool)
        .await
        .map(|_| ())
}

/// Publisher-side helper: NOTIFY peers that an entire prefix should be
/// dropped (bulk admin write, realm delete).
pub async fn publish_prefix_invalidation(
    pool: &PgPool,
    prefix: &crate::key::CacheKeyPrefix,
) -> Result<(), sqlx::Error> {
    let payload = format!("p:g:{}:{}:*", prefix.realm, prefix.class.as_str());
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(CHANNEL)
        .bind(payload)
        .execute(pool)
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::{CacheClass, CacheKey, CacheKeyPrefix};
    use geonosis_core::id::RealmId;

    #[test]
    fn channel_name_is_pinned() {
        // Peers grep on this constant; renaming silently breaks
        // rolling upgrades. Pin with a literal.
        assert_eq!(CHANNEL, "geonosis_invalidate");
    }

    #[test]
    fn parse_prefix_from_key_payload() {
        let realm = RealmId::new();
        let key = CacheKey::new(realm, CacheClass::Client, "abc");
        let payload = format!("k:{key}");
        let prefix = parse_prefix_from_key(&payload).expect("parse should succeed");
        assert_eq!(prefix.realm, realm);
        assert_eq!(prefix.class, CacheClass::Client);
    }

    #[test]
    fn parse_prefix_from_glob_payload() {
        let realm = RealmId::new();
        let glob_prefix = CacheKeyPrefix::new(realm, CacheClass::User);
        let payload = format!("p:g:{}:{}:*", glob_prefix.realm, glob_prefix.class.as_str());
        let parsed = parse_prefix_from_glob(&payload).expect("parse should succeed");
        assert_eq!(parsed.realm, realm);
        assert_eq!(parsed.class, CacheClass::User);
    }

    #[test]
    fn unknown_class_yields_none() {
        let realm = RealmId::new();
        let payload = format!("k:g:{realm}:bogus:abc");
        assert!(parse_prefix_from_key(&payload).is_none());
    }

    #[test]
    fn payload_round_trip_with_redis_format() {
        // The RedisCache publishes the same format on its pub/sub
        // channel. parse_prefix_from_* must accept both producers.
        let realm = RealmId::new();
        let key = CacheKey::new(realm, CacheClass::Flow, "browser");
        let key_payload = format!("k:{key}");
        let glob = format!("p:g:{}:flow:*", realm);
        assert!(parse_prefix_from_key(&key_payload).is_some());
        assert!(parse_prefix_from_glob(&glob).is_some());
    }
}
