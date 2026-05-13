# 09 — Cache & Cluster State

The cluster has **no shared cache**. Each pod owns a private cache.
Cross-pod consistency is reached via **Postgres `LISTEN` / `NOTIFY`**.
This document explains how that holds together at scale.

## Why no Redis / Infinispan

A shared cache is the natural place for IAM products to hide
complexity — it ends up holding session state, rate-limit counters,
cluster topology, and partial migration state. It's also where
Keycloak's operational pain often originates (Infinispan split-brain,
state-transfer pauses, eager initialization).

We made an explicit bet: **the database is the cluster**. As long as
the database is up, the cluster is consistent. When the database is
down, no logins succeed *anywhere*, which is the simplest possible
failure semantics. Adding a cache layer outside the DB is a future
option, not a current dependency.

## What we cache

Each pod runs a Moka-based **bounded LRU** of roughly:

| Class | Key | Eviction | TTL |
|---|---|---|---|
| Realm | `realm:{slug}` | LRU + NOTIFY | 30 min |
| Client | `client:{realm}:{client_id}` | LRU + NOTIFY | 30 min |
| Flow (compiled) | `flow:{id}:{version}` | LRU + NOTIFY | 30 min |
| Theme overlay tree | `theme:{name}` | LRU + file-watch | 5 min |
| SPI registry | `spi:{realm}` | LRU + NOTIFY | 30 min |
| Active JWKS | `jwks:{realm}` | LRU + NOTIFY | 30 min |
| Identity provider | `idp:{realm}:{alias}` | LRU + NOTIFY | 30 min |
| Federation source | `fed:{realm}:{alias}` | LRU + NOTIFY | 30 min |
| User (hot path) | `user:{id}` | LRU | **5 s** |

The user cache is deliberately *short-TTL only*. We do NOT invalidate
user cache via NOTIFY (would be very noisy under load). A 5-second
staleness on a user record is acceptable; admin-side disables propagate
through session revocation, not cache invalidation.

We deliberately do **not** cache:

- Sessions (always DB-resident; per-pod lookup).
- Auth codes / refresh tokens (single-use, must be authoritative).
- Audit events.

## NOTIFY protocol

A single Postgres channel: `geonosis_invalidate`.

Payload is a JSON object:

```json
{
  "kind": "client",         // entity class
  "realm": "acme",
  "id": "ulid-or-key"
}
```

Writers (admin handlers, the cleanup job, federation sync) emit a
`pg_notify` in the **same transaction** as the write. If the
transaction rolls back, the notification is never sent.

```sql
SELECT pg_notify(
  'geonosis_invalidate',
  json_build_object(
    'kind', 'client',
    'realm', $1,
    'id',    $2
  )::text
);
```

## Listener loop

Each pod opens **one** dedicated DB connection for `LISTEN`. That
connection is *not* part of the application pool; it lives in the
`geonosis-cache` module:

```rust
async fn listener_loop(pool: PgPool, cache: Arc<CacheRegistry>) {
    let mut conn = pool.acquire().await?;
    conn.execute("LISTEN geonosis_invalidate").await?;
    loop {
        match conn.next_notification().await {
            Ok(n) => cache.apply(&n.payload),
            Err(e) => {
                tracing::warn!(?e, "listener disconnected; resetting");
                cache.drop_all_volatile();
                // reconnect with backoff
            }
        }
    }
}
```

Properties:

- **Single connection**, so there's no contention or ordering
  surprise.
- **Reconnect drops the volatile cache** — easier than reasoning
  about missed notifications. Correctness > efficiency on the
  reconnect path.
- The pod's `/-/ready` probe fails while the listener is down. The
  pool can still serve reads, but K8s steers traffic to other pods
  until reconnection succeeds.

## Coalescing

Many writes target the same entity in a burst (e.g. realm config
import touches many rows). We coalesce notifications **on receipt**:

```rust
struct CoalescingBuffer {
    pending: HashSet<CacheKey>,
    deadline: Instant,
}
```

When the first notification arrives, set deadline to `now + 50 ms`.
Add subsequent notifications to the set. At deadline, apply all in
one pass. Bounded by entity count, not by burst size.

## Watcher: filesystem

Themes and per-pod overlays use the [`notify`](https://crates.io/crates/notify)
crate. We watch the theme directory and invalidate
`theme:{name}` keys on any change in that subtree. Debounce 200 ms.

## Cache as a trait

```rust
#[async_trait]
trait Cache: Send + Sync {
    async fn get<T>(&self, key: CacheKey) -> Option<Arc<T>>
    where T: Send + Sync + Clone + 'static;

    async fn put<T>(&self, key: CacheKey, value: Arc<T>, ttl: Duration);

    async fn invalidate(&self, key: CacheKey);

    async fn invalidate_prefix(&self, prefix: &str);
}
```

A `MokaCache` implements it. A `NoopCache` exists for tests. We do
**not** ship a `RedisCache` in v0.1, but the trait makes one possible
later.

## Negative caching

For hot non-existence lookups (a misconfigured client repeatedly
querying a nonexistent realm), we cache `None` for a short TTL (1 s)
to prevent stampedes. Negative entries are also invalidated by
NOTIFY on the corresponding create.

## Cache poisoning safety

- Cache values are **owned, immutable `Arc<T>`** clones; serving them
  cannot mutate them.
- Deserialization happens at the storage boundary; cached values are
  already validated domain types.
- No cross-realm key collision is possible: every key embeds
  `realm:{slug}`.

## Failure modes

| Failure | Behavior |
|---|---|
| Listener reconnect | Cache flushed; next requests are cold. P99 latency briefly increases. No correctness impact. |
| `NOTIFY` payload truncated by Postgres (8 KiB limit) | Should never happen with our payloads (small). Defensive: payloads carry only kind + key, not state. |
| Postgres unavailable | Listener fails, pod marks not-ready, traffic shifts. Other pods still serve cached reads until cold. |
| Massive invalidation storm | Coalescing buffer + bounded HashSet caps memory. |

## Stampede protection

For expensive computed entries (compiled flow, JWKS construction), we
use **single-flight**:

```rust
let value = single_flight.get_or_compute(key, || async {
    /* expensive build */
}).await;
```

Concurrent callers wait on the same in-flight future.

## Metrics

- `geonosis_cache_hits_total{class}`
- `geonosis_cache_misses_total{class}`
- `geonosis_cache_evictions_total{class}`
- `geonosis_cache_size{class}`
- `geonosis_listener_reconnects_total`
- `geonosis_listener_lag_seconds` (estimated from NOTIFY timestamps)

## Non-goals

- **Strong cluster-wide consistency** for cached entries. Bounded
  staleness only.
- **Cross-pod request migration** (e.g. moving an in-progress flow
  to another pod). Each request is pinned to one pod via ingress.
- **Sticky sessions.** Not needed; flow state is in Postgres.

## Open

- **Cache size budgets**: total ~256 MiB default per pod, split per
  class — needs benchmarks.
- **Optional Redis cache backend** for installs that need it (very
  high RPS, or want lower variance on user cache) — design but defer.
- **`LISTEN` retry policy** beyond exponential backoff — circuit-
  breaker if Postgres is flapping.
