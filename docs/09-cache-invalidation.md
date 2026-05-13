# 09 — Cache & Cluster State

Caching is hidden behind the **`Cache` trait**. In v0.1 the default
implementation is **Redis** (with Redis pub/sub for cluster-wide
invalidation). An alternative implementation runs an in-process LRU
with **Postgres `LISTEN`/`NOTIFY`** for invalidation — supported for
small or air-gapped installs that don't want a Redis dependency.

In a future major release, the Redis dependency is replaced by
**Komino**, an embedded Infinispan-class distributed cache gossip-
clustered between Geonosis pods themselves. The `Cache` trait is
the seam; this swap is intended to be invisible to callers.

## Why hide cache behind a trait

- IAM products end up with cache choices as long-tail commitments.
  Putting cache behind a trait means we can move (Redis → Komino)
  without rewriting handlers.
- It also keeps tests honest: a `NoopCache` impl forces every code
  path to also be correct against a cold cache.
- Multiple deployment shapes are supported: small (no Redis), normal
  (Redis), future (Komino-clustered).

## The `Cache` trait

```rust
#[async_trait]
pub trait Cache: Send + Sync {
    /// Lookup. Returns `Some(value)` on hit, `None` on miss
    /// (whether negative-cached or absent).
    async fn get<T>(&self, key: &CacheKey) -> Option<Cached<T>>
    where T: Send + Sync + DeserializeOwned + 'static;

    /// Insert or overwrite. The TTL is enforced by the backing store
    /// where possible (Redis SET PX); the in-process backend honors
    /// it via Moka time-to-live.
    async fn put<T>(&self, key: CacheKey, value: &T, ttl: Duration)
    where T: Send + Sync + Serialize + 'static;

    /// Insert a negative entry (key resolved to "absent"). Lower
    /// default TTL than `put`.
    async fn put_negative(&self, key: CacheKey, ttl: Duration);

    /// Cluster-wide invalidation. Fans out via the impl's bus.
    async fn invalidate(&self, key: &CacheKey);

    /// Cluster-wide invalidation by prefix (e.g. all clients of a realm).
    async fn invalidate_prefix(&self, prefix: &CacheKeyPrefix);

    /// Single-flight: dedupe concurrent requests for the same key.
    async fn get_or_load<T, F, Fut>(
        &self,
        key: CacheKey,
        ttl: Duration,
        loader: F,
    ) -> Result<Cached<T>, CacheError>
    where
        T: Send + Sync + Serialize + DeserializeOwned + 'static,
        F: Send + FnOnce() -> Fut,
        Fut: Send + std::future::Future<Output = Result<T, CacheError>>;
}

pub struct CacheKey {
    pub realm: RealmId,            // every key is realm-scoped
    pub class: CacheClass,         // typed kind: Realm/Client/Flow/...
    pub id: String,                // local identifier inside the class
}

pub struct Cached<T> {
    pub value: Arc<T>,
    pub fetched_at: Instant,
    pub ttl: Duration,
}
```

Keys carry a typed `CacheClass` so we get compile-time guarantees
that, e.g., a `Client` cache lookup can't accidentally read a
`Flow` row. The wire encoding for Redis prefixes the class:
`geo:{realm}:{class}:{id}`.

## Implementations

| Impl | Crate path | When |
|---|---|---|
| `RedisCache` | `geonosis-cache::redis` | **v0.1 default.** Single Redis (or Sentinel/Cluster) endpoint. Uses Redis as both KV and pub/sub. |
| `LocalCache` | `geonosis-cache::local` | Air-gapped / dev / no-Redis. In-process Moka LRU + Postgres `LISTEN`/`NOTIFY` for invalidation. |
| `KominoCache` | `geonosis-cache::komino` | **Future (v1.x).** Embedded distributed cache gossip-clustered between Geonosis pods. Replaces Redis without API change. |
| `NoopCache` | tests only | Always miss. Used to validate cold-path correctness. |

Implementations declare their **capabilities**:

```rust
pub struct CacheCapabilities {
    pub shared_across_pods: bool,
    pub durable_through_restart: bool,
    pub supports_prefix_invalidation: bool,
    pub typical_get_p99_micros: u32,
}
```

Code that requires shared state (rate-limit counters, code grant
caches) checks `shared_across_pods` and falls back to Postgres-only
where the cache is local.

## RedisCache (default v0.1)

**Storage model:**

- Values serialized with `bincode` (compact, schema-tied) and
  versioned (`v1:`, `v2:` prefix per `CacheClass`) so format changes
  are forward-detected and treated as a miss.
- Per-key TTL via `SET PX`. Default TTLs per class match the table
  below.
- Atomic compare-and-set on writes that need it (`SET ... XX NX`).
- Single-flight implemented with `SET key loading PX 5000 NX` lease;
  losers `WAIT` and retry the read.

**Invalidation:**

- Local invalidate: `DEL` key.
- Cluster-wide invalidate: `PUBLISH geo:invalidate <serialized key>`.
- Subscribed pods receive the message and `DEL` the same key (and
  drop the L1 in-process entry — see below).

**L1 in-process layer:**

Pods keep a small Moka L1 in front of Redis with a 1-second TTL.
This collapses the worst hot-path costs (the JWKS lookup on every
`/token` for example). The pub/sub subscriber drops L1 entries on
invalidation messages. L1 is keyed identically to L2 so consistency
reasoning is one-step.

**Failure semantics:**

- Redis unavailable → reads fall through to Postgres; writes succeed
  (DB write commits, invalidation queued in a bounded in-memory
  outbox and replayed on reconnect).
- If the outbox overflows or reconnect fails for > 60 s, the pod
  flips readiness false and Kubernetes shifts traffic.
- Redis sentinel/cluster modes supported via `redis-rs` ahead-of-time
  client setup; no special server logic.

## LocalCache (no-Redis option)

For deployments that don't run Redis:

- Each pod has a Moka LRU keyed identically.
- One dedicated Postgres connection runs `LISTEN geonosis_invalidate`.
- Writes invoke `pg_notify('geonosis_invalidate', payload)` in the
  same transaction as the DB write — if the txn rolls back, no
  notification is sent.
- Capabilities: `shared_across_pods=false` for the L2 (each pod has
  its own LRU, but they're kept consistent through NOTIFY-driven
  evictions); `supports_prefix_invalidation=true` (via NOTIFY
  payload).
- Trade-off: warm-up after pod restart is slow because the cache is
  local. Acceptable for small deployments; not the default.

This is **exactly the cache layer that earlier doc revisions
described**. It still works; it just is no longer the default.

## KominoCache (future)

Komino is a planned native distributed cache, in the spirit of
mature embedded JVM caches that other established IAMs rely on, but
implemented in Rust as a Geonosis-native crate. Goals for Komino:

- **Embedded in `geonosis-server`** — pods cluster directly with
  each other, no external middleware.
- **Gossip-based membership** + consistent-hash partitioning.
- **Causal-replication** between pods (anti-entropy on join).
- **Per-realm-keyspace ownership** so a realm's hot keys live on
  one set of pods, reducing cross-pod chatter.
- **API-equivalent** to the existing `Cache` trait. Operators
  upgrade Geonosis and toggle a config flag; Redis can be removed.
- **Operationally simpler** than running Redis HA, while preserving
  the cluster-wide cache semantics.

Komino is **not** v0.1 work. It's an explicit medium-term direction
that informs the trait surface — we don't add Redis-specific methods
that would later be hard to satisfy without backing into Redis.

It is acceptable that early Komino releases run alongside Redis as
a migration path before Redis can be retired.

## What we cache (per class)

| Class | Key | Where | TTL | Cluster broadcast on invalidation |
|---|---|---|---|---|
| Realm | `realm/{slug}` | L1 + L2 | 30 min | yes |
| Client | `client/{realm}/{client_id}` | L1 + L2 | 30 min | yes |
| Flow (compiled) | `flow/{id}/{version}` | L1 + L2 | 30 min | yes |
| Theme overlay tree | `theme/{name}` | L1 only (file-system source) | 5 min | yes (within pod via file watcher) |
| SPI registry | `spi/{realm}` | L1 + L2 | 30 min | yes |
| Active JWKS | `jwks/{realm}` | L1 + L2 | 30 min | yes |
| Identity provider | `idp/{realm}/{alias}` | L1 + L2 | 30 min | yes |
| Federation source | `fed/{realm}/{alias}` | L1 + L2 | 30 min | yes |
| User (hot path) | `user/{id}` | L1 + L2 | **5 s** | no — short TTL only |
| **User Profile** schema | `user-profile/{realm}` | L1 + L2 | 30 min | yes — on schema save |
| **Organization** | `org/{realm}/{alias}` | L1 + L2 | 30 min | yes |
| **SAML metadata** (IdP role) | `saml-metadata/{realm}` | L1 + L2 | 30 min | yes — on signing-key rotation or SAML config change |
| **SCIM target** health/schema | `scim-target/{realm}/{alias}` | L1 + L2 | 60 s | yes |
| **Agent** (hot Token-Exchange path) | `agent/{realm}/{alias}` | L1 + L2 | 30 s | yes — revocation must propagate fast |
| Negative miss | `neg/...` | L1 + L2 | 1 s | implicit (next positive write invalidates) |
| Rate-limit counters | counter buckets | L2 only (Redis) | window-bound | n/a (atomic INCR) |

Sessions, auth codes, refresh tokens are NOT cached — they're
authoritative in Postgres and the cost of a miss is one cheap
indexed lookup.

## Coalescing

For bursts of writes touching the same entity (e.g. realm import),
the invalidation publisher coalesces by key over a 50 ms window
before publishing. Bounded by HashSet, not by burst size.

## Stampede protection

`get_or_load` implements single-flight at both L1 and L2:

- L1: `dashmap` of in-progress futures by key.
- L2: Redis `SET ... XX NX` lease with a 5 s wait-and-retry.

This stops the herd of concurrent `/token` validations from each
recomputing JWKS during a key rotation.

## Cache as an interface, in code

A handler calls only the trait:

```rust
async fn load_client(
    cache: &dyn Cache,
    storage: &dyn ClientStorage,
    realm: RealmId,
    client_id: &str,
) -> Result<Arc<Client>, AppError> {
    let key = CacheKey::client(realm, client_id);
    cache.get_or_load(key, Duration::from_secs(1800), || async {
        storage.find_client(realm, client_id).await
    }).await
}
```

No code path imports `redis`. The Redis client lives inside
`geonosis-cache::redis`. Switching backends is a configuration
choice.

## Metrics

- `geonosis_cache_hits_total{class,layer}` — layer ∈ {l1, l2}
- `geonosis_cache_misses_total{class,layer}`
- `geonosis_cache_evictions_total{class,layer}`
- `geonosis_cache_size{class,layer}`
- `geonosis_cache_outbox_depth` (queued invalidations when L2 down)
- `geonosis_cache_backend{impl="redis|local|komino"}` — info metric
- `geonosis_cache_invalidations_published_total{class}`
- `geonosis_cache_invalidations_received_total{class}`

## Non-goals

- **Strong consistency** across pods. Bounded staleness only.
- **Cross-pod request migration.** Each request is pinned to one pod.
- **Sticky sessions.** Not needed; flow state is in Postgres.
- **Custom serialization formats.** `bincode` everywhere; a value's
  schema is its Rust type.

## Decisions and open items

- **v0.1 default**: Redis (single, sentinel, or cluster). Required
  for the default Helm deployment.
- **No-Redis fallback**: `LocalCache` with Postgres `LISTEN`/`NOTIFY`.
  Supported and tested; not the default.
- **Komino**: future native impl; informs the trait surface but no
  code in v0.1.
- **Cache size budget per pod**: 256 MiB L1 by default, allocated
  across classes by weight; Redis sizing is operator-controlled.
- **Authorization codes / device codes** in Redis: deferred to v0.2
  for very-high-RPS realms; v0.1 uses Postgres for these.
- **Multi-region Redis**: out of scope; Redis is assumed regional.
- **Komino persistence on cold start**: TBD; v1.x design problem.
