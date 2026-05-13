# 01 — Architecture

This document is the **map**. Each component links to its own deeper doc.
Read this first; refer to others when you need detail.

## Top-level view

```
                          ┌──────────────────────────────────────────┐
                          │              Kubernetes                  │
                          │                                          │
                          │  Ingress (TLS, L7)                       │
                          │      │                                   │
                 ┌────────┼──────┴────────────┐                      │
                 ▼        ▼                   ▼                      │
            ┌──────┐ ┌──────┐  ...       ┌──────┐                    │
            │ pod  │ │ pod  │            │ pod  │                    │
            │  N   │ │  N   │            │  N   │                    │
            └──┬───┘ └──┬───┘            └──┬───┘                    │
               │        │                   │                        │
               └────────┴────────┬──────────┘                        │
                                 │                                   │
                       ┌─────────┴───────────┐                       │
                       ▼                     ▼                       │
              ┌─────────────────┐    ┌───────────────────┐           │
              │   PostgreSQL    │    │      Redis        │           │
              │  primary + RR   │    │  hot cache + bus  │           │
              │  (system of     │    │  (replaceable by  │           │
              │   record)       │    │   Komino v1.x)    │           │
              └─────────────────┘    └───────────────────┘           │
                                                                     │
                       ┌─────────────────────────────────────────────┘
                       ▼
              ┌─────────────────┐
              │ Object store    │
              │ (S3/GCS) for    │
              │ WASM modules    │
              └─────────────────┘
```

A pod is the unit of replication. Every pod is stateless beyond an
in-process cache. The cluster has **two stateful dependencies** by
default: **Postgres** (durable system of record) and **Redis** (hot
cache + pub/sub fan-out). A no-Redis deployment is supported for
small installs — the same `Cache` trait is satisfied by an in-process
LRU with Postgres `LISTEN`/`NOTIFY` for invalidation.

A future major release replaces the Redis dependency with **Komino**,
an embedded Infinispan-class distributed cache, gossip-clustered
between Geonosis pods themselves. The `Cache` trait is the seam:
swapping the implementation is intended to be invisible to callers.

## A single pod

```
                ┌─────────────────────────────────────────────────────────┐
                │                       geonosis-server                   │
                │                                                         │
                │   ┌────────────┐   ┌──────────────┐   ┌─────────────┐   │
HTTP ─────────► │   │ axum router│──►│  middlewares │──►│   handlers  │   │
                │   └────────────┘   │  (TLS termin.│   │  (OIDC, ad- │   │
                │                    │   tracing,   │   │   min API,  │   │
                │                    │   auth, rate)│   │   UI, well- │   │
                │                    └──────────────┘   │   known)    │   │
                │                                       └──────┬──────┘   │
                │                                              │          │
                │   ┌─────────────────────────────────────┐    │          │
                │   │              core domain            │◀───┘          │
                │   │  realm · user · client · session ·  │               │
                │   │   role · group · flow · key         │               │
                │   └──────┬──────────────────────┬───────┘               │
                │          │                      │                       │
                │   ┌──────▼──────┐       ┌───────▼──────┐                │
                │   │   storage   │       │   spi-host   │                │
                │   │  (Postgres) │       │  (wasmtime)  │                │
                │   │  + cache    │       │              │                │
                │   └──────┬──────┘       └───────┬──────┘                │
                │          │                      │                       │
                │   ┌──────▼──────┐       ┌───────▼──────┐                │
                │   │   pgx pool  │       │  WASM        │                │
                │   │  + LISTEN/  │       │  components  │                │
                │   │   NOTIFY    │       │  (per-realm) │                │
                │   └─────────────┘       └──────────────┘                │
                └─────────────────────────────────────────────────────────┘
```

## Component responsibilities

| Component | Crate | Role |
|---|---|---|
| HTTP surface | `geonosis-server` | axum router, TLS, middleware stack, panic boundary |
| Core domain | `geonosis-core` | Pure entity types, no I/O. Realm, User, Client, Session, Role, Group, Flow, KeyMaterial |
| Storage | `geonosis-storage` | `Storage` trait + Postgres impl with sqlx |
| Cache | `geonosis-cache` | `Cache` trait + Redis impl (default), Postgres-NOTIFY-only impl (no-Redis option), Komino impl (future) |
| Migrations | `geonosis-migrate` | sqlx migrations + expand-contract helpers |
| OIDC protocol | `geonosis-protocol-oidc` | `/authorize`, `/token`, `/userinfo`, `/logout`, `/.well-known/openid-configuration`, JWKS |
| Auth flow | `geonosis-flow` | Graph executor + serializable DSL |
| LDAP federation | `geonosis-federation-ldap` | Bind to external LDAP/AD; mirror users on demand |
| Identity broker | `geonosis-broker` | OIDC and SAML brokering (acts as SP) |
| Crypto | `geonosis-crypto` | JWT signing, key generation, KMS trait |
| SPI host | `geonosis-spi-host` | Wasmtime + WIT bindings; per-realm sandbox |
| SPI authoring SDK | `geonosis-spi-api` | Rust bindings for plugin authors; re-exports generated `wit-bindgen` glue |
| Admin UI | `geonosis-admin-ui` | Leptos SSR + hydration; component slot trait for theming |
| Theme engine | `geonosis-theme` | Filesystem theme overlay + hot reload watcher |
| CLI | `geonosis-cli` (`geoctl`) | Operator CLI: realm import/export, plugin install, key rotate |
| Build tasks | `xtask` | codegen (WIT), dev-server with hot reload, e2e fixtures |

## Request anatomy: an OIDC `authorize`

1. **Ingress** terminates TLS, forwards to a pod.
2. **axum middleware** assigns a request id, opens an OTel span, hits
   the rate-limit middleware.
3. **`oidc::authorize_handler`** parses + validates the request, loads
   the **Client** via storage (cache-hit common), resolves the
   **Realm** + binding **Flow**.
4. **`flow::Executor`** walks the flow graph. Each step is either a
   built-in authenticator (password, OTP, WebAuthn, IdP redirect) or
   a WASM-hosted custom authenticator (called via `geonosis:authn`
   WIT interface).
5. Each authenticator may render a UI page through the **theme
   engine** or redirect to an external IdP via the **broker**.
6. On success, the executor produces a `Subject`, issues an
   authorization code, persists a **CodeGrant** row, and 302s back
   to the client.
7. The eventual `/token` exchange signs an **access token** + **id
   token** using a **KeyMaterial** (active signing key per realm).

## Cross-pod consistency model

| State class | Where it lives | Read consistency | Invalidation |
|---|---|---|---|
| Configuration (realm, client, flow, theme bindings) | Postgres + Redis + in-process L1 | bounded staleness (≤ 100 ms on hot path) | `Cache::invalidate` (Redis pub/sub or Postgres NOTIFY) |
| Cryptographic keys | Postgres + Redis + in-process | same as config | same; explicit rotate command |
| User records | Postgres + Redis (short TTL) | strong (no cache) for writes; cached read on hot path with short TTL (5 s) | TTL + invalidation on writes |
| Sessions (browser SSO cookies) | Postgres | strong | not cached cross-pod; per-pod lookup against DB; session id is opaque, indexed |
| Authorization codes / device codes | Postgres (Redis allowed in v0.2 for very high RPS) | strong, single-use, TTL-indexed | row delete on use |
| Rate-limit counters | Redis (when configured) → cluster-wide; otherwise per-pod bucket | per-pod fallback is best-effort cluster total | natural decay |
| Refresh tokens | Postgres (hashed) | strong | row delete on revoke / rotate |
| WASM module bytecode | Object store + Postgres metadata | bounded staleness | invalidation event → recompile in pod |

Rate-limit being per-pod is an explicit non-goal of v0.1: see
[`13-observability.md`](./13-observability.md) for the trade-off.

## Per-pod lifecycle

```
boot → load config from DB → compile WASM components (per realm)
     → open LISTEN connection → start HTTP listener → mark ready
                ▲                       │
                │                       │  on NOTIFY:
                │                       ▼   - invalidate cache key
        readiness                     react   - recompile WASM module
        probe via /-/ready                    - reload theme overlay
```

## Hot-reload mechanics

There are four hot-reload paths:

1. **Config** (realm/client/flow change in DB) → `NOTIFY` →
   targeted cache invalidation.
2. **Theme** (file written to theme volume) → `notify` crate watcher
   → reload partial of theme engine.
3. **WASM plugin** (new module uploaded via admin API) → Postgres
   row insert → `NOTIFY` → all pods download bytecode, compile in
   background, atomically swap the per-realm SPI table.
4. **Signing key rotation** → new `KeyMaterial` row marked
   `state=Active` → old `state=PreviousActive` for grace window
   (kept in JWKS for verify) → `NOTIFY`.

No request is dropped during any of these.

## Failure model

- **Pod loss:** Kubernetes restarts. The lost pod's in-flight authorize
  flow is abandoned (browser sees a fresh attempt on retry). Code/token
  grants persisted in DB survive.
- **Postgres primary loss:** server enters degraded mode — login
  requests fail fast with `temporarily_unavailable`, ongoing
  authenticated sessions continue to verify against the in-process JWKS
  cache. Recovery is automatic when primary returns.
- **WASM module crash:** sandboxed, contained to a single request.
  Three consecutive crashes mark the module `quarantined`; flow falls
  through to a `Disabled` step if its `requirement` allows.
- **NOTIFY backlog:** if a pod misses notifications (long stall), it
  drops its cache on reconnect (safe but cold).

## Non-goals (architecture-level)

- **Custom storage backends** in v0.1. Postgres only. The trait exists
  but no second implementation ships.
- **Replication-aware writes.** All writes go to the Postgres primary.
- **Cross-region active-active.** Pods in one region only.
- **Embedded LDAP server.** We *consume* LDAP; we don't serve LDAP.
