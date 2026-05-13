# 13 — Observability

Geonosis emits **logs**, **metrics**, **traces**, and **audit
events**. Each is a distinct signal with its own backend, schema, and
sensitivity rules.

## Signal map

| Signal | Backend (recommended) | Volume | Sensitivity |
|---|---|---|---|
| Logs | stdout JSON → cluster log pipeline | medium | scrubbed; debug-level only with consent |
| Metrics | Prometheus (`/metrics`) | low | none — counts and labels |
| Traces | OTLP → OTel collector → vendor | high in dev, sampled in prod | request ids, no secrets |
| Audit events | Postgres `audit_event` → exporter sinks | medium | sensitive; durable |

## Logging

- `tracing` + `tracing-subscriber` with the `json` formatter for
  production, pretty for dev.
- Levels: `error`, `warn`, `info` enabled by default; `debug` and
  `trace` opt-in per module via `RUST_LOG`.
- Every span carries `realm_id`, `request_id`, `user_id` (if known),
  `client_id` (if known).
- `tracing-subscriber` is configured to drop fields containing
  `Secret<_>` debug; passwords, tokens, and refresh tokens cannot
  end up in logs by construction (they live in `Secret<_>` types).
- Each request emits an entry-and-exit log at `info` for non-2xx,
  `debug` for 2xx, so production noise is dominated by errors.

Sample log line:

```json
{
  "ts": "2025-01-08T10:21:34.521Z",
  "level": "warn",
  "target": "geonosis_protocol_oidc::token",
  "msg": "token request failed",
  "request_id": "01HKZTV1A2B3CRYZ",
  "realm_id": "01HKZ...",
  "client_id": "acme-web",
  "error_code": "invalid_grant",
  "detail": "code_already_used"
}
```

## Metrics

Prometheus `/metrics` endpoint, no auth (network-policy gated). Naming
follows OpenMetrics conventions; all names prefixed `geonosis_`.

Core RED/USE metrics:

- `geonosis_http_requests_total{method,path,status}` — counter
- `geonosis_http_request_duration_seconds{method,path}` — histogram
- `geonosis_oidc_authorize_total{realm,outcome}`
- `geonosis_oidc_token_total{realm,grant_type,outcome}`
- `geonosis_oidc_login_failures_total{realm,reason}`
- `geonosis_session_active{realm}` — gauge
- `geonosis_session_created_total{realm}`
- `geonosis_session_revoked_total{realm,reason}`
- `geonosis_db_pool_in_use`, `geonosis_db_pool_size` — gauges
- `geonosis_db_query_duration_seconds{stmt}` — histogram
- `geonosis_listener_reconnects_total`, `geonosis_listener_lag_seconds`
- `geonosis_cache_*` (see [`09-cache-invalidation.md`](./09-cache-invalidation.md))
- `geonosis_spi_*` (see [`07-spi-wasm.md`](./07-spi-wasm.md))
- `geonosis_migration_state{name,phase}` — gauge `1` for current
- `geonosis_build_info{version,commit,profile}` — gauge `1`

Histograms use power-of-2 buckets in milliseconds for latencies.

## Traces

- OpenTelemetry SDK with OTLP/gRPC exporter.
- Trace context propagation: standard W3C `traceparent` headers.
- Default sampling: 100% in dev; in prod, `parentbased_traceidratio`
  with 1% (`OTEL_TRACES_SAMPLER_ARG=0.01`).
- High-value spans always sampled (errors, slow requests > p99) via
  a tail-based sampling rule at the collector.

Span hierarchy for an authorize request:

```
http_request
└── oidc_authorize
    ├── load_client (db.query)
    ├── load_flow (cache.get | db.query)
    └── flow_step                      ← repeats for each step
        ├── authenticator (provider="password")
        └── render
```

Span attributes:

- `realm.slug`
- `client.id`
- `flow.alias`, `flow.version`, `flow.node_id`
- `spi.provider_urn`, `spi.module_sha256` (on SPI spans)
- `db.statement` (parameter-stripped)
- `error.code` and `error.kind` on errors

## Audit events

A separate, **append-only** signal designed for compliance review and
forensic analysis. Persisted to `audit_event` (Postgres partitioned
by month) and optionally streamed to external sinks.

Event shape:

```rust
pub struct AuditEvent {
    pub id: EventId,                 // ULID
    pub realm_id: RealmId,
    pub occurred_at: DateTime<Utc>,
    pub actor: Actor,
    pub action: String,              // taxonomy below
    pub target: Option<Target>,
    pub detail: serde_json::Value,
}

pub enum Actor {
    User { id: UserId, ip: Option<IpAddr> },
    Client { id: ClientId },
    System,
    AdminApi { user_id: UserId, ip: IpAddr },
}

pub enum Target {
    User(UserId),
    Client(ClientId),
    Realm(RealmId),
    Flow(FlowId),
    Key(KeyId),
    Session(SessionId),
    Other { kind: String, id: String },
}
```

### Action taxonomy (selected)

`login.success`, `login.failure`, `login.locked`, `logout.success`,
`token.issued`, `token.refreshed`, `token.revoked`,
`token.reuse_detected`, `consent.granted`, `consent.revoked`,
`user.created`, `user.updated`, `user.deleted`, `user.password_changed`,
`user.required_action_set`, `client.created`, `client.updated`,
`client.secret_rotated`, `flow.created`, `flow.updated`,
`spi.installed`, `spi.uninstalled`, `spi.quarantined`,
`federation.synced`, `federation.error`, `broker.first_login`,
`broker.link_created`, `key.rotated`, `key.disabled`,
`admin.role_assigned`, `admin.role_revoked`.

The complete enumeration of `action` strings lives in
`crates/geonosis-core/src/audit_action.rs` as a typed enum;
the user-facing list is generated from it via `geoctl docs gen-audit`.
Each action is documented inline with the required `detail` fields.

### Sinks

- **Postgres** (built-in): always-on.
- **Webhook**: POST batches to a configured URL (HMAC-signed).
- **Kafka** (v0.2): produce to a configured topic.
- **CloudWatch / Stackdriver / Loki** (v0.2): via OTel logs pipeline.

Sinks are configured per realm. Failures to deliver to external sinks
**must not** lose audit records; the Postgres copy is authoritative.

### Retention

- Default 90 days in Postgres.
- Configurable per realm; minimum 30 days.
- Off-host archival (S3 with object-lock for WORM compliance) is
  v0.2.

## End-user privacy & GDPR

### Logging knobs

- IP addresses appear in audit and logs. A realm can enable IP
  truncation (last octet zeroed) for GDPR-conscious deployments.
- User-agent strings logged in raw form by default; same toggle
  affects this.
- Account deletion: per realm policy, audit events for a deleted user
  may be retained anonymized (replace `user_id` with a hashed
  placeholder while keeping action timeline).

### Self-service data export & erasure (v0.2)

When the account console ships in v0.2 we add two end-user
endpoints:

```
GET    /realms/{slug}/account/me/export          # download all data
POST   /realms/{slug}/account/me/delete          # request erasure
```

- **Export** returns a single ZIP containing the user's profile,
  attributes, group/role memberships, organization memberships,
  active sessions, brokered identity links, audit events keyed by
  this user (subject to realm retention), and consent records. JSON
  manifest + per-section JSON files. Generated synchronously for
  small users (< 50 MB); for larger users (high-volume audit
  trails), queued and emailed-when-ready.
- **Delete** is a two-step: request → confirmation email → hard
  delete + audit-event anonymization. Realm operators may set a
  cooling-off window (default 7 days) during which the user can
  rescind.
- **Audit events** for the deleted user are retained per
  retention-policy but with `user_id` rewritten to a one-way hash
  so the timeline is preserved without re-identifying the subject.
- Federated and brokered users: deletion removes the local mirror;
  the external store is the operator's responsibility.

Operator-side admin APIs `GET /admin/v1/realms/{slug}/users/{id}/export`
and `DELETE /admin/v1/realms/{slug}/users/{id}` provide the
same shape for admin-driven erasure (e.g. DPO request handling).
These exist in v0.2 alongside the end-user paths.

## Dashboards (shipped)

We ship example Grafana dashboards under `deploy/grafana/`:

- **Geonosis Overview**: RPS, error rate, login success ratio, p95
  latencies.
- **Authentication**: login attempts by realm/outcome/method, MFA
  step distribution, broker outcomes.
- **Token Lifecycle**: tokens issued, refreshed, revoked, reuse
  detection.
- **Federation Health**: LDAP source state, response times, sync
  progress.
- **Cluster Health**: DB pool, listener lag, cache hit rates, SPI
  call latencies.
- **Audit Volume**: events by action, by realm.

Prometheus alerting rules cover:

- `error_rate > 1% for 5m`
- `p99_authorize_latency > 250ms for 10m`
- `login_failure_ratio > 30% for 5m`
- `db_pool_saturation > 80% for 5m`
- `spi_quarantined_total increase`
- `listener_lag > 5s for 1m`
- `token_reuse_detected_total increase` (security alert)

## Non-goals

- **Centralized log aggregation built-in.** We emit JSON to stdout.
- **APM provider integrations** beyond OTLP.
- **PII redaction beyond the listed toggles**. Operators integrate
  with a redaction-aware pipeline if needed.

## Decisions and open items

- **Trace sampling**: `parentbased_traceidratio(0.01)` head-based
  sampler in the SDK. **Tail-based** retention at the collector
  picks up any trace where:
  - a span has `error.kind` set, **or**
  - the root span's duration exceeds the rolling p99 by 2×, **or**
  - a span tagged `spi.outcome != success` is present.

  This combination keeps the cost low while never losing a slow or
  failed authorize. Operators can override the ratio via
  `OTEL_TRACES_SAMPLER_ARG`.
- **Audit event compaction**: deferred to v0.2. For v0.1 we accept
  the cost of writing one row per `token.refreshed`. If a realm
  truly drives millions of refreshes/hour and the audit storage
  proves expensive, the v0.2 plan is a per-family summary row
  flushed every N events or every T seconds.
