# Geonosis

Identity & Access Management server written in Rust. OIDC 1.0 + OAuth 2.1
issuer with a graph-DSL flow engine, WebAssembly SPI for plugins, an
embedded Leptos admin UI, and a Kubernetes-native deployment story.

> **Status — v0.1, in active development.** The protocol surface, flow
> engine, storage backends, admin UI, and CLI are all real. Some v0.1
> roadmap items are still incomplete; the **[What works today](#what-works-today)**
> and **[Known gaps before v0.1 GA](#known-gaps-before-v01-ga)** sections
> below distinguish them honestly. `docs/14-roadmap.md` is the
> authoritative scope document — this README is a snapshot of what's
> actually wired in the binary right now.

---

## Quickstart (5 minutes, with Docker)

```sh
make quickstart
```

That runs `docker compose -f deploy/compose/quickstart.yml up -d`,
waits for `/-/ready`, and prints the demo credentials. The compose
stack starts Postgres 16 and the server with
`GEONOSIS_BOOTSTRAP_QUICKSTART=1`, which provisions:

- Realm `acme`
- End-user `ada@master.test` / `ada-pw`
- Admin user `admin@master.test` / `admin-pw`
- OIDC client `master-web` (public, redirect `http://127.0.0.1:8888/callback`)

Verify discovery:

```sh
curl -fsS http://localhost:8080/realms/master/.well-known/openid-configuration | jq .
```

Stop + reset:

```sh
make compose-down      # stops the stack, keeps the DB volume
make compose-wipe      # stops + drops the volume
```

See [`docs/recipes/01-quickstart-docker.md`](./docs/recipes/01-quickstart-docker.md)
for the full walk-through.

## Building from source

```sh
make build       # cargo build --workspace
make test        # cargo test --workspace --lib   (323 tests pass)
make run         # run the server with in-memory storage on :8080
make cli -- --help   # geoctl operator CLI
```

The full target menu lives in [`Makefile`](./Makefile); run `make help`
to list every target.

---

## What works today

### Protocols

- **OIDC 1.0 + OAuth 2.1**: `/authorize`, `/token`, `/userinfo`, `/jwks`,
  `/.well-known/openid-configuration`, `/revoke`, `/introspect`.
- **PKCE S256 mandatory** — `plain` is rejected; public clients without
  PKCE are rejected.
- **Refresh-token rotation with family reuse detection** — reuse burns
  the entire family.
- **PAR** (RFC 9126), **Device Authorization** (RFC 8628),
  **Token Revocation** (RFC 7009), **Introspection** (RFC 7662).
- **Token Exchange** (RFC 8693) — delegation form for the agent-identity
  path; subject-token-type is `access_token` only in v0.1.
- **Per-realm signing keys** (RS256, ES256, EdDSA) with an
  Active → Previous → Disabled state machine and JWKS exposure of both
  during a rotation window.

### Authentication flows + authenticators

- **Graph-DSL flow engine** with versioned snapshots so in-flight
  `FlowState` instances resolve to the version they started on.
- **7 built-in flows** seeded at realm bootstrap: `browser`,
  `direct-grant`, `registration`, `reset-credentials`,
  `first-broker-login`, `client-authentication`, `step-up`.
- **11 built-in authenticators**: `password` (Argon2id), `otp` (TOTP),
  `webauthn` (assertion-as-step), `recovery-code`, `magic-link`,
  `phone-otp`, `consent`, `cookie`, `idp-redirect`, `require-action`,
  `risk-score`.

### Identity surface

- **Users / Credentials / Groups / Roles** — full CRUD with hierarchical
  groups, composite roles, role attributes.
- **Organizations** — domains, memberships, invitations, per-org roles
  (owner/admin/member/custom), IdP bindings, `org` token claim.
- **Brute-force protection** — per-user lockout with configurable backoff.
- **Agent identity** — first-class `Agent` entity with capability URNs
  and a delegated-token mint path.
- **LDAP / AD federation** — pool registry, full + incremental sync.
- **Identity brokering** (OIDC, SAML SP role only) — generic OIDC
  adapter; vendor-specific adapters (Google/GitHub/Apple/Microsoft) are
  partial (see gaps).

### Storage + cluster

- **Two storage backends**: in-memory (dev quickstart) and Postgres.
- **Postgres** with row-level security (`tenant_isolation` policy per
  table; `current_setting('geonosis.realm_id')` set per request).
- **Cache trait** with three implementations: Redis (default v0.1),
  LocalCache (Moka L1 + Postgres `LISTEN`/`NOTIFY`), and a Noop for tests.
- **Single-flight per-key dedupe** inside the cache layer.
- **Per-realm in-process token-bucket rate limiter** on the hot OIDC
  endpoints (cluster-wide Redis-backed counters land in v0.2).
- **Zero-downtime migrations** — expand/contract discipline,
  `pg_advisory_lock`-gated runner, and a `schema_compat` enforcement
  at boot.

### Admin REST API + operator CLI

- `/admin/v1/...` REST surface covers realms, clients, users, roles,
  groups, organizations (+ domains + members + invitations + roles +
  consent policies + IdP bindings), agents, identity providers, keys,
  sessions, audit events, flows.
- `geoctl` CLI mirrors the surface plus database-admin ops:
  `realms`, `users`, `clients`, `orgs`, `agents`, `keys`, `events`,
  `flows` (validate / export / import), `spi` install/list,
  `migrate` up/status, `federation` sync.

### Admin UI (Leptos SSR)

- List + detail pages for: realms, users, clients, roles, groups,
  organizations, agents, identity providers, sessions, audit events,
  flows.
- Audit-event explorer with action / actor / from / until filters
  (server-rendered `<form method="get">` — no JS).
- Flow editor JSON-first scaffold (server-rendered skeleton with a
  textarea; the hydrated canvas island is v0.1.x).
- Two shared Leptos primitives — `<ListTable>` and `<PageHeader>` —
  remove the boilerplate every CRUD page used to duplicate.

### Operations + DX package

- **5-minute quickstart** via `make quickstart` (Docker Compose).
- **Dockerfile** (multi-stage; non-root user; minimal Debian-slim
  runtime with `ca-certificates`, `tzdata`, `curl`).
- **Helm chart** in `deploy/helm/geonosis/` — Deployment with
  `maxUnavailable: 0` + topology spread + preStop drain hook,
  Service, Ingress, HPA, PDB, NetworkPolicy, ServiceAccount, plus
  optional `ServiceMonitor` + `PrometheusRule` (operator-gated).
- **Health probes**: `/-/started`, `/-/ready`, `/-/healthy`, plus
  `POST /-/drain` for the K8s `preStop` hook.
- **Prometheus** `/metrics` endpoint (see gaps for what's actually
  emitted today vs the roadmap target).
- **One shipped Grafana dashboard** at `deploy/grafana/geonosis-overview.json`
  (the other five from the doc table are tracked in
  `deploy/grafana/README.md`).
- **Two example apps** under `examples/`: an axum resource server with
  JWKS verify (Rust), and a Next.js 14 + Auth.js v5 OIDC client.
- **20 task-oriented recipes** under `docs/recipes/`.

---

## Known gaps before v0.1 GA

Honest list. Some of these are intentional v0.1.x / v0.2 splits per
`docs/14-roadmap.md`; some are unfinished v0.1 work. Each item links
out to the doc it lives under so you can check the contract.

### Protocol

- **SAML IdP role** — the `geonosis-protocol-saml-idp` crate exists
  with assertion-builder types, but no `/realms/:slug/protocol/saml/*`
  endpoints are wired in the router yet. Doc 20 is the contract; the
  HTTP integration (metadata, SSO, ACS, SLO, signed assertions) is
  scheduled as the next major sprint.
- **JAR** (signed `request=` parameter, RFC 9101) — intentionally
  deferred to v0.2; discovery advertises `request_parameter_supported=false`
  honestly. PAR covers the equivalent use case.
- **Token Exchange — scope limits.** Only `subject_token_type=access_token`
  is accepted in v0.1. Impersonation (no `act` chain), refresh-token
  subjects, and arbitrary audience reduction land alongside Agent v1.
- **Step-up ACR enforcement** — the `step-up` built-in flow exists, but
  the flow executor doesn't yet gate on the `acr_values` request
  parameter; the requested ACR is recorded in context and the gate is
  v0.1.x.
- **SSO browser cookie** — v0.1 has no persistent SSO cookie surface,
  so every `/authorize` starts a fresh interactive login. `prompt=none`
  and `max_age` enforcement land with the cookie surface.
- **FAPI 1 Baseline conformance suite in CI** — the defaults are
  FAPI-compatible (PKCE-mandatory, S256 only, asymmetric tokens), but
  there is no OpenID Foundation conformance harness wired in CI yet.

### Observability

- **Prometheus metric set is incomplete.** The `/metrics` endpoint
  exposes 5 series today: `geonosis_build_info`,
  `geonosis_process_start_time_seconds`, `geonosis_http_requests_total`,
  `geonosis_http_responses_total{class}`, `geonosis_audit_events_total`.
  Doc 13 lists ~22; the remaining ~17 (OIDC counters, DB pool gauges,
  cache hit/miss, listener lag, SPI counters, token-reuse-detected,
  HTTP latency histogram) are declared in alert rules but not yet
  emitted from the handlers. Dashboards and alert rules that reference
  them evaluate to "no data" until the instrumentation lands.
- **Audit event emission is wired but not called.** The audit
  `Publisher` is in `AppState`, the Postgres + webhook sinks work, but
  the OIDC / admin handlers don't yet call `audit.publish(...)` on
  state-changing operations. Rows land only when something writes them
  directly. This is the v0.1.x audit-instrumentation pass.
- **1 of 6 shipped Grafana dashboards** (Overview). Authentication,
  Token Lifecycle, Federation Health, Cluster Health, Audit Volume
  dashboards are tracked in `deploy/grafana/README.md` and unblock
  once the missing metrics emit.

### Flows + admin UI

- **Built-in flows don't auto-seed at realm creation.** The 7 built-in
  `FlowDefinition`s exist (`geonosis_flow::builtin::v0_1_flows()`) but
  neither `create_realm` nor the quickstart bootstrap calls them, so a
  freshly-created realm has no `browser` / `direct-grant` / … flow
  installed. Today the workaround is `geoctl flows import` per alias;
  the auto-seed call is a one-line v0.1.x fix.
- **Flow version desync window.** In-flight `FlowState`s read the
  current `(realm, alias)` flow row rather than the version they
  started on, so editing a flow while a user is mid-login can break
  their session. Doc 06's design is snapshot-keyed reads with a
  long-TTL GC pass; only the storage column is present today.
- **Flow editor canvas.** v0.1 ships the SSR skeleton plus a
  `<textarea>` for the JSON DSL (server-side `geonosis_flow::compile`
  validates on save). Doc 08 §"Flow editor (special case)" describes
  a hydrated canvas island; v0.1.x is the canvas pass.
- **Admin UI scope.** All Leptos list pages are read-only in v0.1;
  the doc-promised inline create / edit / delete forms (and the SPI
  binding management UI) land in v0.1.x. CRUD itself is fully reachable
  through `geoctl` and the JSON `/admin/v1/...` surface today.

### Identity surface

- **Org consent policies** — stored end-to-end, but not enforced at the
  authorize / consent screen (the consent decision is still
  per-client). Doc 15 §"Consent management" is the contract.
- **Password / OTP / WebAuthn policy** — settings are persisted on the
  realm row and surface in the admin UI, but the runtime path that
  validates a candidate credential against the policy isn't wired yet.
- **User-Profile validators** — declarative schema parses + stores, but
  user create / update don't run the validators (regex, length, custom
  WASM) on input attributes yet.
- **Domain verification** — the admin endpoint accepts a candidate
  domain and the "verified" flag, but the DNS TXT challenge isn't
  performed yet; verification is operator-asserted in v0.1.
- **Vendor broker adapters** — only the generic OIDC adapter is
  functional; the Google / GitHub / Apple / Microsoft quirk modules
  defined in `geonosis-broker` are placeholders.
- **Pairwise subject identifiers** — `Client.pairwise_sub_algorithm`
  field persists, but the token mint path doesn't yet honor it.

### Plugins / SPI

- **All 9 WIT interfaces have a host runtime** in
  `crates/geonosis-spi-host/src/runtime/`: `authn`, `mapper`, `event`,
  `policy`, `user-storage`, `broker-adapter`, `user-profile-validator`,
  `ui-component`, plus the `host` capability surface (logging /
  secrets / http-client). End-to-end dispatch (load → compile → call
  → decode wire result) has only been driven through `authn`,
  `mapper`, and `event` so far; the other runtimes compile but have
  no integration smoke test.
- **Built-ins as plugins** — `ProviderRegistry` is in place and the
  URN scheme (`builtin:*` vs `wasm:*`) is enforced, but built-in
  authenticators / mappers / events are **not** seeded as `SpiBinding`
  rows at realm bootstrap. Operators therefore cannot reorder or
  override built-ins through the admin UI / API yet — the flow
  executor falls back to a hard-coded built-in dispatcher when no
  WASM binding matches. Doc 07 §"Provider registry + built-ins-as-plugins"
  is the contract; v0.1.x will fix the seeding.
- **Plugin manifest signing** — the verification primitives exist
  in `geonosis_spi_host::manifest` (Ed25519 signature, SHA-256 of
  bytecode, trust-list check, all unit-tested). The `geoctl spi install`
  CLI command stores the bytecode + SHA but does **not** invoke
  these primitives yet — the trust enforcement step is v0.1.x.
- **Hot reload** of WASM modules is designed (modules are compiled
  on-demand from bytecode + cached) but the file watcher / cache
  invalidator that would let an operator push a new bytecode and
  see it picked up live isn't wired yet.

### DX

- **`geonosis-verify` crate** (embeddable JWT validator for resource
  servers) — scheduled for v0.2 alongside the SDK push.
- **Other framework examples** — only Next.js + axum ship in v0.1; the
  SvelteKit / FastAPI / Spring / Django ones come with v0.2.
- **OpenAPI spec generation + auto-generated client SDKs** — v0.2.

---

## Project layout

```
crates/
  geonosis-core/             # Domain types, IDs, common enums
  geonosis-crypto/           # KMS trait + Software impl + Argon2id
  geonosis-storage/          # Storage trait + Memory + Postgres impls
  geonosis-migrate/          # Embedded SQL migrations + leader lock
  geonosis-cache/            # Cache trait + Redis + LocalCache + Noop
  geonosis-flow/             # Graph DSL + executor + 7 built-in flows
  geonosis-authenticators/   # 11 built-in authenticator implementations
  geonosis-spi-host/         # WIT interfaces + wasmtime runtime hosts
  geonosis-protocol-oidc/    # OIDC discovery + authorize + token
  geonosis-protocol-oauth/   # OAuth 2.1 grants + PAR + device + introspect
  geonosis-protocol-saml-idp/  # SAML IdP types (not yet routed)
  geonosis-broker/           # Identity broker (OIDC + SAML SP)
  geonosis-federation-ldap/  # LDAP/AD federation runtime
  geonosis-audit/            # Audit publisher + Postgres + webhook sinks
  geonosis-admin-ui/         # REST v1 handlers + Leptos SSR pages
  geonosis-ui-kit/           # Maud component primitives + design tokens
  geonosis-theme/            # Theme overlay engine
  geonosis-i18n/             # FTL bundles
  geonosis-server/           # Binary: axum router + AppState + bootstrap
  geonosis-cli/              # geoctl operator CLI

deploy/
  compose/quickstart.yml     # Local-dev Postgres + server stack
  helm/geonosis/             # Production-target Helm chart
  grafana/                   # Dashboards
  prometheus-rules/          # Alert rules

examples/
  axum-resource-server/      # Rust JWT-verify resource server
  nextjs-app/                # Next.js 14 + Auth.js v5 OIDC client

docs/                         # Authoritative scope + design docs
docs/recipes/                 # 20 task-oriented recipes
Makefile                      # Build / test / run / deploy targets
Dockerfile                    # Multi-stage server image
```

---

## Documentation

Authoritative scope lives under [`docs/`](./docs/). Start with:

- [`docs/README.md`](./docs/README.md) — table of contents.
- [`docs/14-roadmap.md`](./docs/14-roadmap.md) — v0.1 / v0.2 / v0.3 split.
- [`docs/01-architecture.md`](./docs/01-architecture.md) — component
  map.
- [`docs/recipes/`](./docs/recipes/) — task-oriented how-tos.

## License

TBD.
