# 14 — Roadmap

A milestone-based plan rather than a calendar. Each phase has a
concrete exit criterion. Time estimates are rough orders of magnitude
for a small focused team (2–3 engineers).

## Phase 0 — Foundation (≈ 4–6 weeks)

**Goal:** a server that boots, serves the discovery doc, and signs
its first JWT against a Postgres-backed realm.

Exit criteria:

- [ ] Workspace skeleton with crates listed in
      [`01-architecture.md`](./01-architecture.md).
- [ ] Postgres schema baseline migration (realm, user, client,
      credential, key_material, session, code_grant, refresh_token,
      audit_event).
- [ ] `RealmStorage` + `ClientStorage` traits + Postgres impl with
      RLS enforcement.
- [ ] `geonosis-crypto` with software JWS sign/verify for RS256,
      ES256, EdDSA.
- [ ] `/realms/{slug}/.well-known/openid-configuration` + JWKS
      endpoints.
- [ ] Boot/migration/healthcheck endpoints; `/-/started`,
      `/-/ready`, `/-/healthy`.
- [ ] Cache + listener loop (no SPI yet).
- [ ] CI: build, test, lint, audit, sqlx-prepare.

## Phase 1 — Local authentication (≈ 6–8 weeks)

**Goal:** a real user can log in with username/password via the
browser, receive id/access tokens, and refresh.

Exit criteria:

- [ ] Flow executor + the four built-in flows (browser, direct-grant,
      reset-credentials, registration).
- [ ] Authenticators: `password`, `otp` (TOTP), `cookie`, `consent`.
- [ ] Argon2id password hashing + parameter upgrade-on-login.
- [ ] PKCE-mandated `/authorize` + `/token` (`authorization_code`,
      `refresh_token`, `client_credentials`).
- [ ] Refresh-token rotation with family reuse detection.
- [ ] Session model + browser SSO cookie.
- [ ] Per-pod rate limiter on `/authorize` and `/token`.
- [ ] Audit events for the common login actions.
- [ ] Conformance: passes a self-hosted run of the OIDC Basic
      certification suite.

## Phase 2 — Admin UI v1 (≈ 6–8 weeks)

**Goal:** the binary's admin UI lets an operator create a realm,
manage users, clients, and roles, and view audit events.

Exit criteria:

- [ ] Leptos admin app with SSR + auth via master-realm tokens.
- [ ] CRUD pages for: realms, users, clients, roles, groups,
      sessions.
- [ ] Audit event explorer.
- [ ] REST API `/admin/v1/...` mirroring the UI; OpenAPI doc
      generated.
- [ ] Basic theme overlay (login-template substitution) with hot
      reload.
- [ ] Internationalization plumbing; English + Turkish bundles ship.
- [ ] CLI (`geoctl`) parity for realms / clients / users /
      keys / audit.

## Phase 3 — Federation & broker (≈ 6–8 weeks)

**Goal:** real users can come from LDAP/AD, and "Sign in with
Google/GitHub/corporate Okta" works.

Exit criteria:

- [ ] LDAP federation with pass-through bind and on-demand mirror.
- [ ] AD-specific helpers (objectGUID, sAMAccountName).
- [ ] Identity broker: OIDC discovery-based IdPs + GitHub (OAuth2)
      and Apple (special cases).
- [ ] First-broker-login flow with mapper bindings.
- [ ] SAML 2.0 SP role: AuthnRequest, ACS, SAML metadata download.
- [ ] Connection pool & circuit-breaker for federation sources.

## Phase 4 — SPI v1 (≈ 6 weeks)

**Goal:** operators can ship custom WASM authenticators, mappers, and
event listeners.

Exit criteria:

- [ ] Wasmtime host (`geonosis-spi-host`) with epoch interruption,
      fuel, memory caps.
- [ ] WIT worlds: `geonosis:authn`, `geonosis:mapper`,
      `geonosis:event`, `geonosis:policy`, with `geonosis:host`
      interface.
- [ ] `geonosis-spi-api` crate (Rust authoring SDK).
- [ ] Module upload via admin API + persistence (Postgres `bytea`
      first; S3 backend behind a feature flag).
- [ ] Compiled-module cache (`*.cwasm`) under
      `/var/cache/geonosis/spi/`.
- [ ] Quarantine + retry policies for misbehaving plugins.
- [ ] Reference plugin: a simple "captcha" authenticator and a
      "claim-prefix" mapper.

## Phase 5 — Flow editor v1 (≈ 6 weeks)

**Goal:** operators edit auth flows visually; flows hot-reload.

Exit criteria:

- [ ] Graph editor (Leptos island) reading/writing YAML/JSON DSL.
- [ ] Inline validation (graph cycles, missing providers, etc.).
- [ ] Versioned flow storage; in-flight executions complete on the
      original version.
- [ ] Dry-run with synthetic context to preview branch decisions.
- [ ] All built-in authenticators surfaced with config schemas.

## Phase 6 — Production readiness (≈ 6 weeks)

**Goal:** confidence to run in real production at small/medium scale.

Exit criteria:

- [ ] Helm chart + Operator-friendly Deployment templates.
- [ ] Documented Postgres requirements, sizing, alerting rules.
- [ ] Backup & restore runbook (master key included).
- [ ] Schema migration discipline enforced in CI (the
      [`10-zero-downtime-migrations.md`](./10-zero-downtime-migrations.md)
      lints).
- [ ] OIDC Basic + FAPI 1 Baseline conformance suite passing.
- [ ] Load test fixture (`crates/geonosis-bench`) with target
      profiles (steady-state, spike, MFA-heavy).
- [ ] Security audit pass (in-house: threat model recheck + crypto
      surface review). External audit before v1.0.

## Phase 7 — v0.2 candidates

Picked in order of operator demand. Not committed.

- **Geonosis-as-IdP for SAML** (sign-side).
- **WebAuthn** as a first-class authenticator with passkey lifecycle.
- **DPoP** sender-constraint.
- **Token Exchange** (RFC 8693).
- **Vault Transit / AWS KMS / GCP KMS** backends.
- **Cluster-wide rate limiting** (Redis or DB).
- **Account console** (self-service end-user portal).
- **Kerberos / SPNEGO** browser SSO via SPI.
- **Search by attribute** (full-text on user attributes).
- **K8s Operator CRDs**.
- **Multi-region active-active** plan (deferred design).

## What we explicitly defer to v1.0+

- **UMA 2.0** authorization services.
- **Self-issued OP**.
- **CIBA**.
- **GUI plugin authoring**.
- **Visual builder for login pages** (themes remain file/code-based).
- **Migration importers** (Keycloak realm export → Geonosis).

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Leptos SSR + island hydration immaturity bites us | Keep admin mostly form-post; islands are localized; fall back to plain forms anywhere reactivity is risky |
| Wasmtime WASI 0.2 churn | Pin to a tested release; isolate the host crate so upgrades are auditable |
| OIDC/FAPI conformance surface is large | Run the conformance suite in CI from Phase 1; treat regressions as P0 |
| Schema migration discipline slips | CI lints + a "migration review" approval gate |
| Postgres becomes the single point of contention | Bench from Phase 1; design replica-aware reads for v0.2 |
| Crypto vendoring | `josekit` review + audit before any GA; consider migration to `rustcrypto` after |

## How we'll know it's working

- Every phase ships with a runnable demo and a recorded conformance
  test run.
- Every PR includes either a doc update or a "no docs change needed
  because…" note.
- A weekly load-test run is published to track regression in
  authorize p99 and refresh throughput.
