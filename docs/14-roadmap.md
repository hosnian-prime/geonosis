# 14 — Roadmap

The authoritative phase-distribution document. Every feature
discussed in any other doc is placed in v0.1, v0.2, or v0.3, with a
brief "how" pointer. The target: **by v0.3, the platform covers
substantially the entire feature surface of incumbent enterprise
IAMs**, plus several differentiators.

This is a milestone-based plan, not a calendar. Time estimates are
rough orders of magnitude for a focused team of 2–3 engineers.

## v0.1 — Foundation + critical differentiators (≈ 6–8 months)

The goal of v0.1 is to ship a platform that, even at "first release",
covers the everyday IAM needs of a B2B SaaS or enterprise team **and**
includes the differentiators (visual graph flows, WASM SPI override,
Organizations, Agent identity, SAML IdP role) that justify migration
from incumbents.

### v0.1 — Core protocol surface

| Feature | Doc | How |
|---|---|---|
| OIDC 1.0 + OAuth 2.1 endpoints | [`03`](./03-protocols-oidc.md) | `geonosis-protocol-oidc` + `geonosis-protocol-oauth` crates |
| PKCE-mandatory authorize + token | [`03`](./03-protocols-oidc.md) | Default policy; `plain` rejected |
| Refresh-token rotation + family reuse detection | [`03`](./03-protocols-oidc.md) | `family_id` lineage; reuse burns the family |
| FAPI 1 Baseline conformance | [`03`](./03-protocols-oidc.md) | Defaults are FAPI-compatible; **conformance suite CI moved to v0.1.x** |
| Token Exchange (RFC 8693) | [`03`](./03-protocols-oidc.md) + [`18`](./18-agent-identity.md) | First implementation lands with Agent identity |
| Device Authorization grant (RFC 8628) | [`03`](./03-protocols-oidc.md) | Polling endpoint; interval hard-coded 5 s |
| PAR (RFC 9126) | [`03`](./03-protocols-oidc.md) | Pushed authorization requests |
| JAR (RFC 9101) | [`03`](./03-protocols-oidc.md) | Signed request objects; **implementation moved to v0.1.x** |
| Token revocation (RFC 7009) + introspection (RFC 7662) | [`03`](./03-protocols-oidc.md) | `/oauth2/revoke` + `/oauth2/introspect` |
| SAML 2.0 SP role (consuming SAML IdPs) | [`05`](./05-identity-broker.md) | `geonosis-broker` |
| **SAML 2.0 IdP role (issuing assertions)** | [`20`](./20-saml-idp.md) | `geonosis-protocol-saml-idp` crate, NEW push to v0.1 |
| Per-realm signing keys (RS / ES / EdDSA) | [`12`](./12-security-crypto.md) | `KeyMaterial` with state-machine; software keys in v0.1 |
| JWS + JWE | [`12`](./12-security-crypto.md) | `josekit`; algorithm allowlist |
| Built-in flows: browser, direct-grant, reset-credentials, registration, first-broker-login, client-authentication, **step-up** | [`06`](./06-auth-flows.md) | Graph DSL; per-version snapshots |
| ACR policy (per-realm authn-strength) | [`12`](./12-security-crypto.md) | Sender-constraint + AMR boolean over levels |

### v0.1 — Identity & user surface

| Feature | Doc | How |
|---|---|---|
| Users + Credentials + Groups + Roles | [`02`](./02-data-model.md) | Postgres schema; hierarchical groups; composite roles |
| **Role attributes** | [`02`](./02-data-model.md) | `Role.attributes` consumed by built-in mappers |
| **Organizations** (B2B SaaS sub-realm) | [`15`](./15-organizations.md) | Full feature: domains, invitations, memberships, per-org IdPs, per-org roles (owner/admin/member/custom with fine-grained permissions), branding, `org` token claim |
| **Consent management** (system + org-level) | [`15`](./15-organizations.md) | Per-client consent screen, persisted `ConsentGrant`, org consent policies (pre-approve/block/manage scopes), consent audit trail |
| **User Profile** declarative schema | [`16`](./16-user-profile.md) | Per-realm attribute schema, validators (incl. WASM custom), `Reject` default unmanaged policy |
| LDAP/AD federation | [`04`](./04-federation-ldap.md) | `builtin:user-storage:ldap:{alias}` provider, AD tombstone-as-disable |
| Identity brokering (OIDC + SAML SP) | [`05`](./05-identity-broker.md) | Generic adapters + first-party plugins for Google, GitHub, Apple, Microsoft |
| **Agent identity** (AI / M2M delegation) | [`18`](./18-agent-identity.md) | First-class `Agent` entity; Token Exchange path; capability URN namespace; audit category |
| `required_actions` + `required_flow` | [`06`](./06-auth-flows.md) | Admin-set per-user gates; evaluated at flow Start |
| Full-text user search (tsvector) | [`02`](./02-data-model.md) | Generated `search_vector` column + GIN index |
| Pairwise subject identifiers per client | [`02`](./02-data-model.md) | `Client.pairwise_sub_algorithm` |
| Realm-level password policy DSL | [`02`](./02-data-model.md) | `PasswordRule` enum |
| OTP policy + WebAuthn policy | [`02`](./02-data-model.md) | Per-realm; supports passwordless config |
| Brute-force protection | [`02`](./02-data-model.md) | Per-user lockout, configurable backoff |

### v0.1 — Built-in authenticators

`password`, `otp` (TOTP), `cookie`, `consent`, **`webauthn`
(assertion-as-step; full passkey lifecycle v0.2)**, `recovery-code`,
`magic-link`, `phone-otp` (authenticator in v0.1; SMS dispatch via
an event-listener-style SPI plugin; first-party `spi-twilio` ships
v0.1, self-service end-user enrollment lands with the account
console in v0.2), `idp-redirect`, `require-action`, `risk-score`
(returns a discrete decision; full anomaly detection v0.3).
Spec in [`06`](./06-auth-flows.md).

### v0.1 — WASM SPI

| WIT interface | Purpose | Doc |
|---|---|---|
| `geonosis:authn@0.1.0` | Custom authenticators | [`07`](./07-spi-wasm.md) |
| `geonosis:mapper@0.1.0` | Claim transformations (token, id, SAML, userinfo) | [`07`](./07-spi-wasm.md) |
| `geonosis:event@0.1.0` | Event listeners | [`07`](./07-spi-wasm.md) |
| `geonosis:policy@0.1.0` | Policy decisions (scope grants, agent capabilities) | [`07`](./07-spi-wasm.md) |
| `geonosis:user-storage@0.1.0` | User-storage providers (replaces `federation`) | [`07`](./07-spi-wasm.md) |
| `geonosis:broker-adapter@0.1.0` | Vendor IdP quirks | [`07`](./07-spi-wasm.md) |
| `geonosis:user-profile-validator@0.1.0` | Custom attribute validators | [`16`](./16-user-profile.md) |
| `geonosis:ui-component@0.1.0` | Server-side UI component overrides for admin / login | [`08`](./08-admin-ui.md) |
| `geonosis:host@0.1.0` | Host capabilities exposed to plugins | [`07`](./07-spi-wasm.md) |

**Provider registry + built-ins-as-plugins** ([`07`](./07-spi-wasm.md)):
every built-in registers as a `SpiBinding` with a `builtin:`
URN; operators can replace, disable, or chain extras around any
built-in via the same admin UI surface as third-party plugins.

Authoring SDK: **Rust** only in v0.1 (`geonosis-spi-api`).

### v0.1 — Admin UI + theming

| Feature | Doc | How |
|---|---|---|
| Embedded Leptos SSR + island hydration | [`08`](./08-admin-ui.md) | `geonosis-admin-ui` + `geonosis-ui-kit` |
| Slot-based component override | [`08`](./08-admin-ui.md) | `Surface` trait; built-in + WASM-backed implementations |
| File-based theme overlay (template substitution) | [`08`](./08-admin-ui.md) | Filesystem watcher; hot reload |
| Internationalization (FTL bundles, RTL-day-one) | [`08`](./08-admin-ui.md) | `geonosis-i18n` |
| CRUD pages: realms, users, clients, roles, groups, orgs, sessions, agents | [`08`](./08-admin-ui.md) | Form-post-first; flow editor is the only hydrated island |
| Visual flow editor (graph canvas) | [`06`](./06-auth-flows.md) + [`08`](./08-admin-ui.md) | YAML/JSON round-trip; dry-run with synthetic context |
| Audit event explorer | [`13`](./13-observability.md) | Filter by realm / actor / action / time |
| Theme sandbox threat model | [`08`](./08-admin-ui.md) | CSP + escape-by-default + no template I/O primitives |
| WCAG 2.1 AA + day-one RTL | [`08`](./08-admin-ui.md) | CSS logical properties only (CI lint) |

### v0.1 — Cluster / cache / cluster-state

| Feature | Doc | How |
|---|---|---|
| `Cache` trait | [`09`](./09-cache-invalidation.md) | Hides backend; supports Redis (default), LocalCache (no-Redis), Komino (v1.x) |
| Default impl: Redis (KV + pub/sub fan-out) | [`09`](./09-cache-invalidation.md) | `geonosis-cache::redis`; Sentinel/Cluster supported |
| Alternative impl: LocalCache (in-process LRU + Postgres LISTEN/NOTIFY) | [`09`](./09-cache-invalidation.md) | `geonosis-cache::local`; for small/air-gapped installs |
| L1 in-process LRU (Moka) | [`09`](./09-cache-invalidation.md) | 1-second TTL; collapses hot-path round-trips |
| Single-flight per-key dedupe | [`09`](./09-cache-invalidation.md) | L1 + L2 lease-based |
| Per-pod rate limiter | [`12`](./12-security-crypto.md) | Token bucket; cluster-wide variant in v0.2 |
| Postgres row-level security | [`02`](./02-data-model.md) | `tenant_isolation` policy per realm |

### v0.1 — Deployment

| Feature | Doc | How |
|---|---|---|
| Helm chart for K8s | [`11`](./11-deployment-k8s.md) | `deploy/helm/geonosis/` |
| Health probes (`/-/started`, `/-/ready`, `/-/healthy`) | [`11`](./11-deployment-k8s.md) | DB pool / listener / SPI registry health |
| PodDisruptionBudget + topologySpreadConstraints + NetworkPolicy | [`11`](./11-deployment-k8s.md) | Defaults in chart |
| Rolling update strategy `maxUnavailable: 0` | [`11`](./11-deployment-k8s.md) | preStop drain hook 15 s |
| Expand-contract migration discipline | [`10`](./10-zero-downtime-migrations.md) | CI lint, schema-version compatibility window |
| Operator-driven Postgres backup runbook | [`11`](./11-deployment-k8s.md) | + master-key derivation note |

### v0.1 — Observability

| Feature | Doc | How |
|---|---|---|
| OTel logs + metrics + traces from day-0 | [`13`](./13-observability.md) | `tracing` + `tracing-opentelemetry` |
| Tail-sampled OTLP exports for errors / slow requests | [`13`](./13-observability.md) | Sampler at collector |
| Prometheus `/metrics` endpoint | [`13`](./13-observability.md) | `geonosis_*` namespace |
| Audit events to Postgres + webhook | [`13`](./13-observability.md) | Two sinks built-in |
| Shipped Grafana dashboards + PrometheusRule alerts | [`13`](./13-observability.md) | `deploy/grafana/`, `deploy/prometheus-rules/` |

### v0.1 — Developer experience

| Feature | Doc | How |
|---|---|---|
| **5-minute quickstart** | [`21`](./21-dx-package.md) | Single Docker compose; bootstrap realm; 3 cURL commands |
| **Next.js example app** | [`21`](./21-dx-package.md) | `examples/nextjs-app/` |
| **axum resource-server example** | [`21`](./21-dx-package.md) | `examples/axum-resource-server/` |
| **20 task-oriented recipes** | [`21`](./21-dx-package.md) | `docs/recipes/` |
| `geoctl` operator CLI | [`08`](./08-admin-ui.md) | parity with admin UI for realms/clients/users/orgs/keys/audit/spi |
| YAML/JSON flow export/import | [`06`](./06-auth-flows.md) | `geoctl flows ...` |
| Plugin packaging convention | [`07`](./07-spi-wasm.md) | `geoctl spi install` + signed manifests |

### v0.1 — Cross-cutting

- Single binary (`geonosis-server`), no JVM.
- Multi-pod K8s native.
- Hot reload: config, themes, WASM plugins, key rotations — all
  without restarts.
- All entities partitionable / scopable by `realm_id`; RLS as
  defense-in-depth.
- `master` realm bootstrap.

---

## v0.1.x — Production hardening (≈ 4–6 weeks after v0.1 feature freeze)

The goal of v0.1.x is to close the gap between "feature-complete v0.1"
and "production-safe for external traffic". No new features — only
hardening, compliance verification, and fixes for gaps discovered
during the v0.1 audit. Items are ordered by dependency: SSO cookie
unlocks conformance testing, conformance testing validates the
protocol surface, load testing validates the deployment model.

### v0.1.x — SSO session surface (prerequisite for everything below) ✅ DONE

| Feature | Why | How | Status |
|---|---|---|---|
| **SSO browser cookie** (`geonosis_sid`) | Without this, every `/authorize` starts a fresh login; `prompt=none` always returns `login_required`; SPAs cannot do silent token renewal; SAML IdP-initiated flow is fragile | Realm-scoped `HttpOnly; SameSite=Lax; Secure` cookie set on login success (`login_actions.rs`), read on `/authorize` (`authorize/sso.rs`); resolves existing session → skip flow when `max_age` not elapsed | ✅ |
| `prompt=none` + `prompt=login` + `prompt=consent` enforcement | OIDC Core §3.1.2.1 compliance; RPs depend on `prompt=none` for silent renewal | `authorize/sso.rs::enforce_prompt_policy()`: `prompt=none` → reuse session or `login_required`; `prompt=login` → force re-auth; `prompt=none` mutually exclusive with all other values | ✅ |
| `max_age` enforcement with `auth_time` | RPs use `max_age` to demand fresh authentication | Compare `now - session.started_at` against `max_age`; trigger re-auth if elapsed | ✅ |
| `id_token_hint` session resolution on `/authorize` | Required for RP-Initiated Logout and silent renewal flows | Extract `sub` from hint payload, validate against cookie-bound session user; full JWT signature verification in v0.2 | ✅ |
| SSO shortcircuit code path | Skip login flow entirely when valid session exists | `authorize/sso.rs::shortcircuit()`: updates `last_seen_at`, records client participation for logout fan-out, mints `CodeGrant` directly | ✅ |
| `session_id` threading into flow context | Cookie authenticator needs session ID during flow execution | `FlowContext.session_id` populated from cookie; `flow_runtime.rs` passes it into `AuthnContext` | ✅ |

### v0.1.x — Security hardening

| Feature | Why | How |
|---|---|---|
| **Per-realm key derivation** (`refresh_hash_key`, `client_secret_hash_key`) | Current deployment-wide single key means a compromise in one realm leaks all realms' refresh tokens | BLAKE3 keyed derivation with `realm_id` as domain separator; backwards-compatible migration (re-hash on next refresh) |
| **Cluster-wide rate limiting** (moved from v0.2) | Per-pod token-bucket is bypassed in multi-pod deployments; attacker distributes brute-force across pods | Redis `INCRBY` + sliding window; falls back to per-pod when Redis is unavailable; reuses existing Redis dependency from cache layer |
| `CodeGrant.acr` Postgres migration | P1-3 fix added the field to the struct but no DB column exists | `20260520001_add_acr_to_code_grant.up.sql`: `ALTER TABLE code_grant ADD COLUMN acr TEXT` |
| Error-path timing normalization | Password verification timing leaks whether the username exists (fast reject on unknown user vs. slow Argon2 on known user) | Constant-time dummy Argon2 verify on unknown-user path |

### v0.1.x — Conformance & interop verification

| Feature | Why | How |
|---|---|---|
| **OIDC Basic conformance suite in CI** | v0.1 "done" signal requires it (line 373); catches edge cases that unit tests miss | OpenID Foundation RP test against a bootstrapped Geonosis instance in GitHub Actions |
| **FAPI 1 Baseline conformance suite in CI** | v0.1 roadmap line 27 promises it; enterprise procurement requires certification | Same CI flow; FAPI profile enforces stricter defaults |
| **Vendor broker interop tests** | Google/GitHub/Apple/Microsoft adapters listed in v0.1 but never tested against real providers | CI job with test OAuth apps on each provider; asserts token exchange + userinfo roundtrip |
| JAR (RFC 9101) signed `request` parameter | Listed in v0.1 (line 30) alongside PAR but not implemented; `authorize.rs` returns `request_not_supported` | Parse + verify signed request JWT; reject unsigned when `require_request_object_signing` is set on client |

### v0.1.x — Observability completeness

| Feature | Why | How |
|---|---|---|
| Wire `cache_hits` / `cache_misses` metrics | Defined but never incremented; cache performance is invisible in dashboards | Add `.inc()` calls in `LocalCache::get` and `RedisCache::get` |
| Wire `spi_quarantined` metric | Defined but never incremented; SPI health alerts fire on missing data | Add `.inc()` in SPI host quarantine logic |
| Complete Grafana dashboards (5 of 6 blocked) | Only the Overview dashboard ships; OIDC, Sessions, Cache, SPI, Federation dashboards have no data | Wire remaining metrics, validate each dashboard against a running instance |

### v0.1.x — Load testing

| Feature | Why | How |
|---|---|---|
| **Authorize + token load test** (target: ≥ 5000 req/s on 4 vCPU) | v0.1 "done" signal requires it | `k6` or `oha` script in `tests/load/`; CI runs nightly against a 4-vCPU pod with warm Postgres + Redis |
| Connection-pool tuning runbook | Default `sqlx` pool size may bottleneck under load | Document pool-size / max-connections / idle-timeout tuning |
| Flame-graph profiling pass | Identify hot paths before production traffic | `cargo flamegraph` on the load test; optimize top 3 bottlenecks |

### v0.1.x — "Done" criteria (gate for v0.2 start)

| Criterion | Verification |
|---|---|
| ✅ SSO cookie works end-to-end | `prompt=none` returns tokens without re-login; `max_age=0` forces re-auth; implemented in `authorize/sso.rs` |
| OIDC Basic + FAPI 1 Baseline conformance green in CI | OpenID Foundation test report attached to release |
| Load test ≥ 5000 authorize req/s on 4 vCPU | CI artifact with p50/p95/p99 latencies |
| All Prometheus metrics emit data | Grafana dashboards show non-zero values for every panel |
| Per-realm key derivation active | Refresh tokens from realm A cannot be validated in realm B |
| Cluster-wide rate limiting active | Multi-pod brute-force test shows unified counter enforcement |

---

## v0.2 — Enterprise B2B + ecosystem expansion (≈ 4–6 months after v0.1.x)

The goal of v0.2 is parity with established enterprise IAMs on
features that enterprise procurement teams check off explicitly,
plus the ecosystem assets (SDKs, account console, KMS) that move
adoption from "we evaluated it" to "we deployed it". v0.2 starts
only after v0.1.x "done" criteria are met (conformance green, SSO
cookie working, load test passing).

### v0.2 — Protocols

| Feature | Doc | How |
|---|---|---|
| **SCIM 2.0 inbound + outbound** | [`19`](./19-scim.md) | `geonosis-protocol-scim` (inbound) + `builtin:event:scim-outbound` (outbound) |
| **WebAuthn passkey lifecycle** | [`08`](./08-admin-ui.md) + [`16`](./16-user-profile.md) | Self-service enrollment / removal / cross-device sync / recovery in account console |
| **DPoP** sender-constrained tokens | [`03`](./03-protocols-oidc.md) | RFC 9449; per-realm choice |
| **mTLS-bound tokens** | [`03`](./03-protocols-oidc.md) | RFC 8705; per-realm choice |
| JARM signed response_mode=jwt | [`03`](./03-protocols-oidc.md) | Per-client opt-in |
| Token Exchange GA (full RFC 8693 surface) | [`03`](./03-protocols-oidc.md) | All token type combinations |
| Device polling interval per-realm | [`03`](./03-protocols-oidc.md) | Replace v0.1's hard-coded 5 s |
| Self-service passkey enrollment flow | [`06`](./06-auth-flows.md) | Built-in flow `passkey-enroll` |

### v0.2 — Crypto

| Feature | Doc | How |
|---|---|---|
| **BYOK upload** (PEM/JWK/DER → wrapped or KMS-imported) | [`12`](./12-security-crypto.md) | Admin UI + `geoctl keys import` |
| **HashiCorp Vault Transit** KMS backend | [`12`](./12-security-crypto.md) | First external KMS implementation |
| AWS KMS backend | [`12`](./12-security-crypto.md) | Asymmetric KMS keys; IRSA-compatible auth |
| GCP KMS backend | [`12`](./12-security-crypto.md) | Workload Identity auth |

### v0.2 — End-user surface

| Feature | Doc | How |
|---|---|---|
| **Account console** | [`08`](./08-admin-ui.md) | New `geonosis-account-ui` crate; SSR + island; profile editing, session list, MFA enrollment, brokered-identity linking, org memberships, agent management |
| **GDPR self-service** (export + delete) | [`13`](./13-observability.md) | `/account/me/export` (ZIP), `/account/me/delete` (cooling-off + audit anonymize), admin-API equivalents |
| Phone OTP enrollment in account console | [`08`](./08-admin-ui.md) | Plugin-provided SMS sender (Twilio / MessageBird / SNS) via mapper config |
| Account-console attribute editing from User Profile schema | [`16`](./16-user-profile.md) | Forms generated from declared schema |

### v0.2 — Operational

| Feature | Doc | How |
|---|---|---|
| ~~Cluster-wide rate limiting~~ | [`12`](./12-security-crypto.md) | **Moved to v0.1.x** — per-pod only is a security gap in multi-pod |
| Audit sinks: Kafka, cloud-native (CloudWatch / Stackdriver / Loki) | [`13`](./13-observability.md) | New `EventSinkKind` variants |
| Audit event compaction | [`13`](./13-observability.md) | Per-token-family summary rows |
| Migration progress UI in admin console | [`10`](./10-zero-downtime-migrations.md) | Backfill worker status + ETA |
| IP truncation + UA redaction toggles | [`13`](./13-observability.md) | Surfaced in admin |
| **Per-realm metering counters** | [`22`](./22-cloud-offering.md) | Audit pipeline counters; consumed by managed Cloud |
| Test-mode realms | [`21`](./21-dx-package.md) | `geoctl realm create --kind test --auto-seed`; flagged in admin UI |

### v0.2 — SPI ecosystem

| Feature | Doc | How |
|---|---|---|
| **Go (TinyGo) authoring SDK** | [`07`](./07-spi-wasm.md) | `geonosis-spi-go` |
| **JavaScript / TypeScript (ComponentizeJS) SDK** | [`07`](./07-spi-wasm.md) | `geonosis-spi-js` |
| `geonosis:scim-mapper@0.1.0` SPI | [`19`](./19-scim.md) | Per-target transform on push |
| `geonosis:scim-target-auth@0.1.0` SPI | [`19`](./19-scim.md) | Non-standard SCIM endpoint auth |
| `geonosis:agent-attestation@0.1.0` SPI | [`18`](./18-agent-identity.md) | Validate actor-token attestations |
| `spi-kerberos` first-party plugin | [`04`](./04-federation-ldap.md) | Kerberos / SPNEGO browser SSO |
| `spi-okta`, `spi-onelogin` first-party plugins | [`05`](./05-identity-broker.md) | Vendor quirks |

### v0.2 — DX

| Feature | Doc | How |
|---|---|---|
| **`geonosis-verify` Rust crate published** | [`21`](./21-dx-package.md) | JWT validator + JWKS cache; DPoP/mTLS-aware; agent `act` unwrap |
| OpenAPI spec generated for admin REST | [`08`](./08-admin-ui.md) | `utoipa` annotations |
| **Admin SDKs (TS, Python, Go, Rust)** | [`21`](./21-dx-package.md) | Auto-generated from OpenAPI |
| Postman / Bruno collection | [`21`](./21-dx-package.md) | Auto-exported from OpenAPI |
| SvelteKit + FastAPI example apps | [`21`](./21-dx-package.md) | `examples/sveltekit-app/`, `examples/fastapi-resource-server/` |
| Migration guides from incumbent IAMs (concept-mapping) | [`21`](./21-dx-package.md) | Docs only; no automated converter |
| Recipes set 2 (next 10) | [`21`](./21-dx-package.md) | SCIM provisioning, passkey enrollment, agent setup, etc. |
| Docs site (`docs.geonosis.dev`) + Algolia search | [`21`](./21-dx-package.md) | Docusaurus-style |

### v0.2 — Cloud preparation (no Cloud code yet)

- **Per-realm metering hooks** in audit pipeline (see Operational).
- Cloud private preview with design-partner customers.
- Compatibility checklist enforcement in CI (no cross-realm reads, etc.).

---

## v0.3 — Almost-everything done (≈ 6–8 months after v0.2)

The goal of v0.3: a customer evaluating Geonosis against any
incumbent finds **the feature they need is here**, with a small set
of named exceptions (multi-region active-active and a few legacy
protocols). Cloud GA happens here.

### v0.3 — Protocols

| Feature | Doc | How |
|---|---|---|
| **UMA 2.0 Authorization Services** | new `docs/23-uma.md` (to be written) | `geonosis-protocol-uma` crate |
| **CIBA** (Client-Initiated Backchannel Auth) | [`03`](./03-protocols-oidc.md) | Polling + notification + push modes |
| **OpenID Federation 1.0** | new `docs/24-openid-federation.md` (to be written) | Federation of federations; emerging spec |
| **Verifiable Credentials / SD-JWT VC** issuance | new `docs/25-verifiable-credentials.md` (to be written) | `geonosis-protocol-vc` + `geonosis:vc-issuer@0.1.0` SPI |
| mDL (mobile driving license) profile experimental | new doc | Best-effort interop with ISO 18013-5 wallets |
| Step-up assurance levels (NIST 800-63-3 IAL/AAL) | [`12`](./12-security-crypto.md) | Emit `acr` values matching NIST levels |

### v0.3 — Crypto

| Feature | Doc | How |
|---|---|---|
| **PKCS#11 / HSM** backend | [`12`](./12-security-crypto.md) | Generic PKCS#11 driver; tested with SoftHSM + nCipher + YubiHSM |
| Continuous authentication freshness for agents | [`18`](./18-agent-identity.md) | Attestation heartbeats with `agent-attestation` SPI |
| Per-tenant ed25519 device-keys for binding | [`12`](./12-security-crypto.md) | Wraps DPoP-bound tokens with device attestation |

### v0.3 — Agents

| Feature | Doc | How |
|---|---|---|
| **Agent-to-agent delegation chains** | [`18`](./18-agent-identity.md) | Nested `act` chains with policy-driven capability reduction per hop |
| Continuous attestation | [`18`](./18-agent-identity.md) | Heartbeat-driven freshness |
| Agent cost-tracking built-in mappers | [`18`](./18-agent-identity.md) | OpenAI / Anthropic / Vertex usage scoped to agent + parent |
| Agent rate-limit per-capability granularity | [`18`](./18-agent-identity.md) | `spend:daily` enforces hard ceilings |

### v0.3 — Federation / broker

| Feature | Doc | How |
|---|---|---|
| Cross-realm federation within one cluster | new `docs/26-cross-realm-federation.md` | Curated trust links between realms |
| Additional first-party broker plugins | [`05`](./05-identity-broker.md) | `spi-aws-iam-identity-center`, `spi-salesforce`, `spi-servicenow`, `spi-slack`, `spi-discord` |
| SAML attribute push to attribute authorities | [`20`](./20-saml-idp.md) | For federation-aware enterprises |
| WebAuthn discoverable credentials default | [`08`](./08-admin-ui.md) | Passkeys before passwords in registration |

### v0.3 — Adaptive / risk

| Feature | Doc | How |
|---|---|---|
| Risk-score authenticator with heuristic anomaly detection | [`06`](./06-auth-flows.md) | Velocity, geo, device fingerprint, time-of-day; ML-free baseline |
| Adaptive MFA flows | [`06`](./06-auth-flows.md) | Step-up triggered by risk score |
| Mobile-app-friendly authn flows | [`06`](./06-auth-flows.md) | Deeplink-aware, biometric prompts via WebAuthn platform authenticators |
| Phone-number-as-username | [`16`](./16-user-profile.md) | First-class for B2C use; SMS-OTP-driven login |

### v0.3 — Operational

| Feature | Doc | How |
|---|---|---|
| **K8s Operator with CRDs** | [`11`](./11-deployment-k8s.md) | `Realm`, `Client`, `WasmPlugin`, `IdentityProvider` CRDs |
| Multi-region active-active **design** | new doc | Conflict resolution, write fences, audit ordering |
| Migration importer from incumbent IAMs | [`14`](./14-roadmap.md) | Best-effort YAML converter |

### v0.3 — DX

| Feature | Doc | How |
|---|---|---|
| Spring Boot + Django example apps | [`21`](./21-dx-package.md) | `examples/spring-boot-app/`, `examples/django-app/` |
| Interactive WASM-in-browser playground | [`21`](./21-dx-package.md) | Ephemeral Geonosis in a browser tab |
| Test mode → migration mode | [`21`](./21-dx-package.md) | Promote a test-realm to a production-realm |
| SDK parity across Rust + Go + TS + Python | [`21`](./21-dx-package.md) | All admin operations covered |

### v0.3 — Cloud

| Feature | Doc | How |
|---|---|---|
| **Geonosis Cloud GA** | [`22`](./22-cloud-offering.md) | First region (EU); SOC 2 in progress |
| **Plugin marketplace** | [`22`](./22-cloud-offering.md) | Curated, one-click install per realm |
| Backup browser UI | [`22`](./22-cloud-offering.md) | On top of `geoctl realm export` |
| Geo-routing | [`22`](./22-cloud-offering.md) | Per-customer region selection |
| Audit-log SIEM integrations | [`22`](./22-cloud-offering.md) | Splunk, Datadog, Elastic, S3 + Object Lock |

---

## v1.0 — GA, audit, polish

After v0.3, the work shifts from "more features" to "production hardening":

- External security audit.
- FAPI 1 Advanced + FAPI 2.0 conformance.
- Long-term stable HTTP API + WIT contracts.
- Multi-region active-active **shipping** (not just design).
- Komino retiring Redis dependency (separately tracked as
  Komino phase below).

## Komino — separately tracked (v1.x)

[`09-cache-invalidation.md`](./09-cache-invalidation.md) §KominoCache.
Replaces Redis with an embedded, gossip-clustered, Rust-native
distributed cache. Independent of the feature-distribution above;
proceeds when foundational work is mature enough to absorb the
churn. Compatibility checklist:

- API-equivalent to the existing `Cache` trait.
- Helm chart toggle: `cache.backend=komino`.
- Migration runbook: Redis → Komino with overlap window.
- Benchmarks show ≤ 10% RPS regression vs. Redis at p99.

---

## Explicit non-goals (always)

These are firm "we will not build this" commitments — listing them
to prevent perpetual reopening:

- **WS-Federation** passive requestor.
- **SAML 1.x** in any role.
- **CAS** server.
- **OpenID 2.0** consumption (the old spec, not OIDC).
- **Closed-source server.** Geonosis stays under an OSI license.
- **Hostile dual-licensing** (BSL etc.) of the core server.
- **Cloud-only protocol features.** Anything that speaks OIDC /
  SAML / SCIM stays in OSS.
- **Crippled OSS** as an upgrade funnel.

---

## How we'll know each phase is done

| Phase | "Done" signal |
|---|---|
| v0.1 | Feature freeze: all v0.1 features implemented; 5-minute quickstart works end-to-end; unit + integration tests green |
| v0.1.x | Production gate: OIDC Basic + FAPI 1 Baseline conformance passing in CI; SSO cookie works (prompt=none, max_age); load test ≥ 5000 authorize req/s on 4 vCPU; cluster-wide rate limiting active; per-realm key derivation active; all metrics emit data |
| v0.2 | Account console fully usable for end-user self-service; SCIM 2.0 interop tested against Okta + Entra ID provisioning; `geonosis-verify` crate published; 4 admin SDKs published |
| v0.3 | Cloud GA in first region; UMA 2.0 + CIBA + OpenID Federation conformance tests passing; plugin marketplace publicly available; migration importer works against a representative incumbent realm export |
| v1.0 | External security audit passed; HTTP API stable contract; multi-region active-active shipped; Komino candidate replacing Redis in benchmarks |

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Scope inflation pushes v0.1 past 8 months | This roadmap is the contract; cuts come from v0.2-bound items moving to v0.3, not v0.1 items slipping |
| Leptos SSR + island hydration matures slower than expected | Most admin pages stay classical form-post; only flow editor + account console need hydration |
| WASM SPI ecosystem stays sparse | First-party plugins (Google/GitHub/Apple/Microsoft, REST-user-storage, captcha) seed the marketplace; clear authoring guide + 5-min quickstart for plugin authors |
| SAML IdP role complexity (XML-DSig surface) eats Phase 3 | Use vetted XML-DSig crate; cover with shipped interop fixtures from major SP libs |
| Schema-migration discipline slips during enterprise-feature buildout | CI lint blocks merges; quarterly audit of past migrations |
| Cloud planning crowds out OSS velocity | Strict separation: no Cloud code in OSS repo (see [`22`](./22-cloud-offering.md)) |
| ~~SSO cookie was missing from the original roadmap~~ | **RESOLVED** — SSO browser cookie, prompt enforcement, max_age, id_token_hint all implemented in v0.1.x. `authorize/sso.rs` handles session resolution and shortcircuit. `id_token_hint` JWT signature verification deferred to v0.2 |
| v0.1 "done" criteria not met at feature freeze | v0.1.x phase added to close the gap (conformance, load test, metrics) before v0.2 feature work begins |

## How this roadmap is maintained

- Every meaningful design decision lands in a doc under `docs/`.
- This roadmap **reflects** those docs; if there's a contradiction,
  the per-feature doc wins, and this roadmap gets a follow-up commit.
- A quarterly "roadmap audit" PR cross-checks every item against
  the corresponding doc and the GitHub issue tracker (when one
  exists).
