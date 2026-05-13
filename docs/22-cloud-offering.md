# 22 — Geonosis Cloud (Managed Offering Plan)

A **planning document**, not a v0.1 deliverable. The OSS server
must come first and earn trust; the managed offering is the path
to commercial sustainability. This doc captures the strategy so
v0.1/v0.2 design decisions stay compatible with a managed product
later.

## Why this matters

Most IAM markets have an OSS-plus-Cloud shape (Auth0, WorkOS,
Clerk, Stytch, ZITADEL). Pure-OSS competitors (incumbent IAM,
SuperTokens, Authelia) struggle to fund continuous protocol
conformance, security audits, and 24/7 incident response. Without
a managed product, Geonosis stays a project, not a platform.

This is a strategy commitment, not a roadmap commitment. **No
code lands for "Cloud" in v0.1 or v0.2** — but architectural
choices in those releases are graded against "does this preclude
the managed path?".

## Operating model

| Aspect | Position |
|---|---|
| Source | Geonosis Cloud runs **the same `geonosis-server` binary** that OSS users run. No private fork. |
| Differentiation | Operational expertise, SLAs, compliance certifications, support — not feature gates. |
| Pricing | Per-monthly-active-user or per-resource (still TBD); transparent calculator before sign-up. |
| Tiers | Free (dev / small B2C), Team, Business, Enterprise. Free tier is generous enough that Geonosis can be a real solution there, not a teaser. |
| Lock-in | Zero. Export/import via `geoctl realm export | import` round-trips a full realm. Customer can leave with their data and their plugins. |

## What Cloud adds operationally

- **Multi-tenant hosting** with strict isolation. Per-tenant
  Postgres schema (cheap path) or per-tenant database (premium
  path).
- **Geo-routing**: customers select a region; Geonosis Cloud
  provides EU, US, and (later) APAC clusters.
- **Managed Redis / Komino** transparently.
- **Managed KMS** (Vault Transit or cloud-provider KMS), free
  master-key management for the customer.
- **Compliance posture**: SOC 2 Type II, ISO 27001, GDPR DPA,
  EU data-residency commitments. Hosted on infrastructure that
  is already certified.
- **24/7 oncall**, defined incident SLAs.
- **Custom domains** with managed TLS (LetsEncrypt + zero-touch
  rotation).
- **One-click backup / restore** of a realm.
- **Audit-log shipping** to customer's SIEM as a managed
  integration (Splunk, Datadog, Elastic, S3 + Object Lock).

## Architectural compatibility checklist

These are constraints v0.1/v0.2 OSS code MUST honor so the
managed path is viable later:

- [ ] All per-realm data is fully addressable by `realm_id`. **No
      cross-realm reads.** (We have this; RLS enforces it.)
- [ ] All operator-tunable behavior is in DB (not env vars or
      mounted config files) so it's per-tenant configurable.
      (We have this for everything except master key + DB URL.)
- [ ] No global locks that hold across realms. Postgres advisory
      locks for migrations are scoped to schema. (Honored.)
- [ ] Audit events are partitioned by month + per-realm queryable
      (no global indexes that scale poorly multi-tenant). (We have
      partitioned audit_event.)
- [ ] Hot reload is realm-scoped. Touching one realm doesn't
      restart pods serving other realms. (We have this.)
- [ ] Rate limiting can be per-realm bounded. (Per-pod today;
      v0.2 cluster-wide Redis-backed.)
- [ ] SPI quarantine state is per-realm. (We have this.)
- [ ] Cost-attributable metering. (Need to add — see below.)

The last bullet is a **gap**: for a Cloud business model, we need
to count actions per realm in a billing-grade way. The hooks:

- **Counters per realm per action class** (token-mints, MAUs, SPI
  fuel consumed, SCIM ops, audit events stored). These are written
  to a `realm_metering` table or shipped to a metering service.
- **Designed in v0.1** (cheap to add to the audit event pipeline);
  consumed in Cloud only.

→ Adding to v0.2 roadmap.

## Customer-facing surface

Cloud-only features (the managed dashboard, billing, region picker,
backup browser, etc.) live in a **separate** application that
calls into Geonosis admin APIs. They are NOT contributed back to
the OSS repo.

This separation matters: OSS users don't see a "Cloud" button or
"Upgrade" CTA in their admin console. The OSS admin UI is complete
on its own.

## Plugin marketplace (v0.3 candidate)

A natural Cloud-only feature: a curated marketplace of WASM SPI
plugins (`spi-google`, `spi-github`, `spi-acme-billing-mapper`, ...)
with one-click install per realm.

The marketplace itself is OSS-friendly — plugin manifests are
published openly; the curation, signing, and one-click UX are
Cloud features.

## Open-source SaaS tension management

The team will be deliberate about what stays free and what becomes
Cloud-only:

| Stay in OSS forever | Always |
|---|---|
| Every protocol feature | every grant type, every authn method, every SPI interface |
| Every admin operation | nothing is "Cloud-only API" |
| Every plugin interface | community-contributable |
| Multi-pod scale | Helm chart, K8s manifests, full HA |

| Cloud-only | Always |
|---|---|
| Managed-Postgres / managed-Redis / managed-KMS | infra |
| Compliance audit reports | paperwork |
| 24/7 support contracts | people |
| Backup browser UI | a UI on top of `geoctl realm export` |
| Geo-replicated multi-region | until v0.4+ in OSS |
| SLA-backed uptime | business model |
| Plugin marketplace UX | curation layer |

Notably: **we never feature-gate the protocol surface**. A
Cloud-only OAuth grant type, or a Cloud-only authenticator, would
fragment the project. Resist always.

## Phase

- **v0.1**: no Cloud code. Architecture decisions reviewed against
  the compatibility checklist; gaps logged.
- **v0.2**: ship per-realm metering hooks in audit pipeline.
  Begin operating a private Cloud preview for design partners.
- **v0.3**: Cloud GA, first region (EU). Plugin marketplace public.
- **v0.4+**: Multi-region routing, federated Cloud across regions.

## SOLID notes

- **Single Responsibility**: Cloud surfaces (billing, dashboard,
  marketplace) live in a separate codebase. Geonosis OSS does NOT
  ship Cloud-specific abstractions.
- **Open/Closed**: Cloud is a *consumer* of the OSS APIs and the
  SPI surface. Adding Cloud-only features requires no OSS change
  beyond the metering hooks.
- **Liskov**: a Cloud-hosted realm is indistinguishable from a
  self-hosted realm from an end user's perspective (same OIDC
  endpoints, same SAML metadata, same flow editor).
- **Interface Segregation**: an OSS user pays no cost for
  Cloud-only features. The OSS binary doesn't link Cloud code.
- **Dependency Inversion**: Cloud depends on OSS abstractions
  (admin REST API, `geoctl`, OpenAPI spec); OSS does not depend
  on Cloud.

## Non-goals (forever)

- **Closed-source server**. Never.
- **Cloud-only features in the protocol layer**. Never.
- **Hostile dual-licensing** (BSL, etc.) of the core server.
  The core stays under an OSI-approved license.
- **Crippled OSS** as an upgrade funnel. The OSS path is fully
  capable; Cloud earns its money on operations, not artificial
  scarcity.
