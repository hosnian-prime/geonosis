# Geonosis — Technical Documentation

Geonosis is an Identity & Access Management (IAM) platform written in Rust.
It targets the feature surface of established enterprise IAMs with an
embedded admin UI, WASM-based extension SPIs, customizable UI/flows, and
zero-downtime operation on Kubernetes.

This directory is the single source of truth for the architecture. Source
code references its decisions; designs that are not written down here do not
exist.

## Reading order

| # | Doc | Purpose |
|---|-----|---------|
| 00 | [vision.md](./00-vision.md) | What we build, what we don't, success metrics |
| 01 | [architecture.md](./01-architecture.md) | Component map, request flow, runtime model |
| 02 | [data-model.md](./02-data-model.md) | Domain entities + Postgres schema |
| 03 | [protocols-oidc.md](./03-protocols-oidc.md) | OIDC / OAuth 2.1 endpoint surface |
| 04 | [federation-ldap.md](./04-federation-ldap.md) | LDAP / AD as a user federation source |
| 05 | [identity-broker.md](./05-identity-broker.md) | Social + external OIDC/SAML IdP brokering |
| 06 | [auth-flows.md](./06-auth-flows.md) | Auth flow graph DSL + executor |
| 07 | [spi-wasm.md](./07-spi-wasm.md) | WASM-based SPI model (WASI 0.2 + WIT) |
| 08 | [admin-ui.md](./08-admin-ui.md) | Leptos SSR admin UI + theming model |
| 09 | [cache-invalidation.md](./09-cache-invalidation.md) | In-process cache + Postgres LISTEN/NOTIFY |
| 10 | [zero-downtime-migrations.md](./10-zero-downtime-migrations.md) | Expand-contract schema changes |
| 11 | [deployment-k8s.md](./11-deployment-k8s.md) | Multi-pod K8s deployment topology |
| 12 | [security-crypto.md](./12-security-crypto.md) | Keys, JWT signing, secret handling |
| 13 | [observability.md](./13-observability.md) | Logs, metrics, traces, audit |
| 14 | [roadmap.md](./14-roadmap.md) | Phased delivery plan |
| 15 | [organizations.md](./15-organizations.md) | Sub-realm Organizations (B2B SaaS tenants) |
| 16 | [user-profile.md](./16-user-profile.md) | Declarative attribute schema |
| 17 | [feature-parity.md](./17-feature-parity.md) | Feature scope audit vs. established IAMs |
| ∞ | [glossary.md](./glossary.md) | Terms used across docs |

## Status

These documents capture the **initial architecture** agreed on at project
inception. Sections marked **OPEN** require further decision before
implementation can proceed. Sections marked **DEFERRED** are out of scope
for v0.1 but anticipated.

## Conventions

- **MUST / SHOULD / MAY** follow RFC 2119.
- Trait and type names use their final Rust spelling so docs and code agree.
- Diagrams use ASCII when possible; PlantUML/Mermaid only when warranted.
- Every doc has a `## Non-goals` section. If something isn't in scope,
  it goes there explicitly.
