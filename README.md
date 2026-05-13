# Geonosis

A full-featured Identity & Access Management server written in Rust.

- OIDC 1.0 + OAuth 2.1 compliant authentication and authorization
- LDAP / Active Directory user federation
- External IdP brokering (OIDC + SAML)
- Embedded admin UI and login UI (Leptos SSR)
- WebAssembly-based extension SPI (WASI 0.2 + WIT)
- Visually-edited authentication flows with hot reload
- Designed for multi-pod Kubernetes deployment with zero-downtime
  upgrades; Redis-backed cache in v0.1, replaced by an embedded
  distributed cache (Komino) in a future major release

> **Status:** early architecture phase. Source code does not yet
> exist in this repository. Technical documentation under
> [`docs/`](./docs/) is the source of truth.

## Documentation

Start here: [`docs/README.md`](./docs/README.md).

The architecture is broken into 15 focused docs covering the vision,
component map, data model, protocol surface, SPI contracts, admin
UI, cluster invariants, security, deployment, and a phased roadmap.

## License

TBD.
