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

> **Status:** v0.1 foundation landing. The cargo workspace, core
> entity types, OIDC/OAuth grant engines (PKCE-S256, refresh-token
> family rotation), flow DSL + executor, SPI provider registry, KMS
> trait + software impl, in-memory storage, Moka-backed cache, audit
> publisher, and axum server with `/.well-known/openid-configuration`
> and JWKS endpoints all build, lint, and test. Postgres backend,
> WASM runtime, and Leptos admin UI follow in subsequent v0.1 PRs.
> Technical documentation under [`docs/`](./docs/) remains the source
> of truth.

## Building

```sh
cargo build --workspace
cargo test --workspace
cargo run --bin geonosis-server -- --help
cargo run --bin geoctl -- version
```

## Documentation

Start here: [`docs/README.md`](./docs/README.md).

The architecture is broken into focused docs covering the vision,
component map, data model, protocol surface, SPI contracts, admin
UI, cluster invariants, security, deployment, organizations, user
profile schema, agent identity, SCIM, SAML IdP role, developer
experience, the planned managed offering, feature scope, and a
phased roadmap.

## License

TBD.
