# 00 — Vision

## What Geonosis is

Geonosis is a **full-featured enterprise-grade** Identity & Access
Management server written in Rust. It provides:

- Standards-compliant **OpenID Connect 1.0** and **OAuth 2.1** authorization.
- **LDAP / Active Directory** federation as a user source.
- **Identity brokering** for external OIDC and SAML IdPs (Google, GitHub,
  Microsoft, enterprise IdPs).
- An **embedded admin UI** served from the same binary.
- A **WASM-based extension SPI** so operators can plug in custom
  authenticators, user storage, event listeners, mappers, and policies
  without rebuilding the server.
- **Customizable login UI** and **visually-edited authentication flows**
  with **hot reload** — config, themes, and plugins can change without
  restarting any pod.
- First-class **multi-pod** operation on **Kubernetes**, with
  Postgres as the system of record and Redis as the recommended
  default hot-cache + pub/sub bus. A Redis-free mode (in-process
  cache + Postgres `LISTEN`/`NOTIFY`) is supported and tested for
  small or air-gapped installs; a future major release replaces
  the Redis dependency with **Komino**, an embedded distributed
  cache (see [`09-cache-invalidation.md`](./09-cache-invalidation.md)).

## What it is not (Non-goals for v0.1)

The following are explicitly out of scope for the first release. They
may be added later; their absence is by design, not oversight.

- **SAML 2.0 service-provider role.** SAML brokering (consuming external
  SAML IdPs) is in scope. Acting as a SAML IdP for downstream SPs is
  v0.2+. XML-DSig and metadata generation deserve their own quarter.
- **UMA 2.0 fine-grained authorization.** Authorization Services is a
  large surface; v0.1 ships role/group-based authorization only.
- **WebAuthn passkey enrollment UX.** WebAuthn assertion as a step in a
  flow is in scope; passkey lifecycle (cross-device sync, recovery) is
  v0.2.
- **Account console** (self-service end-user portal). Admin console only
  in v0.1.
- **Multi-region active-active.** Single-region multi-pod is in scope;
  geo-distributed write is v0.3+.
- **Built-in BYOK / HSM.** Crypto interface accepts an external KMS via
  trait, but only software-backed keys ship in v0.1.
- **Migration importers from incumbent IAMs.** Realm-export
  converters are nice-to-have but not committed for v0.1.
- **GUI for SPI authoring.** Plugins are built with `cargo` and the
  `geonosis-spi-api` crate.

## Why Rust

- **Single binary**, no JVM, predictable memory footprint. Important for
  K8s where IAM commonly runs as a sidecar or critical-path service.
- **Strong typing of protocol state machines** matters for security
  software. Stop classes of bugs at compile time.
- **Async I/O at scale** — Tokio + axum handle the concurrency profile
  IAM needs (many short-lived authorize requests).
- **WASM host story is mature** in Rust (`wasmtime`, `wit-bindgen`). The
  same toolchain powers our SPI.
- **Leptos** lets us write admin UI in the same language as the core.
  Theming and component override become a Rust API, not a templating
  fork.

## Success criteria for v0.1

1. **Conformance:** passes the OpenID Foundation's OIDC Basic + FAPI 1
   Baseline conformance test suite (self-hosted run, not certified).
2. **Performance:** ≥ 5 000 `authorize_endpoint` requests/sec on a
   4 vCPU pod with a warmed cache, p99 < 50 ms.
3. **Hot reload:** a tenant admin can replace the login theme or a
   WASM authenticator and see the change live without restarting a
   pod or dropping a request.
4. **Operability:** a fresh K8s install with the provided Helm chart
   reaches "ready" in under 5 minutes from `helm install`.
5. **Test coverage:** every protocol endpoint has a positive test, a
   negative test (RFC error code), and a property-based test for
   parameter parsing.

## Audience

- **Application developers** integrating SSO into their apps via OIDC.
- **Platform operators** running Geonosis as part of a K8s platform.
- **SPI authors** writing custom authenticators, mappers, federation
  providers in Rust (or any language that compiles to WASM components).
- **Security engineers** auditing the server's behavior.

## Versioning & stability

- **HTTP API:** semver-stable from v1.0. v0.x is allowed to break.
- **Admin REST API:** versioned at `/admin/v1/...`.
- **WIT contracts** for SPIs are versioned per-interface
  (`geonosis:authn@0.1.0`). Backward compatibility within a major.
- **Database schema:** every schema change uses expand-contract; the
  server runs against the previous and current schema for at least
  one minor release.
