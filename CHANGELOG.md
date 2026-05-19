# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- OIDC conformance test workflow (`.github/workflows/conformance.yml`)
- Integration and cross-boundary test suite (`tests/`)
- Comprehensive API tests for realms, roles, sessions, user profiles, and users
- Test helpers for updating realm and client policies in fixtures
- Cluster-wide rate limiting backed by Redis
- JAR (JWT-Secured Authorization Request) parameter processing and JWT verification
- SSO session handling via `session_id` in `FlowContext`
- Audit logging for authorization, token, and admin actions
- Flow editor panels for node and edge configuration in admin UI
- Toast notification system for user feedback in admin UI
- Logo and favicon SVG assets for admin UI
- `CONTRIBUTING.md`, `SECURITY.md`, and dual Apache-2.0 / MIT license files
- `clippy.toml` and `rustfmt.toml` project-wide lint configuration

### Changed

- Simplified `KeyId` parsing and removed unused extension trait
- Removed unused `PublicMaterial` import from JAR handler
- Silenced Clippy 1.95 `unnecessary_sort_by` and `collapsible_match` warnings
- Moved theme bootstrap into `admin-chrome.js` to comply with CSP policy

### Removed

- Hero, PlanetCanvas, Quickstart, Roadmap, ScrollAnimations, and ThemeToggle landing-page components (replaced by admin console)

## [0.1.0] - 2026-05-14

Initial release of Geonosis -- an enterprise-grade Rust IAM server implementing
OIDC 1.0 and OAuth 2.1.

### Added

#### Protocol Surface (OIDC 1.0 + OAuth 2.1)

- Authorization endpoint with `response_type=code` and full PKCE S256 enforcement
- Token endpoint (authorization_code, refresh_token, client_credentials, device_code grants)
- UserInfo endpoint with signed JWT responses
- OpenID Connect Discovery (`/.well-known/openid-configuration`)
- JWKS endpoint (`/jwks`) for public key distribution
- Token revocation endpoint (RFC 7009)
- Token introspection endpoint (RFC 7662)
- Pushed Authorization Requests / PAR (RFC 9126)
- Device Authorization Grant (RFC 8628)
- Token Exchange (RFC 8693) baseline
- `prompt` and `max_age` enforcement on authorization requests
- Refresh token rotation with reuse detection
- OIDC Back-Channel Logout 1.0 fan-out to relying parties

#### Cryptographic Foundation

- Per-realm signing keys supporting RS256, ES256, and EdDSA algorithms
- JWE encrypt/decrypt with RSA-OAEP-256 / dir + A256GCM allowlist
- Key rotation and JWKS publication

#### Authentication Flow Engine

- Graph-DSL authentication flow engine with conditional branching
- 11 built-in authenticators (password, TOTP, WebAuthn, OTP-email, OTP-SMS, social login, LDAP bind, X.509, Kerberos/SPNEGO, security questions, accept-terms)
- Flow dry-run with synthetic context for testing
- Flow CLI tooling (`geoctl`)

#### Identity Management

- Full identity surface: users, groups, roles, organizations
- User profile and attribute management
- Organization policies with `auto_join_on_domain_match` and login-time enrollment
- Organization claim mapping (claim-to-org mapper)
- Role-based and group-based access control

#### Federation and Brokering

- LDAP/Active Directory federation with bind authentication
- OIDC identity brokering (external IdP login)
- SAML Service Provider identity brokering
- SAML IdP capabilities with POST-binding AuthnRequest XML-DSig verification
- Declarative SAML SP attribute mappers (`attribute_mappers` on `SamlSpClientConfig`)
- Front-channel iframe SLO HTML renderer for SAML SP logout

#### Storage and Caching

- PostgreSQL storage backend with Row-Level Security (RLS)
- Zero-downtime database migrations
- Redis cache backend for distributed deployments
- Local in-process cache backend

#### Extensibility (WASM SPI)

- WASM SPI plugin system powered by Wasmtime with WIT contracts
- 9 plugin interfaces (token mapper, event listener, policy provider, authenticator, etc.)
- Built-in mapper, event, and policy provider SPI registration
- Provider registry with override support

#### Admin Console

- Admin REST API v1 (orgs, agents, roles, groups, profiles, IdPs, sessions, keys, events)
- Admin UI built with Leptos SSR
- Admin authentication middleware with realm context
- Hand-rolled Leptos flow editor canvas (MVP)
- Design tokens, theme overlay system, and i18n support
- Content Security Policy (CSP) headers

#### Operator Tooling

- Operator CLI (`geoctl`) for realm, client, and flow management
- Helm chart for Kubernetes deployment
- Docker support with multi-stage builds
- Quickstart bootstrap mode (`GEONOSIS_BOOTSTRAP_QUICKSTART`)

#### Observability

- OpenTelemetry integration
- Prometheus `/metrics` endpoint
- Structured audit event system

#### CI/CD

- GitHub Actions CI workflow (cargo fmt, clippy, test)

### Fixed

- Build context and Dockerfile path for geonosis service
- Quickstart bootstrap environment variable value (`"true"`)

<!-- Comparison links will be added once v0.1.0 is tagged and released. -->
