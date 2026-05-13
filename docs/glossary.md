# Glossary

Terms used across Geonosis docs. When a term has a precise meaning in
this project that differs from its general usage, the project meaning
governs.

## A

**ACR (`acr`)** — Authentication Context Class Reference. A string in
the id-token that summarizes how strong the authentication was.

**Agent** — A non-human identity acting on behalf of a parent
subject (user, service account, or organization). First-class entity
in v0.1. Authenticated via Token Exchange (RFC 8693); carries an
immutable parent reference, capability URN list, and rate-limit
bucket. See [`18-agent-identity.md`](./18-agent-identity.md).

**Agent capability** — A structured permission on an `Agent` finer
than an OAuth scope: `tool:read-files`, `data:tier`, `model:family`,
`spend:daily`, etc. Emitted in tokens under `geo:agent.capabilities`.

**Action (audit)** — A categorical name for an audit event, e.g.
`login.success`, `token.refreshed`. Taxonomy in
[`13-observability.md`](./13-observability.md).

**Action (flow node)** — A flow node that performs a side effect
without user interaction (e.g. "mark user requires email
verification").

**Active key** — A `KeyMaterial` row currently used to sign new tokens.

**ACR Policy** — Per-realm table of named `acr` levels and the
authentication requirements (AMR set, sender-constraint) that satisfy
each. Drives `acr_values` interpretation and step-up routing. See
[`12-security-crypto.md`](./12-security-crypto.md) §ACR Policy.

**Admin Console** — The embedded web UI used by realm/master admins.

**AMR (`amr`)** — Authentication Methods References. Token claim
listing which authentication methods completed (e.g. `["pwd","otp"]`).

**Argon2id** — Password hashing function used for local user
credentials.

**Audit event** — Append-only record of a security-relevant action,
stored in `audit_event` and optionally shipped to external sinks.

**Authenticator** — A flow step that asks for / verifies one credential
or factor.

## B

**Broker** — The subsystem that delegates login to an external IdP.
Distinct from federation.

**Broker adapter** — A WASM SPI plugin implementing
`geonosis:broker-adapter@0.1.0` that supplies vendor-specific
behavior atop the core's generic OIDC/SAML adapters. First-party
adapters: `spi-google`, `spi-github`, `spi-apple`,
`spi-microsoft`.

**Browser flow** — The interactive login flow used by `/authorize`
when `prompt!=none`.

## C

**Claim** — A name/value pair in a JWT.

**Client** — An OAuth/OIDC application registered in a realm.

**Client authentication method** — How a client proves its identity at
`/token`: `client_secret_basic`, `private_key_jwt`, etc.

**Code grant** — A short-lived authorization code redeemable at the
token endpoint.

**Compaction (audit)** — Reducing repetitive audit events into a
summary, planned for v0.2.

**Confidential client** — A client able to keep a secret (server-side
applications).

**Conformance** — Compliance with a standardized test suite. Our
v0.1 target is OIDC Basic + FAPI 1 Baseline.

**Contract step** — The destructive half of an expand-contract
migration.

**CSRF token** — Per-request token preventing cross-site request
forgery on POST handlers.

## D

**DCR** — Dynamic Client Registration. Optional protocol for
self-registering clients.

**Direct grant** — OAuth's resource-owner-password-credentials grant.
Allowed but discouraged.

**Discovery document** — JSON at
`/.well-known/openid-configuration` that lists endpoints and
capabilities.

**DPoP** — Demonstrating Proof of Possession; sender-constraint
mechanism for access tokens. v0.2.

## E

**EdDSA** — JWS algorithm using Edwards-curve signatures (Ed25519).

**Expand step** — The additive half of an expand-contract migration.

**External KMS** — A non-local key management service (Vault, AWS
KMS, etc.).

## F

**FAPI** — Financial-grade API profile of OAuth/OIDC.

**Federation** — Using an external user store (LDAP/AD) as a source
of users.

**Federation source** — A configured external source (e.g.
`corp-ad`).

**First-broker-login flow** — The flow that runs the first time a
user logs in via a particular brokered IdP.

**Flow** — A `FlowGraph` configured on a realm; defines how
authentication proceeds.

**Flow graph** — The directed acyclic graph of nodes representing a
flow.

**Flow state** — Per-attempt mutable state for a flow execution
(Postgres-persisted).

**Fuel (WASM)** — Wasmtime's per-execution budget. We cap each call
to a known fuel limit.

## G

**`geoctl`** — Operator CLI.

**Group** — A hierarchical collection of users that can carry roles
and attributes.

## H

**HOTP / TOTP** — Hash-based / Time-based one-time password.

**Hot reload** — Updating server state (config, themes, plugins)
without restarting a pod.

## I

**IdP** — Identity Provider. May refer to Geonosis itself, or to an
external service consumed via the broker.

**Island (Leptos)** — A hydrated component within an SSR page.

## J

**JAR** — JWT-Secured Authorization Request. Encodes the
`/authorize` parameters in a signed JWT.

**JARM** — JWT-Secured Authorization Response Mode.

**JOSE** — JavaScript Object Signing and Encryption. Family of
specs: JWS, JWE, JWK, JWKS.

**JWKS** — JSON Web Key Set, our published public-key set per realm.

**JWS** — JSON Web Signature.

**JWE** — JSON Web Encryption.

## K

**KeyMaterial** — Domain type representing one cryptographic key
(private + public) and its state.

**KMS** — Key Management Service. See [`12-security-crypto.md`](./12-security-crypto.md).

**Komino** — Geonosis's planned embedded, Infinispan-class
distributed cache. Gossip-clustered between Geonosis pods,
replacing the Redis dependency in a future v1.x release. The
`Cache` trait is the seam.

## L

**LDAP** — Lightweight Directory Access Protocol. Used as a
federation source (we are an LDAP client, not server).

**LISTEN/NOTIFY** — Postgres' built-in pub/sub. Geonosis uses one
channel `geonosis_invalidate` for cache invalidation across pods.

**Login flow** — Common synonym for **browser flow**.

## M

**Mapper** — A WASM or built-in transformer that produces or alters
claims/attributes.

**Master encryption key** — Server-level secret used to wrap all
per-realm keys at rest.

**Master realm** — Bootstrap realm whose admins can manage other
realms. Always present.

**Mirroring (federation)** — Creating a local shadow record for an
external user.

## N

**NameID (SAML)** — The subject identifier in a SAML assertion.

**NOTIFY (Postgres)** — see LISTEN/NOTIFY.

## O

**OIDC** — OpenID Connect.

**Organization** — A sub-realm grouping of users with shared
branding, default IdP routing, per-org roles, invitations, and
domain claims. Realms host many organizations; users may belong to
0..N organizations. See [`15-organizations.md`](./15-organizations.md).

**Org domain** — A DNS domain claimed and verified by an
Organization. Optionally drives auto-join when a user signs in with
an email under that domain.

**Org membership** — A user's join into an Organization, with org-
scoped roles and a state (Active / Invited / Suspended).

**OAuth 2.1** — Tightened version of OAuth 2.0; baseline for new
deployments.

**Opaque token** — A token whose value is a random reference, not a
JWT.

**Overlay (theme)** — Filesystem layer that overrides built-in
templates or assets.

## P

**PAR** — Pushed Authorization Requests (RFC 9126).

**PKCE** — Proof Key for Code Exchange. Mandatory for public clients.

**Public client** — A client unable to keep a secret (SPA, mobile);
authenticates via PKCE only.

## Q

**Quarantine (SPI)** — Marking a misbehaving plugin as
non-invocable after repeated failures.

## R

**Realm** — A tenant in Geonosis: own users, clients, keys, flows,
themes.

**Refresh token** — A long-lived token redeemable for a fresh access
token at `/token`.

**Required action** — A flag on a user that forces an additive flow
detour the next time they log in (e.g. "verify email"). Multiple
required actions can be active simultaneously.

**Required flow** — A column on `app_user` naming a flow that
**replaces** the client's normal browser flow on the next login.
Cleared by the flow itself on success. Coexists with required
actions.

**RLS** — Row-Level Security in Postgres. Used as defense-in-depth
against realm-cross-talk bugs.

**Role** — A label that grants permissions; can be realm-scoped or
client-scoped.

**Rotation (key)** — Replacing the Active signing key with a new one.

## S

**SAML** — Security Assertion Markup Language. v0.1 supports BOTH
consuming SAML IdPs (broker SP role) AND issuing SAML assertions
(IdP role; see [`20-saml-idp.md`](./20-saml-idp.md)).

**SCIM** — System for Cross-domain Identity Management (RFC 7642–7644).
Standard protocol for user/group provisioning. v0.2 ships inbound
(Geonosis as SCIM service provider) + outbound (Geonosis as SCIM
client). See [`19-scim.md`](./19-scim.md).

**Service account** — A pseudo-user attached to a confidential
client; appears as `sub` for client-credentials tokens.

**Session** — A long-lived browser-side SSO state on Geonosis. Distinct
from token lifetime.

**Slot (UI)** — A named placeholder in a Leptos component that themes
can replace.

**SPI** — Service Provider Interface. Our extension mechanism, backed
by WASM components. Built-in implementations and operator-supplied
WASM implementations live in the same per-realm registry under
**provider URNs**; the operator can disable any built-in, replace
it via `replaces`, or chain extras around it. See the registry
section of [`07-spi-wasm.md`](./07-spi-wasm.md).

**Provider URN** — Stable identifier for any provider, built-in or
WASM. `builtin:{interface-short}:{name}` for built-ins;
`wasm:{module-alias}:{export}` for WASM modules. The `builtin:`
namespace is reserved.

**Step-up flow** — A flow kind triggered by an `/authorize` request
asking for a stronger `acr` than the current session holds. The
executor selects the realm's `step-up` flow whose binding targets
the requested ACR level.

**Subject (flow result)** — The authenticated principal a flow
produces on success.

**Surface (UI)** — A `Surface` trait implementation that resolves
slots to concrete components; selectable per realm/theme.

## T

**Theme** — A directory of templates, assets, optional component
overrides, and metadata.

**TLS** — Transport Layer Security; required everywhere.

**Token family** — Linked set of refresh tokens sharing a
`family_id`. Used to detect rotation reuse.

**Token Exchange** — RFC 8693 OAuth 2.0 token exchange grant.
Implements the `act` (actor) chain that lets a token represent
"this user, acting via this agent (or other delegate)". Central to
the agent identity model.

**`act` claim** — Per RFC 8693 §4.1, a JWT claim identifying the
acting party in a token-exchange chain. Geonosis emits `act` for
agent-issued tokens; can be nested when an agent re-delegates.

**Tombstone (AD)** — An LDAP entry in the deleted-objects container
representing a logically-deleted user. Geonosis treats tombstones
as disable signals, not delete signals — see
[`04-federation-ldap.md`](./04-federation-ldap.md) §AD-specific.

**`tsvector`** — Postgres full-text search type. `app_user`
has a generated `search_vector` column built from username, email,
and name fields, indexed with GIN.

## U

**User** — A person (or a brokered/federated identity) within a
realm.

**User Profile** — A per-realm declarative schema describing which
user attributes exist, who can read/write them, and how they are
validated. Drives registration, account-console, and admin forms.
See [`16-user-profile.md`](./16-user-profile.md).

## V

**Vault Transit** — HashiCorp Vault's cryptographic-operations
engine. The first external `KeyManagementService` backend shipped,
in v0.2.


**Version (flow)** — Monotonic counter that bumps on every flow save.
In-flight executions complete on their original version.

## W

**WASI 0.2** — WebAssembly System Interface, component-model edition.
Geonosis SPI uses WASI 0.2 imports.

**Wasmtime** — Bytecode Alliance WASM runtime. Our host engine.

**WebAuthn** — W3C authenticator API for passkeys and security keys.

**WIT** — WebAssembly Interface Type. The IDL we use to declare SPI
contracts.

**Worker (backfill)** — Long-running background job that updates rows
in batches during a schema migration's expand phase.

## Z

**Zero-downtime** — Upgrade discipline guaranteeing no pod-down and
no service interruption.
