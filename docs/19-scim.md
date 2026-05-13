# 19 — SCIM 2.0 Provisioning

**SCIM 2.0** (System for Cross-domain Identity Management, RFC 7642 /
7643 / 7644) is the standard protocol for user and group lifecycle
between identity authorities and SaaS applications. It is **table
stakes** for enterprise B2B sales. Geonosis ships SCIM in **v0.2**
with both inbound and outbound roles.

## Two directions

| Direction | Role | Use case |
|---|---|---|
| **Inbound** (server) | Geonosis is the SCIM service provider | An external IdP (Okta, Entra ID, OneLogin, Google Workspace) provisions users + groups into a Geonosis realm or organization |
| **Outbound** (client) | Geonosis is the SCIM client | Geonosis pushes user/group changes from a realm or organization out to an application that exposes a SCIM endpoint |

Both directions ship together. The data flows in opposite directions
but the schema and types are shared.

## Conceptual scope

- **Resources**: `User`, `Group`, `EnterpriseUser` extension,
  `Organization` (per [`15-organizations.md`](./15-organizations.md))
  via custom extension.
- **Operations**: CRUD + filtered list + bulk + PATCH (RFC 7644 §3.5).
- **ETag**-style versioning per resource.
- **Bulk** capped at 1000 operations / request, op-level transactions
  (one fails, others succeed).
- **Filtering** subset: `eq`, `ne`, `co`, `sw`, `ew`, `pr`, `gt`,
  `ge`, `lt`, `le`, `and`, `or`, `not`. Sub-attribute paths
  (`emails.value eq "..."`).
- **Pagination**: `startIndex` + `count`, capped at 200/page.

## URL surface (inbound)

Each realm exposes a SCIM endpoint. For B2B SaaS scenarios, each
organization can expose its own SCIM endpoint scoped to its members.

```
GET    /realms/{slug}/scim/v2/ServiceProviderConfig
GET    /realms/{slug}/scim/v2/ResourceTypes
GET    /realms/{slug}/scim/v2/Schemas

GET    /realms/{slug}/scim/v2/Users
POST   /realms/{slug}/scim/v2/Users
GET    /realms/{slug}/scim/v2/Users/{id}
PUT    /realms/{slug}/scim/v2/Users/{id}
PATCH  /realms/{slug}/scim/v2/Users/{id}
DELETE /realms/{slug}/scim/v2/Users/{id}

GET    /realms/{slug}/scim/v2/Groups
POST   /realms/{slug}/scim/v2/Groups
GET    /realms/{slug}/scim/v2/Groups/{id}
PUT    /realms/{slug}/scim/v2/Groups/{id}
PATCH  /realms/{slug}/scim/v2/Groups/{id}
DELETE /realms/{slug}/scim/v2/Groups/{id}

POST   /realms/{slug}/scim/v2/Bulk
POST   /realms/{slug}/scim/v2/.search
GET    /realms/{slug}/scim/v2/Me                    # current authenticated subject

# Per-organization variant
GET    /realms/{slug}/orgs/{alias}/scim/v2/Users
... etc
```

## Authentication for inbound SCIM

A realm can host **one or more SCIM clients** — each is an OAuth
client of kind `ScimClient` with a confidential secret or a bound
public key. The provisioning client authenticates with bearer
token or `private_key_jwt`. Each SCIM call is rate-limited per
client.

Per-org SCIM clients are scoped: their writes can only affect
members of the bound organization.

## Schema mapping

The User Profile schema ([`16-user-profile.md`](./16-user-profile.md))
**drives** the SCIM `Schemas` endpoint. Custom attributes declared
in the profile appear as SCIM extension attributes under
`urn:ietf:params:scim:schemas:extension:geonosis:2.0:User`.

The default mapping:

| SCIM | Geonosis |
|---|---|
| `userName` | `username` |
| `name.givenName` | `name.given` |
| `name.familyName` | `name.family` |
| `emails[primary=true].value` | `email` |
| `active` | `enabled` |
| `groups[].value` | `Group.id` references |
| `externalId` | `attributes.external_id` (set by client) |
| `EnterpriseUser.department` | `attributes.department` (if declared) |

Operators can override per-attribute mapping via the realm's User
Profile (annotations like `ui.widget` extend to `scim.path`).

## Outbound SCIM (client)

A realm can declare **SCIM targets** — external SCIM endpoints that
should receive provisioning events. Each target has:

```rust
pub struct ScimTarget {
    pub id: ScimTargetId,
    pub realm_id: RealmId,
    pub organization_id: Option<OrganizationId>, // when set, scopes the source data
    pub alias: String,
    pub endpoint: Url,
    pub auth: ScimTargetAuth,                   // Bearer / OAuth2 / PrivateKeyJwt
    pub schema_overrides: Vec<ScimMapping>,
    pub events: ScimEventFilter,                // which Geonosis events trigger a push
    pub sync_mode: ScimSyncMode,                // RealTime | Scheduled
    pub retry_policy: ScimRetryPolicy,
    pub enabled: bool,
}

pub enum ScimSyncMode {
    RealTime,                                    // push on every relevant audit event
    Scheduled { cron: String },                  // periodic full or delta sync
}
```

Outbound flow:

1. A Geonosis audit event (`user.created`, `user.updated`,
   `org.member.added`, ...) fires.
2. The SCIM client subsystem listens via the `geonosis:event` SPI
   (yes — outbound SCIM is itself a built-in event-listener
   provider, URN `builtin:event:scim-outbound`).
3. For each enabled `ScimTarget`, the change is translated to a
   SCIM PATCH/POST/DELETE and sent.
4. Retries with exponential backoff; failures logged and surfaced in
   the admin UI's "SCIM health" widget.
5. After 5 consecutive failures, the target enters
   `state=CircuitOpen`; sync resumes when manually re-enabled.

## Edge cases

- **PATCH semantics** (RFC 7644 §3.5.2): `add` / `remove` / `replace`.
  Path syntax `emails[type eq "work"].value`. We implement the full
  PATCH grammar; PUT is supported but discouraged for partial updates.
- **`id` immutability**: enforced.
- **`externalId` uniqueness**: per realm, per source. Two clients
  can use the same `externalId` value (it's scoped to the requesting
  client's account record).
- **`groups` membership writes via User PUT/PATCH**: accepted but
  the inverse `Group.members` write is the canonical path; we
  reconcile.
- **Deletion**: a SCIM DELETE on a user runs the same erasure flow
  as `/account/me/delete` from [`13-observability.md`](./13-observability.md)
  §GDPR — audit events are anonymized, not deleted.

## Operational surface

The admin UI exposes:

- **SCIM Clients** page (inbound): create, rotate secret, view
  recent operations + error rate.
- **SCIM Targets** page (outbound): create, test connection,
  trigger full sync, view per-target health.
- **Schema mapping editor**: per-attribute SCIM path overrides.
- **Audit events** specific to SCIM: `scim.user.created`,
  `scim.user.failed`, `scim.target.circuit_open`, etc.

## SPI extensibility

- **`geonosis:scim-mapper@0.1.0`** (v0.2 WIT): custom transform of a
  resource before push (e.g. masking sensitive attributes per target).
  Same interface for inbound (transform on receive).
- **`geonosis:scim-target-auth@0.1.0`** (v0.2 WIT): supply
  authentication for non-standard SCIM endpoints (e.g. AWS SigV4
  for some private SCIM-like APIs).

Built-in providers:

- `builtin:event:scim-outbound` — the outbound SCIM driver, an event
  listener.
- `builtin:scim:inbound` — the inbound SCIM handler, mounted as the
  axum router for `/scim/v2/*` paths.

## Phase

- **v0.2**: full inbound + outbound. ServiceProviderConfig,
  Schemas, ResourceTypes; User + Group + EnterpriseUser. Bulk,
  PATCH, filtering, pagination. Mapping editor in admin UI.
- **v0.3**: SCIM-target-driven app inventory (a realm exposes
  "where this user is provisioned out to" in their profile);
  cross-tenant SCIM federation patterns.

## Non-goals

- **SCIM 1.1** — not implemented.
- **Provisioning to non-SCIM endpoints** — handled by a generic
  outbound webhook (built-in) + the operator's translation logic, or
  a custom WASM event listener.
- **Re-provisioning on schema-only changes** — schema edits do not
  trigger re-sync; only data changes do. Operators can manually
  trigger full sync per target.

## SOLID notes

- **Single Responsibility**: SCIM lives in `geonosis-protocol-scim`
  (inbound HTTP surface) and a built-in event listener
  (`scim-outbound`). The shared schema/type code lives in
  `geonosis-scim-types`. Three concerns, three crates.
- **Open/Closed**: New target types extend via
  `scim-target-auth` SPI; new resource types extend via
  `Schemas` endpoint declarations + User Profile annotations. Core
  doesn't change.
- **Liskov**: Outbound is just one event listener among many
  (`builtin:event:scim-outbound`); fits the chain dispatcher
  semantics (`13-observability.md`) without special-casing.
- **Interface Segregation**: SCIM clients (inbound) and SCIM
  targets (outbound) are separate entities with separate admin
  surfaces. No single "SCIM config" blob that mixes the two.
- **Dependency Inversion**: The outbound driver depends on the
  `Cache` trait, the `EventListener` trait, and the
  `Http` host capability — not on Redis or any HTTP client
  directly.
