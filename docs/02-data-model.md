# 02 — Data Model

The Geonosis domain. Entities and their persisted shape. The Rust types
listed here are **normative**: code MUST match these spellings.

## Tenancy

We adopt the **Realm = tenant** model from Keycloak.

- A **Realm** owns its users, clients, groups, roles, keys, flows,
  themes, and SPI bindings.
- Cross-realm references are forbidden. The `master` realm exists as
  an administrative bootstrap with users that can administer other
  realms.
- A `realm_id` column exists on **every** tenanted table and is part
  of every primary lookup index. Multi-tenant isolation is enforced
  by query, by RLS policy, and by repository trait boundary.

## Entity catalog

```
┌─────────┐    1   N  ┌────────┐
│  Realm  │──────────►│  User  │
└─────────┘           └────────┘
     │                    │  N         M  ┌────────┐
     │                    └──────────────►│  Role  │
     │                    │  N         M  └────────┘
     │                    └─────────────► ┌────────┐
     │                                    │ Group  │
     │   1     N  ┌─────────┐             └────────┘
     ├───────────►│ Client  │
     │            └─────────┘
     │   1     N  ┌──────────────┐
     ├───────────►│ Identity-    │
     │            │ Provider     │
     │            │ (broker)     │
     │            └──────────────┘
     │   1     N  ┌──────────────┐
     ├───────────►│ Federation   │
     │            │ Source (LDAP)│
     │            └──────────────┘
     │   1     N  ┌──────────────┐
     ├───────────►│ AuthFlow     │
     │            └──────────────┘
     │   1     N  ┌──────────────┐
     ├───────────►│ KeyMaterial  │
     │            └──────────────┘
     │   1     N  ┌──────────────┐
     ├───────────►│ Theme        │
     │            └──────────────┘
     └───────────►│ SpiBinding   │
                  └──────────────┘
```

## Core types (Rust)

```rust
pub struct Realm {
    pub id: RealmId,                    // ULID
    pub slug: String,                   // url path segment, [a-z0-9-]
    pub display_name: String,
    pub enabled: bool,
    pub registration: RegistrationPolicy,
    pub session_policy: SessionPolicy,
    pub token_policy: TokenPolicy,
    pub theme_binding: ThemeBinding,    // names of themes for login/email/admin
    pub acr_policy: AcrPolicy,          // see 12-security-crypto.md
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Per-realm rules that derive `acr` from authentication outcome (AMR / sender-constraint).
/// Used to satisfy `acr_values` requests and to drive the `step-up` flow kind.
pub struct AcrPolicy {
    pub levels: Vec<AcrLevel>,          // ordered, ascending
}

pub struct AcrLevel {
    pub value: String,                  // e.g. "0", "1", "2", "urn:mace:incommon:iap:silver"
    pub display_name: String,
    pub require: AcrRequirement,
}

/// Boolean expression over AMRs + sender-constraint.
pub enum AcrRequirement {
    Any,                                // any successful authn
    AmrContains(Vec<Amr>),              // e.g. [pwd] for level 1, [pwd, otp] for level 2
    AllOf(Vec<AcrRequirement>),
    AnyOf(Vec<AcrRequirement>),
    SenderConstrained(SenderConstraint),// dpop | mtls
}

pub struct User {
    pub id: UserId,
    pub realm_id: RealmId,
    pub username: String,               // unique per realm, case-folded
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<PersonName>,
    pub credentials: Vec<CredentialRef>,// references; secret material in credentials table
    pub federation: Option<FederationLink>, // Some(...) when user is mirrored from LDAP/IdP
    pub attributes: BTreeMap<String, AttributeValue>,
    pub required_actions: Vec<RequiredAction>, // verify-email, update-password, ...
    pub required_flow: Option<FlowAlias>,      // forces this flow on the next login (admin-set)
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct Client {
    pub id: ClientId,
    pub realm_id: RealmId,
    pub client_id: String,              // OAuth client_id, unique per realm
    pub kind: ClientKind,               // Confidential | Public | BearerOnly | ServiceAccount
    pub redirect_uris: Vec<UriPattern>,
    pub post_logout_uris: Vec<UriPattern>,
    pub allowed_origins: Vec<Origin>,
    pub grants: GrantPolicy,            // which OAuth grants permitted
    pub auth_method: ClientAuthMethod,  // client_secret_basic, private_key_jwt, none (PKCE)
    pub flow_binding: FlowBinding,      // browser / direct-grant / reset / registration flow refs
    pub default_scopes: Vec<ScopeName>,
    pub optional_scopes: Vec<ScopeName>,
    pub access_token_lifetime: Duration,
    pub refresh_token_lifetime: Duration,
    pub service_account_user_id: Option<UserId>, // if kind == ServiceAccount
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct Role {
    pub id: RoleId,
    pub realm_id: RealmId,
    pub scope: RoleScope,               // RealmRole | ClientRole(ClientId)
    pub name: String,                   // unique within scope
    pub description: Option<String>,
    pub composites: Vec<RoleId>,        // composite (parent → child) roles
}

pub struct Group {
    pub id: GroupId,
    pub realm_id: RealmId,
    pub parent_id: Option<GroupId>,
    pub name: String,
    pub path: String,                   // materialized path "/eng/backend"
    pub attributes: BTreeMap<String, AttributeValue>,
    pub assigned_roles: Vec<RoleId>,
}

pub struct AuthFlow {
    pub id: FlowId,
    pub realm_id: RealmId,
    pub alias: String,                  // "browser", "direct-grant", custom
    pub description: Option<String>,
    pub graph: FlowGraph,               // see 06-auth-flows.md
    pub version: i32,                   // monotonic; old versions kept for in-flight
    pub built_in: bool,
}

pub struct IdentityProvider {
    pub id: IdpId,
    pub realm_id: RealmId,
    pub alias: String,                  // "google", "corp-okta"
    pub kind: IdpKind,                  // Oidc | Saml
    pub config: IdpConfig,              // protocol-specific fields
    pub trust: IdpTrust,                // signing keys / metadata URL
    pub mapper_bindings: Vec<MapperBinding>, // SPI mappers run on the broker assertion
    pub first_login_flow: FlowId,
    pub post_login_flow: Option<FlowId>,
    pub enabled: bool,
}

pub struct FederationSource {
    pub id: FederationId,
    pub realm_id: RealmId,
    pub alias: String,                  // "corp-ad"
    pub kind: FederationKind,           // Ldap | Spi(WasmModuleId)
    pub config: FederationConfig,       // bind DN, base DN, attr map, page size, tls
    pub priority: i32,                  // resolution order
    pub sync_policy: SyncPolicy,        // pull schedule + full/incremental
    pub enabled: bool,
}

pub struct KeyMaterial {
    pub id: KeyId,
    pub realm_id: RealmId,
    pub usage: KeyUsage,                // Sig | Enc
    pub alg: KeyAlgorithm,              // RS256, ES256, EdDSA, ...
    pub state: KeyState,                // Active | PreviousActive | Disabled
    pub public_jwk: serde_json::Value,
    pub private_ref: PrivateKeyRef,     // Local(opaque ciphertext) | Kms(uri)
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
}

pub struct Session {
    pub id: SessionId,                  // 32-byte random, opaque
    pub realm_id: RealmId,
    pub user_id: UserId,
    pub authn_level: AuthnLevel,
    pub idp_alias: Option<String>,
    pub started_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub remote_ip: IpAddr,
    pub user_agent: String,
    pub clients: Vec<ClientSessionRef>, // child client sessions (per-app SSO)
}

pub struct CodeGrant {
    pub code: CodeId,                   // 32-byte random, opaque
    pub realm_id: RealmId,
    pub client_id: ClientId,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub scope: Vec<ScopeName>,
    pub redirect_uri: Url,
    pub code_challenge: Option<CodeChallenge>, // PKCE
    pub nonce: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,      // 60s
}

pub struct RefreshToken {
    pub id: RefreshTokenId,             // hashed in storage
    pub family_id: TokenFamilyId,       // for rotation reuse detection
    pub realm_id: RealmId,
    pub client_id: ClientId,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub scope: Vec<ScopeName>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
}

pub struct SpiBinding {
    pub id: SpiBindingId,
    pub realm_id: RealmId,
    pub interface: WitInterfaceName,    // "geonosis:authn", "geonosis:event", ...
    pub provider_alias: String,
    pub module_id: WasmModuleId,        // bytecode pointer
    pub config: serde_json::Value,      // typed by interface contract
    pub priority: i32,
    pub enabled: bool,
}

pub struct WasmModule {
    pub id: WasmModuleId,
    pub realm_id: RealmId,
    pub sha256: [u8; 32],
    pub bytecode_url: Url,              // or inline if small
    pub wit_world: String,              // declared world (e.g. "geonosis:authn@0.1.0")
    pub uploaded_by: UserId,
    pub uploaded_at: DateTime<Utc>,
}
```

## Identifier strategy

- All ids are **ULID** rendered as `Crockford base32`. Lexicographic
  sort matches time order; useful for paginating audit logs.
- Storage column type: `text` with a `CHECK` constraint and a
  `BTREE` index. Postgres `uuid` was considered and rejected to keep
  audit logs readable in raw SQL.

## Postgres schema (sketch)

This is the v0.1 baseline. Real DDL lives in
`crates/geonosis-migrate/migrations/`.

```sql
CREATE TABLE realm (
    id              TEXT PRIMARY KEY,
    slug            TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    registration    JSONB NOT NULL,
    session_policy  JSONB NOT NULL,
    token_policy    JSONB NOT NULL,
    theme_binding   JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE app_user (
    id              TEXT PRIMARY KEY,
    realm_id        TEXT NOT NULL REFERENCES realm(id),
    username_lc     TEXT NOT NULL,
    email_lc        TEXT,
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    name            JSONB,
    federation      JSONB,
    attributes      JSONB NOT NULL DEFAULT '{}'::jsonb,
    required_actions TEXT[] NOT NULL DEFAULT '{}',
    required_flow   TEXT,                  -- forces this flow alias on next login
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    -- Generated full-text search vector over username/email/name; see note below.
    search_vector   tsvector GENERATED ALWAYS AS (
        setweight(to_tsvector('simple', coalesce(username_lc, '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(email_lc, '')),    'B') ||
        setweight(to_tsvector('simple', coalesce(name->>'given',  '')), 'C') ||
        setweight(to_tsvector('simple', coalesce(name->>'family', '')), 'C')
    ) STORED,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (realm_id, username_lc)
);
CREATE INDEX ON app_user (realm_id, email_lc);
CREATE INDEX app_user_search_vector_idx ON app_user USING GIN (realm_id, search_vector);

CREATE TABLE credential (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES app_user(id),
    realm_id        TEXT NOT NULL,
    kind            TEXT NOT NULL,        -- 'password' | 'otp' | 'webauthn' | 'recovery'
    secret_data     BYTEA NOT NULL,       -- algorithm-specific encoded form
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON credential (user_id, kind);

-- ... clients, roles, groups, user_role, user_group, group_role,
-- identity_provider, federation_source, auth_flow, key_material,
-- session, code_grant, refresh_token, spi_binding, wasm_module ...

-- Append-only audit log; partitioned by month.
CREATE TABLE audit_event (
    id              TEXT PRIMARY KEY,
    realm_id        TEXT NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL,
    actor           JSONB NOT NULL,        -- {kind:'user'|'client'|'system', id, ip}
    action          TEXT NOT NULL,         -- e.g. 'login.success'
    target          JSONB,
    detail          JSONB
) PARTITION BY RANGE (occurred_at);
```

### Row-Level Security

For defense in depth, every tenanted table has an RLS policy of the
form:

```sql
ALTER TABLE app_user ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON app_user
    USING (realm_id = current_setting('geonosis.realm_id', true));
```

The server sets `SET LOCAL geonosis.realm_id = '...'` at the start of
each transaction for tenanted handlers. Administrative handlers use a
distinct DB role that bypasses RLS, audited separately.

This is **belt and suspenders** — application code still constructs
queries with `WHERE realm_id = $1` — but RLS catches forgotten
predicates.

## Validation rules (selected)

- `realm.slug` MUST match `^[a-z][a-z0-9-]{1,63}$` and is reserved
  case-insensitively across all realms; `admin`, `master`, `well-known`
  are reserved.
- `user.username` is **case-folded** with NFKC + ICU lowercase to
  produce `username_lc`. The original casing is kept in attributes.
- `client.client_id` MUST match `^[A-Za-z0-9_.-]{1,128}$`.
- `redirect_uri` patterns support exact match and one `*` wildcard
  only at path tail; no scheme wildcards; no `localhost` special case.
- `attribute` keys MUST be ≤ 64 chars; values either string ≤ 2 KiB
  or array of strings with total ≤ 8 KiB.
- All timestamps are stored UTC.

## Non-goals

- **Custom column extensions** — schema is fixed; tenants extend via
  `attributes` JSONB or SPI mappers.
- **Polymorphic actor tables** — no Inheritance, no STI; each entity
  is its own table.
- **Soft delete by default** — only audit events are append-only;
  user delete is hard delete unless `retention_policy` says otherwise.

## Decisions and open items

- **User search**: full-text via Postgres `tsvector` over
  `username_lc`, `email_lc`, and `name` parts, generated as a
  `STORED` column with weight per field. GIN index keyed by
  `(realm_id, search_vector)`. The dictionary is `simple` by default
  for language-independence; realms with majority-language users can
  override to a specific dictionary (e.g. `english`, `turkish`) via
  a per-realm config knob in v0.2.
- **Attribute search**: not part of the base full-text vector; an
  optional GIN index on `attributes` JSONB is added in v0.2 with a
  per-realm allow-list of indexed keys.
- **Audit retention**: 90 days default in Postgres, configurable per
  realm; minimum 30 days. Cold storage off-host (S3 with
  Object Lock) is v0.2.
- **Schema for SAML-as-IdP** (Geonosis issuing SAML assertions):
  deferred to v0.2.
