# 18 — Agent Identity (AI / M2M Delegation)

## What this solves

A growing class of clients is **non-human**: AI agents acting on a
user's behalf, automated assistants, headless service-to-service
processes that need scoped, auditable, revocable identities. The
incumbent OAuth model — `client_credentials` grant for a static
"service account" — is **too coarse**:

- It loses the *parent principal* (who delegated this access?).
- It can't enforce *capabilities* finer than a scope (what model? what
  tool? what data tier?).
- Audit trails get muddied (every agent call shows up as the same
  service account).
- Revocation is all-or-nothing.

Geonosis treats **Agent** as a first-class identity kind in v0.1
with a small, focused data model and protocol surface. It composes
with existing OAuth 2.1 (no protocol fork) — the differences are
the entity, the scopes, the claims, and the audit category.

This is a deliberate **early move** on a category we expect to
mature over the next 12–24 months.

## Conceptual model

```
              ┌─────────────────────────────────────┐
              │  User (or Service Account, or Org)  │  ← parent principal
              └─────────────────────────────────────┘
                          │  authorizes
                          ▼
              ┌─────────────────────────────────────┐
              │  Agent                              │
              │   - kind: assistant / scraper / ...│
              │   - model_hint, vendor, version    │
              │   - capabilities (scoped)          │
              │   - parent_subject (immutable)     │
              │   - expires_at                     │
              │   - revoked_at                     │
              └─────────────────────────────────────┘
                          │  acts as
                          ▼
              ┌─────────────────────────────────────┐
              │  Token (access / id), with `act` claim│
              │  identifying the delegating principal │
              └─────────────────────────────────────┘
```

An Agent is **not** a user. It cannot log in interactively. It is
issued via an OAuth 2.1 grant — typically **Token Exchange
(RFC 8693)** with a `subject_token` from the parent and an
`actor_token` from the agent itself, or via a constrained
`client_credentials` flow against an "agent-capable" client.

The token carries an `act` (actor) claim chain per RFC 8693, so any
downstream resource server can see both the **effective subject**
(`sub` = the user) and the **acting agent** (`act.sub` = the agent).

## Data model

```rust
pub struct Agent {
    pub id: AgentId,
    pub realm_id: RealmId,
    pub alias: String,                      // human-readable, unique per realm
    pub display_name: String,
    pub kind: AgentKind,                    // Assistant | Scraper | Webhook | Batch | Custom(String)
    pub model_hint: Option<String>,         // e.g. "claude-opus-4-7", "gpt-4o"
    pub vendor: Option<String>,
    pub version: Option<String>,
    pub parent_subject: ParentSubject,      // immutable; set at creation
    pub capabilities: Vec<AgentCapability>,  // see below
    pub allowed_scopes: Vec<ScopeName>,     // subset of parent's grantable scopes
    pub allowed_audiences: Vec<String>,     // resource servers this agent may target
    pub rate_limit: AgentRateLimit,
    pub auth_method: AgentAuthMethod,       // PrivateKeyJwt | DpopBoundKey | TokenExchangeOnly
    pub public_key: Option<PublicJwk>,      // for PrivateKeyJwt / DpopBoundKey
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub enabled: bool,
}

pub enum ParentSubject {
    User(UserId),
    ServiceAccount(ClientId),
    Organization(OrganizationId),           // org-wide delegation
}

pub enum AgentKind {
    Assistant,                              // user-facing AI assistants
    Scraper,                                // headless data collection
    Webhook,                                // event-driven callbacks
    Batch,                                  // scheduled jobs
    Custom(String),
}

pub struct AgentCapability {
    pub urn: String,                        // "tool:read-files", "data:tier-2", "model:gpt-4o"
    pub config: serde_json::Value,
}

pub struct AgentRateLimit {
    pub requests_per_minute: u32,
    pub tokens_per_day: Option<u64>,        // for cost-tracking agents
}

pub enum AgentAuthMethod {
    PrivateKeyJwt,                          // agent presents signed JWT assertion
    DpopBoundKey,                           // agent token bound via DPoP
    TokenExchangeOnly,                      // agent only obtainable via RFC 8693
}
```

## URL surface

Each endpoint's required role gate is listed inline. **realm-admin**
is the realm administrator; **parent-user** is the user who owns
the agent (when `parent_subject = User(_)`); **parent-org-admin** is
an org admin (when `parent_subject = Organization(_)`); **agent
itself** authenticates via its bound credentials but cannot mutate
its own configuration.

```
GET    /admin/v1/realms/{slug}/agents                                [realm-admin]
POST   /admin/v1/realms/{slug}/agents                                [realm-admin | parent-user | parent-org-admin]
GET    /admin/v1/realms/{slug}/agents/{alias}                        [realm-admin | parent-user | parent-org-admin]
PATCH  /admin/v1/realms/{slug}/agents/{alias}                        [realm-admin | parent-user | parent-org-admin]
DELETE /admin/v1/realms/{slug}/agents/{alias}                        [realm-admin | parent-user | parent-org-admin]
POST   /admin/v1/realms/{slug}/agents/{alias}/revoke                 [realm-admin | parent-user | parent-org-admin]
GET    /admin/v1/realms/{slug}/agents/{alias}/usage                  [realm-admin | parent-user | parent-org-admin]

# End-user self-service (v0.2 with account console)
GET    /realms/{slug}/account/agents                                 [authenticated user; scope to own]
POST   /realms/{slug}/account/agents                                 [authenticated user; sets parent=self]
DELETE /realms/{slug}/account/agents/{alias}                         [authenticated user; own agents only]

# Protocol surface
POST   /realms/{slug}/protocol/openid-connect/token                  # standard; grant_type=urn:ietf:params:oauth:grant-type:token-exchange
                                                                     # client must be enabled for `token_exchange`
```

`parent-user` authorization is enforced both at the **route** layer
(claim check) and at the **storage** layer (RLS predicate
`Agent.parent_subject = current_user`).

## Token issuance

Two recommended paths:

### Path 1 — Token Exchange (RFC 8693), recommended for assistants

The parent obtains its own token first (normal login). Then the
client requests an exchange:

```http
POST /realms/master/protocol/openid-connect/token
Authorization: Basic <client_id:client_secret>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<user_access_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&actor_token=<agent_assertion_jwt>
&actor_token_type=urn:ietf:params:oauth:token-type:jwt
&resource=https://api.acme.com
&scope=tool:read-files
```

The issued token carries:

```json
{
  "sub": "01HUSER...",
  "act": {
    "sub": "01HAGENT...",
    "kind": "agent:assistant",
    "model_hint": "claude-opus-4-7"
  },
  "aud": "https://api.acme.com",
  "scope": "tool:read-files",
  "exp": ...,
  "amr": ["mfa"],
  "geo:agent": {
    "alias": "weekly-summary-bot",
    "capabilities": ["tool:read-files", "data:tier-2"]
  }
}
```

The `act` chain is **nested** if a token is re-exchanged through
another agent — exactly the model in RFC 8693 §4.1.

### Path 2 — Client credentials with agent binding (simpler)

For service-account-parented agents that don't require a user
context, an "agent-capable" client requests `client_credentials`
with an `agent_alias` parameter:

```http
POST .../token
Authorization: Basic <client_id:client_secret>

grant_type=client_credentials
&scope=tool:read-files
&geonosis_agent=weekly-batch
```

Issued token has `sub = service-account-user`, `act.sub = agent`.

## Capabilities (the differentiator)

Scopes alone are too coarse for many agent use cases. A
**capability** is an additional named, structured permission on an
agent. The resource server (or a SPI policy provider) consumes them:

```json
{
  "capabilities": [
    { "urn": "tool:read-files", "config": { "paths": ["/home/user/work/**"] } },
    { "urn": "data:tier", "config": { "max": 2 } },
    { "urn": "model:family", "config": { "allow": ["claude-*", "gpt-4*"] } },
    { "urn": "spend:daily", "config": { "max_usd": 10 } }
  ]
}
```

Capabilities are emitted in the token under `geo:agent.capabilities`.
A `geonosis:policy@0.1.0` SPI plugin **can** evaluate them at token
mint to allow/deny / reduce; resource servers consume them via the
**JWT verify** crate (see [`21-dx-package.md`](./21-dx-package.md)).

### Reserved capability URN namespace

- `tool:*` — agent tools/actions
- `data:*` — data classification access
- `model:*` — which model the agent runs
- `spend:*` — cost / quota
- `time:*` — temporal constraints (e.g. business-hours-only)
- `custom:*` — operator-defined; recommended `custom:{realm}:...`

## Audit category

Every action by an agent is recorded with action prefix `agent.`:

- `agent.created`, `agent.updated`, `agent.revoked`
- `agent.token.issued` (with both `sub` and `act.sub`)
- `agent.token.rejected` (capability not granted, rate limit hit)
- `agent.capability.exceeded`
- `agent.rate_limit.hit`

Audit events for agent activity are **never** compacted (per
[`13-observability.md`](./13-observability.md) §Audit event
compaction): the user signal must remain clean.

## Rate limiting

Agents have **separate** rate-limit buckets from human users.
Counters are keyed `agent_rl:{realm}:{agent_id}:{window}`. Default
limits set per agent at creation.

Enforcement scope by phase:

- **v0.1, Redis-backed cache (the default deployment shape):**
  cluster-wide enforcement is available immediately, because
  Redis already counts atomically across pods. Agent rate-limit
  shipping in v0.1 specifically piggybacks on this.
- **v0.1, no-Redis (LocalCache) deployment:** per-pod enforcement
  only. Operators running without Redis accept this looser bound.
- **v0.2, general cluster-wide rate limiting** rolls out for
  ALL counters (not just agents); the agent buckets transparently
  benefit and gain richer policy controls (per-capability, per
  parent-subject).

## Revocation

An admin (or the parent user, via account console) can revoke any
agent:

```
POST /admin/v1/realms/.../agents/{alias}/revoke
```

Effect:

- `revoked_at` set; all active tokens issued through the agent are
  invalidated (refresh-token family burned; access-token JTI added
  to revocation list with a TTL = token lifetime).
- Future token exchanges that present this agent's `actor_token` are
  rejected with `invalid_grant`.

## Lifecycle and constraints

- An agent's `parent_subject` is **immutable** after creation. To
  reparent, revoke and re-create.
- An agent's `allowed_scopes` is enforced as a **subset** of the
  parent's grantable scopes at exchange time; agents cannot
  privilege-escalate.
- An agent's `expires_at` is hard — past this point, no new tokens
  are issued regardless of parent state.
- Per-realm cap: default 1000 agents per user; bumped per
  organization policy.

## SPI extensibility

Three points are pluggable:

- **`agent_attestation` WIT (`geonosis:agent-attestation@0.1.0`)** —
  evaluate the actor token's *contents* before exchange. Example:
  enforce that an `actor_token` carries a signed model name + version
  from a trusted attestation server.
- **`geonosis:policy@0.1.0`** (existing) — evaluate capabilities at
  token mint; can reduce capability scope.
- **`geonosis:event@0.1.0`** (existing) — receive `agent.*` events
  for cost tracking, observability, etc.

## Non-goals

- **Cross-realm agent identities** — an agent belongs to exactly one
  realm.
- **Agent-as-user** — agents do not have credentials, passwords, or
  WebAuthn keys. They authenticate via signed assertions.
- **Mutable parent** — see above.
- **Continuous authentication** (heartbeats, attestation freshness)
  beyond `expires_at` — out of scope v0.1; deferred to v0.3.

## Phase

- **v0.1**: Agent entity, Token Exchange path, capability URN
  format, audit category, admin API CRUD.
- **v0.2**: Account-console self-service. Attestation SPI.
- **v0.3**: Agent-to-agent delegation chains with policy-driven
  capability reduction at each hop. Continuous-auth heartbeats.

## Decisions and open items

- **Capability URN namespace**: stable, partitioned `tool:*`,
  `data:*`, `model:*`, `spend:*`, `time:*`, `custom:*`. New top-level
  prefixes require a doc change.
- **Parent-subject immutability**: hard rule. Reparenting = revoke
  + recreate.
- **Per-realm agent cap**: 1000 default per user; per-org policy
  overrides.
- **Cross-realm agents**: explicit non-goal.
- **Continuous attestation**: deferred to v0.3.

## SOLID notes

- **Single Responsibility**: `Agent` doesn't replace user/client; it
  composes alongside them. Capabilities are separate from scopes.
- **Open/Closed**: Capability URN namespace is open; agents accept
  unknown `custom:*` URNs without core changes. Custom enforcement is
  via the existing `policy` SPI.
- **Liskov**: Agent tokens are RFC 8693-compliant access tokens with
  an `act` chain — any standards-aware verifier accepts them.
- **Interface Segregation**: Optional SPIs (`agent-attestation`) are
  separate from required ones. A realm not using attestation is not
  forced to depend on it.
- **Dependency Inversion**: The core depends on the *Subject* enum,
  not on concrete `Agent`; agents enter the token path via the
  same flow execution code that handles users.
