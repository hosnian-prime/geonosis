# 15 — Organizations

**Organizations** are a sub-realm grouping of users with shared
context, branding, identity provider hookups, and roles. They model
the B2B SaaS pattern where one realm hosts many customer tenants.
The design mirrors Keycloak's Organizations feature (introduced in
Keycloak 25, refined in 26+) and ships in v0.1.

## Why both Realm and Organization

The "Realm = tenant" decision (round 1) holds for **server-level
multi-tenancy** — distinct administrators, distinct keys, distinct
auth flows, distinct security boundary. That's the right unit when
you're running, say, two completely separate companies' IAM on one
cluster.

**Organization** is a *lower-cost* unit. Inside a single realm:

- All members share the realm's keys, flows, and auth policies.
- An Organization adds: branding, default IdP routing, per-org
  roles, invitation lifecycle, domain claim, and member directory.
- A user can belong to **0..N** organizations.

This matches the common SaaS shape: you run one Geonosis realm for
your product; each paying customer is an Organization with its own
SSO and its own admin users.

## Entity reference

See [`02-data-model.md`](./02-data-model.md) for full types.
Summary:

| Entity | Purpose |
|---|---|
| `Organization` | Identity, branding, default IdP, attributes |
| `OrgDomain` | Claimed DNS domain(s), verified |
| `OrgMembership` | User ↔ org join with role list and state |
| `OrgInvitation` | Single-use invitation token, expires |
| `OrgRole` | Roles scoped to an organization |

## URL surface

```
GET    /admin/v1/realms/{slug}/orgs
POST   /admin/v1/realms/{slug}/orgs
GET    /admin/v1/realms/{slug}/orgs/{alias}
PUT    /admin/v1/realms/{slug}/orgs/{alias}
DELETE /admin/v1/realms/{slug}/orgs/{alias}

GET    /admin/v1/realms/{slug}/orgs/{alias}/members
POST   /admin/v1/realms/{slug}/orgs/{alias}/members/{user_id}        # add existing user
DELETE /admin/v1/realms/{slug}/orgs/{alias}/members/{user_id}

POST   /admin/v1/realms/{slug}/orgs/{alias}/invitations
GET    /admin/v1/realms/{slug}/orgs/{alias}/invitations
DELETE /admin/v1/realms/{slug}/orgs/{alias}/invitations/{id}

POST   /admin/v1/realms/{slug}/orgs/{alias}/domains
DELETE /admin/v1/realms/{slug}/orgs/{alias}/domains/{id}
POST   /admin/v1/realms/{slug}/orgs/{alias}/domains/{id}/verify

GET    /admin/v1/realms/{slug}/orgs/{alias}/idps
POST   /admin/v1/realms/{slug}/orgs/{alias}/idps          # bind realm IdP to org
DELETE /admin/v1/realms/{slug}/orgs/{alias}/idps/{idp_alias}

GET    /admin/v1/realms/{slug}/orgs/{alias}/roles
POST   /admin/v1/realms/{slug}/orgs/{alias}/roles
PUT    /admin/v1/realms/{slug}/orgs/{alias}/roles/{name}
DELETE /admin/v1/realms/{slug}/orgs/{alias}/roles/{name}
```

End-user-facing (account console, v0.2):

```
GET    /realms/{slug}/account/orgs
POST   /realms/{slug}/account/orgs/invitations/{token}/accept
DELETE /realms/{slug}/account/orgs/{alias}/membership
```

## Invitations

Two flavors:

- **Direct invitation**: admin enters an email; an `OrgInvitation`
  row is created; an email goes out via the realm SMTP config; the
  invitee follows a single-use link to accept (creates user if
  not present, or logs in to link membership).
- **Self-service join via domain match**: when
  `organization_policy.auto_join_on_domain_match=true`, a user whose
  verified email matches a verified `OrgDomain` is offered (or
  forced, per policy) to join during first login.

Invitation lifecycle:

```
Created → Sent → Accepted | Expired | Revoked
```

Tokens are 32-byte random, hashed in `OrgInvitation.token`. Click
flow:

1. User clicks `/realms/{slug}/invitations/{token}` (theme-rendered).
2. If unauthenticated: run a tailored flow — either
   `registration` (creates user) or `browser` (signs in existing).
3. After authentication, the executor finalizes the `OrgMembership`,
   marks the invitation `Accepted`, and 302s to the org's
   `redirect_url` or the realm default landing page.

## Domain claim & verification

A domain is "claimed" when an org admin adds it; **verified** only
after either:

- **DNS TXT** record `geonosis-verify=<token>` on the apex or
  `_geonosis-challenge.<domain>` — checked by the
  `geoctl orgs verify-domain` runner.
- **Email-loop**: a mail to `postmaster@<domain>` containing a
  single-use link. Operator-controlled toggle; off by default.

Unverified domains cannot be used for auto-join.

A domain can be claimed by **one organization at a time**. Trying
to claim a domain owned elsewhere returns `409 conflict`.

## IdP binding per organization

A realm IdP (configured at the realm level) can be **bound** to an
organization. Effect:

- The organization's login page features that IdP as the primary
  option (or hides other IdPs, configurable).
- Users brokering through that IdP into this realm are automatically
  joined to the organization (subject to first-broker-login flow
  rules).
- The org's `default_idp_alias` short-circuits the login picker
  when the org is selected (e.g. organization-tag in `acr_values`
  or subdomain routing).

Multiple orgs can bind to the same realm IdP (e.g. one corporate
Okta hosting multiple customer orgs).

## Per-organization roles

Roles scoped to an org are separate from realm roles. They appear in
tokens under a dedicated `org_access` claim when the user is
authenticated in an organization context:

```json
{
  "sub": "01HJ...",
  "org": {
    "id": "01HJORG...",
    "alias": "acme",
    "roles": ["owner", "billing"]
  },
  "realm_access": { "roles": ["user"] }
}
```

The token includes `org` only when:

- The session was authenticated in an org context, **or**
- The client requested an org scope (`scope=org:acme:roles`).

How "org context" is decided:

- **Subdomain routing**: `acme.tenants.example.com` on the ingress
  routes to the realm with an `org=acme` hint. The browser flow
  honors it.
- **URL parameter**: `?organization=acme` on `/authorize`.
- **Selection page**: when neither subdomain nor parameter is
  present and the user has memberships, a selection step prompts.

## User-level denormalization

`User.organizations: Vec<OrganizationId>` mirrors the org-membership
table for hot-path reads (token mint touches this on every login).
Writes update both atomically inside a single transaction.

## Branding

Each organization has a `OrganizationBranding`:

- Logo URI
- Primary color
- Banner text

Applied to login templates when an org context is set. Implemented as
theme parameters; no separate template files.

## Lifecycle & non-goals

- **Suspending an org**: `enabled=false`; logins from members are
  blocked at the start node with `org_suspended`.
- **Deleting an org**: hard delete; member roles unassigned; users
  not deleted.
- **Cross-realm orgs** — out of scope. An org belongs to exactly one
  realm.
- **Org-level signing keys** — out of scope; realm keys apply.
- **Org-level auth flows** — out of scope in v0.1; orgs inherit the
  realm's flows but can bind a different first-broker-login flow.

## Permissions

- A realm admin manages all orgs in the realm.
- An **organization admin** (member with the realm-defined
  "organization-admin" role, OR an `OrgRole` flagged as admin) can:
  - invite/remove members, manage domains, bind IdPs, set
    org-level roles.
  - cannot create new clients, modify realm settings, or affect
    other orgs.
- These permissions are mediated by the same admin-API auth as
  everything else; the audit log records `admin.org.*` actions.

## Audit events

| Action | Detail |
|---|---|
| `org.created` | by, alias |
| `org.updated` | by, fields-changed |
| `org.deleted` | by, alias |
| `org.member.added` | by, user, roles |
| `org.member.removed` | by, user |
| `org.member.suspended` | by, user |
| `org.invitation.sent` | by, email |
| `org.invitation.accepted` | user, invitation_id |
| `org.invitation.expired` | invitation_id |
| `org.domain.added` | domain |
| `org.domain.verified` | domain, method |
| `org.idp.bound` | idp_alias |

## Tests

- Property: an org's invariants (single realm, unique alias) hold
  under concurrent admin operations.
- Auto-join: a user with `email=user@acme.com` registering against
  a realm with verified org `acme` ends up in `acme` exactly once.
- Token claim: `org` claim present iff org context active.
- IdP binding: claim from the bound IdP propagates `org` correctly.

## Decisions and open items

- **Org context detection**: subdomain → URL parameter → selection
  step. Implemented v0.1.
- **Per-org IdPs**: bound from existing realm IdPs; no per-org
  IdP isolation. Per-org IdP isolation is on the v0.2 wishlist.
- **Org-level flows**: v0.1 only allows overriding
  `first_broker_login_flow` per org-IdP binding. Full per-org flow
  binding is v0.2.
- **Suspension semantics**: hard block at flow Start with
  `org_suspended` error. Soft mode ("warn but allow") not planned.
