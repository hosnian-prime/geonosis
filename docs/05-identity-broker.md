# 05 — Identity Broker

The **broker** lets Geonosis delegate login to an external Identity
Provider (IdP) and accept its assertion as proof of identity. Users
clicking "Sign in with Google" or a corporate "Sign in with Okta" use
this path.

This is distinct from **federation** (which uses an external store
for credentials and user records on every login). Brokering happens
at the protocol layer: we redirect the user to a third party, they
authenticate there, we accept the resulting assertion, then we
optionally create or link a local user record.

## Two layers: generic core + adapter plugins

Geonosis splits the broker surface in two:

1. **Generic adapters** live in the core binary. They speak the
   standards verbatim:
   - **OIDC adapter** — RFC-compliant `code` flow with discovery,
     JWKS, userinfo, JWS validation, PKCE.
   - **SAML adapter** — SP role: AuthnRequest, ACS, signature/
     encryption, NameID handling.
2. **Vendor-specific behaviors** live in **first-party SPI
   plugins** implementing `geonosis:broker-adapter@0.1.0`
   (see [`07-spi-wasm.md`](./07-spi-wasm.md)). The plugin can hook
   at well-defined points: URL building, callback parsing,
   assertion validation, claim enrichment.

Reason: every "Sign in with X" has subtle quirks (Apple's
form_post + JWT + private email relay; GitHub's non-OIDC
OAuth2 + custom `/user` endpoint; corporate Okta's group-claim
formats). Putting them in a plugin keeps the core protocol
adapter clean and lets us ship vendor packages out-of-cycle from
the server release.

### Supported IdP protocols (v0.1 core)

| Protocol | v0.1 | Notes |
|---|---|---|
| OpenID Connect | ✅ generic | Discovery URL or static metadata |
| OAuth 2.0 (non-OIDC, e.g. GitHub) | ✅ via `broker-adapter` plugin | Plugin supplies userinfo mapping + auth flow quirks |
| SAML 2.0 (Geonosis as SP) | ✅ generic | We consume SAML responses; we do not yet issue them |

### First-party adapter plugins (v0.1)

Shipped from the `geonosis/spi-plugins` repository as separately-versioned
WASM components:

| Plugin | Wraps | Notes |
|---|---|---|
| `spi-google` | OIDC | Hosted domain hint, account chooser, group claim |
| `spi-github` | OAuth 2.0 | Custom `/user` + `/user/emails` userinfo composition |
| `spi-apple` | OIDC + form_post | Private-relay email handling, first-name-only-on-first-login |
| `spi-microsoft` | OIDC | tenant id segmenting, multi-tenant `common` quirks |

These are first-party in the sense that we maintain them and they're
included in the default Helm values; they are still plugins. Operators
can update them independently of the server.

Out of scope for v0.1: WS-Federation, CAS, OpenID 2.

## Configuration

```rust
struct IdentityProvider {
    id: IdpId,
    realm_id: RealmId,
    alias: String,                     // "google" — appears in /broker/{alias}/...
    display_name: String,
    kind: IdpKind,                     // Oidc | OAuth2 | Saml
    config: IdpConfig,
    trust: IdpTrust,                   // discovery URL / static signing keys
    first_login_flow: FlowId,          // what to do when this is the user's first SSO via this IdP
    post_login_flow: Option<FlowId>,
    mapper_bindings: Vec<MapperBinding>,
    sync_mode: SyncMode,               // Import | ForceFetch
    link_only: bool,                   // if true, never auto-create users
    enabled: bool,
}
```

For OIDC:

```rust
struct OidcIdpConfig {
    issuer: String,
    discovery_url: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    jwks_uri: Option<String>,
    client_id: String,
    client_auth: ClientAuthMethod,      // basic | jwt | none
    client_secret: Option<Secret<String>>,
    client_assertion_key: Option<KeyId>,
    scopes: Vec<String>,                // default ["openid", "profile", "email"]
    prompt: Option<String>,
    response_mode: Option<String>,
    pkce: PkceMode,                     // Required | IfSupported | Off
    accept_unsigned_userinfo: bool,
}
```

For SAML:

```rust
struct SamlIdpConfig {
    entity_id: String,
    sso_url: String,
    slo_url: Option<String>,
    signing_certs: Vec<X509Certificate>,
    name_id_format: NameIdFormat,
    want_assertions_signed: bool,
    want_responses_signed: bool,
    sp_signing_key: KeyId,              // our key, for AuthnRequest signing
    sp_encryption_key: Option<KeyId>,
    binding_outbound: SamlBinding,      // HTTP-Redirect | HTTP-POST
    binding_inbound: SamlBinding,
}
```

## URL surface

```
GET    /realms/{slug}/broker/{alias}/login            # initiates broker login (from flow)
GET    /realms/{slug}/broker/{alias}/endpoint         # OIDC redirect URI / SAML ACS
POST   /realms/{slug}/broker/{alias}/endpoint
GET    /realms/{slug}/broker/{alias}/metadata         # SAML SP metadata
```

The IdP-side configuration uses these URLs as the **redirect URI**
(OIDC) or **ACS / SLO** (SAML).

## Broker as a flow step

The broker is an authenticator step, not a parallel entry point. A
realm's `browser` flow typically contains:

```
[start]
  → [render-page: login-form-with-broker-buttons]
  → switch (user-action):
      case "submit-password":  → password-step → otp-step → success
      case "select-broker":    → broker-step(alias)
                                  → [first-login subflow on success]
                                  → success
```

`broker-step(alias)`:

1. Generates a `state` and a `nonce`, stores under `BrokerAuthnState`
   row (TTL 10 min).
2. Builds the redirect URL to the IdP.
3. 302s the browser.
4. The IdP-side login completes; browser hits
   `/broker/{alias}/endpoint?code=...&state=...`.
5. Validates `state`, exchanges code for tokens (OIDC), validates
   id-token / userinfo / SAML response, extracts a `BrokerAssertion`.
6. Looks up an existing **broker link** for `(idp_alias, external_id)`.
7. If linked: resume the flow with `Subject::existing(user)`.
8. If unlinked and `link_only=false`: run `first_login_flow`
   (typically "review profile and confirm").
9. If unlinked and `link_only=true`: fail with
   `account_selection_required`.

The flow executor receives `Subject::external(broker_assertion)` and
decides whether to create, link, or reject.

## Brokered assertion shape

```rust
struct BrokerAssertion {
    idp_alias: String,
    external_id: String,              // OIDC `sub` or SAML NameID
    issuer: String,
    raw: Vec<u8>,                     // original assertion bytes
    claims: BTreeMap<String, AttributeValue>,
    tokens: Option<OAuth2TokenSet>,   // access/refresh from IdP, if useful downstream
    received_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}
```

## Mappers

A `MapperBinding` runs over the assertion and contributes to:

- the **draft user** during first login (sets username, email,
  attributes),
- the **claims** issued by Geonosis to the relying client downstream.

Built-in mappers:

- `claim-to-attribute` — copy `claims[x]` to user attribute.
- `claim-to-role` — assign a role when a claim matches a predicate.
- `username-template` — synthesize username from claims (e.g.
  `${preferred_username}@google`).
- `email-verified-passthrough` — accept `email_verified` from IdP.

Custom mappers are WASM modules implementing
`geonosis:mapper@0.1.0`. See [`07-spi-wasm.md`](./07-spi-wasm.md).

## First login policies

`first_login_flow` is a regular flow that runs the **first time** an
external user shows up. Common shapes:

- **Trust-IdP**: auto-create local user with mapped attributes.
- **Review profile**: present a form; user confirms email / username.
- **Link to existing**: if email matches a local user, prompt for
  local password to confirm and link.
- **Forbid**: never create; reject (`link_only=true` shortcut).

Operator picks via UI; defaults to "Review profile" because
silently creating accounts is a footgun.

## Logout

Two flavors:

- **Front-channel logout** (`/protocol/openid-connect/logout`): if
  the session was brokered, render an iframe to the IdP's
  `end_session_endpoint` so the IdP session is also killed.
- **Back-channel logout**: subscribe to `logout_token` events from
  the IdP (if it supports back-channel logout), and revoke local
  sessions when the IdP signals so.

## Security notes

- `state` is bound to the **browser session** (cookie) AND stored
  server-side. Both must match.
- `nonce` is required for OIDC IdPs; checked against the id_token.
- For SAML, `InResponseTo` is required and matched against the
  recorded `AuthnRequest` id; `NotBefore` / `NotOnOrAfter` and
  `Audience` validated strictly.
- We never trust an assertion to grant *admin* privileges; the broker
  can sign you in as a user but cannot directly assign roles unless a
  mapper explicitly does so. Operators should treat broker mappers
  as code review-worthy.
- Open-redirect prevention: every redirect leaving Geonosis (to an
  IdP or back to a client) is whitelist-validated.

## Failure modes

| Situation | Behavior |
|---|---|
| IdP discovery URL unreachable | broker-step fails `temporarily_unavailable` |
| `state` mismatch | flow restarts at login page; audit event |
| `nonce` mismatch | reject with `invalid_grant`; audit |
| Mapper produces username conflicting with existing local user | flow branches to "link to existing" if configured, else fails |
| IdP returns clock-skewed assertion (> 5 min) | reject; clearer error in UI |

## Non-goals

- **Issuing SAML responses to downstream SPs** — that is Geonosis-as-IdP,
  v0.2.
- **WS-Federation passive requestor** — out of scope.
- **OAuth 2.0 token exchange between Geonosis and IdP** — partial in
  v0.2.
- **Multi-step IdP chains** (IdP A redirects to IdP B) beyond the
  IdP's own behavior — we just consume what we're handed.

## Decisions and open items

- **Sign in with Apple** — handled by the `spi-apple` first-party
  plugin (`geonosis:broker-adapter`); private-relay email is treated
  as the `sub`'s primary email but flagged
  `email_relay=true` in user attributes so consumers know.
- **Sign in with GitHub** — `spi-github` plugin composes a userinfo
  view from `/user` + `/user/emails`, surfacing the primary verified
  email.
- **Login hint propagation** — when an OIDC IdP advertises support
  for `login_hint`, the core adapter forwards
  `login_hint` from the inbound `/authorize`. Per-IdP behavior is
  configurable in the adapter binding.
- **Downstream `acr_values` propagation** — when a brokered login
  delivers an IdP `acr`, the realm's `acr_policy`
  (see [`12-security-crypto.md`](./12-security-crypto.md)) maps it
  to the local ACR value; absent a mapping, downstream `acr` is the
  AMR-derived level for the local session.
