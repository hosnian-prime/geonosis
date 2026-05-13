# 20 — SAML 2.0 IdP Role (Issuing Assertions)

Geonosis acts as a **SAML 2.0 Identity Provider** for downstream
service providers (SPs). This complements the SP role spec'd in
[`05-identity-broker.md`](./05-identity-broker.md): there, we
**consume** SAML from external IdPs. Here, we **issue** SAML to
external SPs. Pushed to **v0.1** scope on operator demand —
enterprise SaaS uptake still routinely requires SAML SSO with
Geonosis as the assertion issuer.

## What this ships

- IdP-initiated and SP-initiated SSO (both flows).
- HTTP-Redirect and HTTP-POST bindings.
- Signed assertions (mandatory) and optional encrypted assertions.
- SLO (Single Logout) — front-channel and back-channel.
- Metadata download endpoint.
- NameID formats: `transient`, `persistent`, `emailAddress`,
  `unspecified`, `x509SubjectName`.
- Attribute statements via the `mapper` SPI.
- Signed authentication requests (validated, optional per SP).
- AuthnContextClassRef interplay with our `AcrPolicy`.

## URL surface

```
GET    /realms/{slug}/protocol/saml/descriptor                     [public]  # SP-facing IdP metadata XML
POST   /realms/{slug}/protocol/saml/sso                            [public]  # SP-initiated AuthnRequest (HTTP-POST)
GET    /realms/{slug}/protocol/saml/sso                            [public]  # SP-initiated (HTTP-Redirect)
POST   /realms/{slug}/protocol/saml/slo                            [public]  # SLO (HTTP-POST)
GET    /realms/{slug}/protocol/saml/slo                            [public]  # SLO (HTTP-Redirect)
POST   /realms/{slug}/protocol/saml/artifact                       [public]  # Artifact resolution (v0.2)

# IdP-initiated entry point: requires an authenticated session in the realm
GET    /realms/{slug}/clients-saml/{client_alias}/unsolicited       [authenticated user]

# Admin surface for managing SAML SP clients
GET    /admin/v1/realms/{slug}/saml/clients                        [realm-admin]
POST   /admin/v1/realms/{slug}/saml/clients                        [realm-admin]
GET    /admin/v1/realms/{slug}/saml/clients/{alias}                [realm-admin]
PUT    /admin/v1/realms/{slug}/saml/clients/{alias}                [realm-admin]
DELETE /admin/v1/realms/{slug}/saml/clients/{alias}                [realm-admin]
```

The public-binding endpoints are reachable without prior
authentication — that's how a SAML AuthnRequest from any registered
SP gets routed. Identity verification happens *after* the SP is
identified (by `Issuer`) and any signature requirement is enforced.

## SP as a Client

A downstream SP is registered as a `Client` of kind
`SamlServiceProvider`:

```rust
pub struct SamlSpClientConfig {
    pub entity_id: String,
    pub acs_urls: Vec<Url>,                       // AssertionConsumerService URLs
    pub slo_url: Option<Url>,
    pub binding: SamlBinding,                     // HttpPost | HttpRedirect
    pub name_id_format: NameIdFormat,
    pub want_authnrequest_signed: bool,
    pub want_assertions_encrypted: bool,
    pub signing_key: KeyId,                       // realm key used to sign assertion
    pub encryption_certificate: Option<X509Certificate>, // SP's cert for encrypting
    pub authn_request_signing_certificates: Vec<X509Certificate>, // SP's certs to verify inbound signed requests
    pub attribute_mappers: Vec<MapperBinding>,    // produce <Attribute> statements
    pub default_audience: Option<String>,         // if missing, derived from entity_id
    pub session_index_strategy: SessionIndexStrategy,
}

pub enum SessionIndexStrategy {
    UseSessionId,                                 // index = Geonosis session id
    Random,                                       // fresh per assertion
}
```

`Client.kind = SamlServiceProvider`, with all existing client
features (flow_binding for SP-initiated AuthnRequest's flow,
consent policy, default scopes mapped to SAML attribute statements,
session policies). Reusing `Client` keeps the admin surface
uniform — the operator sees both OIDC clients and SAML SPs in one
list.

## Assertion construction

1. SP-initiated: SP posts an `<AuthnRequest>` to
   `/protocol/saml/sso`. We validate the signature (if required)
   and the SP's entity-id.
2. IdP-initiated: an admin or a user link triggers
   `/clients-saml/{alias}/unsolicited`. Same downstream behavior.
3. The realm's `browser` flow runs. On success, the executor
   produces a `Subject`.
4. The assertion builder:
   - Sets `Issuer` = realm issuer URL.
   - Sets `NameID` per the SP's `name_id_format` and the
     realm's policy. (For `persistent`, we generate per-SP
     opaque per-user identifiers stored in `saml_persistent_id`
     table; same user, different SP, different NameID.)
   - Runs all `attribute_mappers` (built-in + WASM) to produce
     `<AttributeStatement>`.
   - Sets `AuthnContextClassRef` from the realm `acr_policy`
     evaluation.
   - Signs the assertion with `signing_key`.
   - Optionally encrypts with the SP's encryption cert (a
     `<EncryptedAssertion>`).
5. Returns a self-posting form to the SP's ACS URL (HTTP-POST
   binding) or 302 (HTTP-Redirect).

## NameID strategies

| Format | Geonosis behavior |
|---|---|
| `transient` | Fresh random per-session NameID; not persisted |
| `persistent` | Per-(user, SP) opaque ULID stored in `saml_persistent_id`; same user → same SP → same NameID across sessions |
| `emailAddress` | `User.email` (rejected if email not verified) |
| `unspecified` | `User.username` |
| `x509SubjectName` | Reserved for mTLS-bound users; declined in v0.1 if not configured |

## SLO

When an SP-initiated logout arrives at `/protocol/saml/slo`:

1. We validate the LogoutRequest signature.
2. We close the local browser SSO session.
3. We iterate every SP the user was logged into during this
   session (tracked per `Session.clients`) and dispatch a
   LogoutRequest to each. Front-channel via iframe; back-channel
   via direct POST when `backchannel_logout_url` is configured.
4. We respond with a LogoutResponse to the originating SP.

This mirrors the OIDC back-channel logout story (one logout
propagates outward across all session participants).

## Metadata

`/protocol/saml/descriptor` returns the realm's IdP metadata XML:
issuer, signing certs (all currently-valid `KeyMaterial`s of the
realm), SSO bindings, SLO bindings, supported `NameIDFormat`s.

The metadata is cached in the `Cache` layer per realm; invalidates
on key rotation or SAML config change.

## Attribute mapping (the SPI)

The same `geonosis:mapper@0.1.0` interface used for OIDC token
claims also produces SAML `<Attribute>` statements. A
`MapperBinding` declares which SAML attribute name + format the
output is rendered as:

```yaml
mapper_urn: builtin:mapper:groups
config:
  saml:
    attribute_name: "http://schemas.xmlsoap.org/claims/Group"
    attribute_format: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
    name_format: "uri"
```

Custom WASM mappers work the same way; they return a generic
claim set, and the SAML builder serializes it into XML. This is
**Liskov-correct**: a single mapper produces output usable by both
OIDC and SAML downstream protocols.

## Signing key rotation

SAML SPs typically have **cached metadata**. Key rotation that
breaks metadata is operator pain. Our discipline:

- Multiple keys can be in `state=Active` (we permit it for SAML
  because SPs need to verify against any of N).
- The metadata declares all currently-Active keys' certs.
- Rotation: insert new key as `Active`, demote old to
  `PreviousActive` only after a grace window AND only after
  metadata has been re-cached by SPs (operator-driven; we surface
  "last verified rollover" in the admin UI).
- SPs with auto-refresh metadata (most modern ones) cope; older
  SPs need a documented metadata-update process.

## Authn request validation

Inbound `<AuthnRequest>` validation enforces:

- `Issuer` matches the registered SP's `entity_id`.
- Signature (if `want_authnrequest_signed`) verifies against one
  of the SP's configured signing certs.
- `Destination` matches our `/protocol/saml/sso` URL exactly.
- `ProtocolBinding` is one we accept.
- Replay window: `IssueInstant` within ±5 min.
- `ID` is unique within the replay window (Postgres-backed dedupe
  with TTL).
- `AssertionConsumerServiceURL` is in the SP's whitelisted
  `acs_urls`.

Any failure → audit event `saml.authnrequest.rejected` + a
SAML-compliant error response.

## Non-goals

- **SAML 1.1 / SAML 1.0** — out of scope.
- **WS-Federation** — out of scope.
- **SAML attribute push to third parties** — that's SCIM; see
  [`19-scim.md`](./19-scim.md).
- **OAuth-style consent screens for SAML** — SAML's audience binding
  is the consent surface; we don't add a parallel UI step.

## Phase

- **v0.1**: full IdP role as scoped above. Conformance: SAML 2.0 SP
  Initiated + IdP Initiated SSO + SLO interop testing against
  major SP libraries (saml2-js, python-saml, ruby-saml, .NET
  Microsoft.IdentityModel).
- **v0.2**: Artifact binding. ECP profile. Holder-of-Key subject
  confirmation.

## Decisions and open items

- **Multiple Active signing keys** are permitted in SAML realms
  (unlike OIDC, where there's exactly one Active per algorithm).
  Reason: SP metadata caching tolerates several certs better than
  it tolerates abrupt rotation.
- **NameID `persistent`** stores a per-(user, SP) ULID; never
  recoverable to plaintext user id.
- **AuthnRequest replay window**: ±5 minutes; dedupe stored in
  Postgres with TTL.
- **Artifact binding**: v0.2.
- **Holder-of-Key subject confirmation**: v0.2.

## SOLID notes

- **Single Responsibility**: SAML IdP code lives in
  `geonosis-protocol-saml-idp` (issuance), parallel to the
  SP-role code in `geonosis-broker` (consumption). Two crates,
  two roles, shared schema types in `geonosis-saml-types`.
- **Open/Closed**: New attribute mappings go through the existing
  `geonosis:mapper@0.1.0` SPI. The IdP doesn't need extension
  points beyond what other protocols already have.
- **Liskov**: SAML SPs are just `Client` rows of kind
  `SamlServiceProvider` — no parallel "SamlClient" entity, no
  parallel admin surface. The SP's flow binding is the same flow
  binding the OIDC clients use.
- **Interface Segregation**: The SAML IdP code does NOT depend on
  OIDC-token-mint code; it depends on the `MapperRegistry` and the
  `FlowExecutor` traits. An OIDC-only realm pays no SAML cost.
- **Dependency Inversion**: Signing happens via the
  `KeyManagementService` trait — software keys, Vault Transit (v0.2),
  AWS KMS (v0.2), GCP KMS (v0.2), PKCS#11 (v0.3) all work without
  any SAML code change.
