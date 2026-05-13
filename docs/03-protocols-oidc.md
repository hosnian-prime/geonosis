# 03 — Protocols: OpenID Connect & OAuth 2.1

Geonosis ships OIDC 1.0 + OAuth 2.1 with the security profile of FAPI 1
Baseline. This document enumerates the surface, the security
invariants, and where each piece lives in the codebase.

## Standards we target

| Spec | RFC / version | Scope |
|---|---|---|
| OAuth 2.0 | RFC 6749 | base authorization framework |
| OAuth 2.1 | draft-ietf-oauth-v2-1 | tightened defaults (PKCE mandatory, no implicit, etc.) |
| OIDC Core | OpenID Connect Core 1.0 | id_token, userinfo, hybrid disallowed |
| OIDC Discovery | OpenID Connect Discovery 1.0 | `/.well-known/openid-configuration`, `jwks_uri` |
| OIDC Dynamic Registration | OpenID Connect Dynamic Registration 1.0 | optional, per-realm toggle |
| OAuth 2.0 Token Revocation | RFC 7009 | `/oauth2/revoke` |
| OAuth 2.0 Token Introspection | RFC 7662 | `/oauth2/introspect` |
| OAuth 2.0 Device Authorization | RFC 8628 | `/oauth2/device/authorize` |
| OAuth 2.0 PKCE | RFC 7636 | required for public clients, recommended for confidential |
| Pushed Authorization Requests | RFC 9126 | `/oauth2/par` |
| JAR / JARM | RFC 9101 / OAuth2.0 JARM | both supported v0.1 |
| Mutual TLS Client Auth | RFC 8705 | v0.2 — per-realm sender-constraint |
| DPoP | RFC 9449 | v0.2 — per-realm sender-constraint |
| Demonstrated PoP for ATs | draft | v0.2 |
| Token Exchange | RFC 8693 | v0.1 (initial; first use is the Agent identity path) — full surface in v0.2 |
| CIBA | OpenID CIBA Core 1.0 | DEFERRED |
| FAPI 1.0 Baseline | OpenID FAPI 1 Baseline | conformance target v0.1 |
| FAPI 1.0 Advanced / FAPI 2.0 | | v0.2 |

## URL surface

All endpoints are realm-scoped under `/realms/{realm-slug}/`. The
hostname is shared across realms.

```
GET    /realms/{slug}/.well-known/openid-configuration
GET    /realms/{slug}/.well-known/oauth-authorization-server
GET    /realms/{slug}/protocol/openid-connect/jwks
GET    /realms/{slug}/protocol/openid-connect/auth          [authorize]
POST   /realms/{slug}/protocol/openid-connect/auth          [authorize, form_post]
POST   /realms/{slug}/protocol/openid-connect/token         [token]
GET    /realms/{slug}/protocol/openid-connect/userinfo
POST   /realms/{slug}/protocol/openid-connect/userinfo
POST   /realms/{slug}/protocol/openid-connect/logout        [back-channel]
GET    /realms/{slug}/protocol/openid-connect/logout        [front-channel]
POST   /realms/{slug}/protocol/openid-connect/revoke
POST   /realms/{slug}/protocol/openid-connect/introspect
POST   /realms/{slug}/protocol/openid-connect/par           [PAR]
POST   /realms/{slug}/protocol/openid-connect/device/authorize
POST   /realms/{slug}/protocol/openid-connect/device/token
GET    /realms/{slug}/protocol/openid-connect/clients-registrations/openid-connect  [DCR, optional]

# UI pages (rendered by theme engine):
GET    /realms/{slug}/login-actions/authenticate            [step UI]
GET    /realms/{slug}/login-actions/consent
GET    /realms/{slug}/login-actions/post-login

# Admin (separate auth domain):
*      /admin/v1/...                                        [see admin-ui.md]
```

The `/protocol/openid-connect/` prefix matches a path convention many
client SDKs hard-code as a fallback. We adopt it because deviating
costs interop more than it saves in vanity.

## Conformance defaults

These are global defaults a realm operator can adjust. The defaults
should pass FAPI 1 Baseline.

- `response_type=code` only. `id_token`, `token`, `code id_token`
  rejected for new clients (hybrid disallowed).
- **PKCE** required for public clients, allowed for confidential.
  `code_challenge_method=S256` only; `plain` rejected.
- Authorization codes are **single-use**, valid 60 seconds, bound to
  exact `client_id`, `redirect_uri`, `code_challenge`, `nonce`.
- Access tokens: signed JWT (RS256/ES256/EdDSA per realm), default 5
  minute lifetime, `aud` set to client + protected resources.
- Refresh tokens: opaque, server-side, rotated on every exchange.
  Reuse detection: previously-used refresh token invalidates the
  whole token family.
- `scope` defaults to `openid` minimum.
- `nonce` required when `openid` scope is requested.
- `state` strongly recommended; recorded in CSRF check.
- HTTPS required for `redirect_uri` (except `http://127.0.0.1[:port]`
  for native apps, never `localhost` host name).
- `iat`, `exp`, `nbf` (5 s skew) enforced strictly on incoming JWTs.
- `kid` MUST appear in token headers; verification picks the JWKS
  entry strictly by `kid`.

## Token contents

### `id_token` claims (v0.1 baseline)

```json
{
  "iss": "https://geonosis.example.com/realms/acme",
  "sub": "01HJ...ULID",
  "aud": "acme-web",
  "exp": 1700000300,
  "iat": 1700000000,
  "auth_time": 1700000000,
  "nonce": "...",
  "azp": "acme-web",
  "amr": ["pwd", "otp"],
  "acr": "1",
  "sid": "01HJ...session-ulid",
  "name": "Ada Lovelace",
  "preferred_username": "ada",
  "email": "ada@example.com",
  "email_verified": true
}
```

`sub` is the user ULID rendered as Crockford base32. We do **not**
expose internal database ids beyond this.

### `access_token` claims

By default, signed JWT (FAPI-compatible). For lower-trust use cases,
a realm can mark a client `access_token_type=opaque` and we issue a
random reference token (validate via `/introspect`). Mixed is fine.

Standard claims plus:

```json
{
  "scope": "openid profile email orders:read",
  "realm_access": { "roles": ["user", "viewer"] },
  "resource_access": {
    "orders-api": { "roles": ["orders:read"] }
  },
  "groups": ["/eng/backend"],
  "ext": { /* custom claims from SPI mappers */ }
}
```

Custom claims are produced by **mapper SPIs** keyed off scopes. See
[`07-spi-wasm.md`](./07-spi-wasm.md) for the contract.

## Error model

We follow RFC 6749 § 5.2 + RFC 6749 § 4.1.2.1 strictly. The set of
error codes returned to clients is fixed:

`invalid_request`, `unauthorized_client`, `access_denied`,
`unsupported_response_type`, `invalid_scope`, `server_error`,
`temporarily_unavailable`, `interaction_required`, `login_required`,
`account_selection_required`, `consent_required`, `invalid_request_uri`,
`invalid_request_object`, `request_not_supported`,
`request_uri_not_supported`, `registration_not_supported`,
`invalid_client`, `invalid_grant`, `unsupported_grant_type`.

No detail strings leak internal state. A `request_id` is always
returned for operator log correlation; clients can quote it back to
us via the support flow.

## Client authentication

For the `/token`, `/revoke`, `/introspect`, `/par` endpoints:

| Method | When |
|---|---|
| `client_secret_basic` | default for confidential clients |
| `client_secret_post` | accepted but discouraged |
| `client_secret_jwt` | HS256 JWT assertion |
| `private_key_jwt` | RS256/ES256 JWT assertion, recommended for FAPI |
| `none` | public clients (PKCE-only) |
| `tls_client_auth` | v0.2 |

Each client carries `auth_method`; mismatch returns `invalid_client`.

## State machine of `/authorize`

```
       ┌────────────────────────────────────────┐
       │  parse + validate request              │
       │  - redirect_uri exact match?           │
       │  - client enabled?                     │
       │  - response_type allowed?              │
       │  - scope subset of allowed?            │
       └────────────┬───────────────────────────┘
                    │ ok
                    ▼
       ┌────────────────────────────────────────┐
       │  resolve flow                          │
       │   - client.flow_binding.browser        │
       └────────────┬───────────────────────────┘
                    │
                    ▼
       ┌────────────────────────────────────────┐
       │  flow executor (see 06-auth-flows.md)  │
       │   yields one of:                       │
       │     - StepRender(html)                 │
       │     - Redirect(idp_url)                │
       │     - Success(subject)                 │
       │     - Failure(reason)                  │
       └────────────┬───────────────────────────┘
                    │
            Success │
                    ▼
       ┌────────────────────────────────────────┐
       │  evaluate consent (if any required)    │
       └────────────┬───────────────────────────┘
                    │
                    ▼
       ┌────────────────────────────────────────┐
       │  mint CodeGrant, persist, 302 with code│
       └────────────────────────────────────────┘
```

Each step in the flow runs as either a Rust function or a WASM
component (custom authenticator). The flow can branch and loop within
the bounds of the graph DSL.

## `/token` exchange

Path 1 — `grant_type=authorization_code`:

1. Look up code; reject if missing, expired, or used.
2. Verify `client_id`, `redirect_uri`, PKCE verifier.
3. Mint access + (optional) id + refresh tokens.
4. Mark code used.
5. Run **post-mint mappers** to enrich claims.

Path 2 — `grant_type=refresh_token`:

1. Hash the refresh token; look up.
2. Verify not expired, family not invalidated.
3. Rotate: new refresh issued, old marked `used=true`.
4. If a `used=true` token is later seen, the **entire family** is
   revoked and an audit event `token.reuse_detected` is emitted.

Path 3 — `grant_type=client_credentials`:

1. Authenticate client.
2. Mint access token bound to the **service account user** for that
   client.

Path 4 — `grant_type=password` (Direct Access Grant):

1. Authenticate client.
2. Run the client's `direct-grant` flow (typically just password,
   sometimes password + otp).
3. Mint tokens.

Path 5 — `grant_type=urn:ietf:params:oauth:grant-type:device_code`:

1. Look up device code (polling endpoint).
2. Return `authorization_pending` until the user completes the
   companion `/device/authorize` UI flow.

## Discovery document

Generated dynamically per realm. Fields reflect actual enabled
features (algorithms in active keys, grant types per realm policy).
Cached in process; invalidated when realm config or keys change.

```jsonc
{
  "issuer": "https://geonosis.example.com/realms/acme",
  "authorization_endpoint": ".../auth",
  "token_endpoint": ".../token",
  "userinfo_endpoint": ".../userinfo",
  "jwks_uri": ".../jwks",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256", "ES256", "EdDSA"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt", "none"],
  "scopes_supported": ["openid", "profile", "email", "offline_access", "..."],
  "claims_supported": ["sub", "name", "email", "email_verified", "preferred_username", "..."],
  "request_parameter_supported": true,
  "request_uri_parameter_supported": true,
  "require_pushed_authorization_requests": false
}
```

## Implementation crates

- `geonosis-protocol-oidc` — endpoint handlers, request DTOs, error
  mapping. Pure HTTP layer.
- `geonosis-protocol-oauth` — grant-type engines, token mint, PKCE,
  PAR storage.
- `geonosis-crypto` — JWS, JWE, JWKS construction.
- `geonosis-flow` — invoked from `/authorize`.

Each handler is **state-machine first**: parameter parsing returns an
enum of validated requests; only validated values cross into the core.

## Test discipline

- Every endpoint: positive + negative + property-based parameter test.
- Every error code: at least one test that produces it.
- Replay corpus: a fixture of recorded request/response pairs from the
  OIDC conformance suite kept under `tests/conformance/`.
- Fuzzing: `cargo-fuzz` targets for token parser, request parser.

## Non-goals

- **SAML SP endpoints** (issuing SAML responses) — v0.2.
- **CIBA** — deferred.
- **JARM signed response_mode=jwt** — v0.2.
- **Self-issued OP** — out of scope.

## Decisions and open items

- **Sender-constraint**: each realm chooses `dpop`, `mtls`, or `none`
  in v0.2; both implementations land together. v0.1 emits bearer
  tokens. The `acr_policy` (per realm) can require a specific
  sender-constraint at a given ACR level — see
  [`12-security-crypto.md`](./12-security-crypto.md).
- **ACR claim**: per-realm policy table determines the `acr` value
  for any given authentication outcome — see
  [`12-security-crypto.md`](./12-security-crypto.md) §ACR Policy.
- **Default scopes mapping** to claims — needs UX walkthrough during
  Phase 2. The set is stable; only the UI editor surface is open.
- **CIBA** if a customer requires it — v0.3 candidate.
