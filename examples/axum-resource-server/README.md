# axum-resource-server

Minimal axum resource server that validates Geonosis-issued access
tokens against the realm's JWKS. Companion example to `docs/recipes/01-quickstart-docker.md`.

## What it demonstrates

- Bearer token extraction from `Authorization` header.
- JWKS fetch from `<issuer>/protocol/openid-connect/jwks`.
- In-process JWKS cache (10-minute TTL).
- `jsonwebtoken` validation: `iss`, `aud`, `exp`, signature.
- Returning the verified subject claims as JSON.

## Running

```sh
# In a separate terminal, run the quickstart compose stack first.
# See deploy/compose/quickstart.yml.

GEONOSIS_ISSUER=http://localhost:8080/realms/acme \
GEONOSIS_AUDIENCE=acme-web \
    cargo run --manifest-path examples/axum-resource-server/Cargo.toml
```

The server listens on `http://0.0.0.0:7000`.

## Trying it

Obtain an access token (any OIDC flow against the quickstart realm
produces one; see `docs/recipes/01-quickstart-docker.md` for the
auth-code path). Then:

```sh
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:7000/me | jq
```

Expected response:

```json
{
  "sub": "01J...",
  "email": "ada@acme.test",
  "preferred_username": "ada"
}
```

Invalid / expired tokens return `401 Unauthorized` with a short
diagnostic in the body.

## Production checklist (things the example deliberately skips)

- **Scope-based authorization.** Add `scope` claim checks per route.
- **Key-rotation freshness.** Today the cache TTL is 10 minutes;
  production should also evict on `kid` miss and refetch.
- **Structured logging.** Add OTLP / Loki sinks.
- **Rate limit.** This example is a single demonstration endpoint;
  real APIs need per-token rate limiting.
- **Algorithm allowlist.** The example uses whatever algorithm the
  JWT header declares; production should constrain to the realm's
  documented signing alg (typically RS256 or ES256).
