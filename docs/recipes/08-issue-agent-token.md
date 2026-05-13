# 08 — Issue an OAuth token for an AI agent

## What you'll have at the end

An `Agent` named `summary-bot` parented to a real user `ada`, with
scoped capabilities, that can exchange a user's access token for
a downstream token carrying both `sub=ada` AND `act.sub=summary-bot`
in the `act` chain per RFC 8693.

## Prerequisites

- A running realm `acme` with user `ada`.
- A confidential OAuth client `acme-web` with
  `grants.token_exchange = true`.
- `jq` + `openssl` + `curl`.

## Steps

1. **Mint the agent's signing keypair.**

   The agent authenticates via `PrivateKeyJwt` (preferred for AI
   agents — no shared secret to leak):

   ```sh
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out agent.key
   openssl rsa -in agent.key -pubout -out agent.pub
   ```

2. **Register the agent.**

   ```sh
   geoctl agents create \
     --realm acme \
     --alias summary-bot \
     --display-name "Weekly Summary Bot" \
     --kind assistant \
     --model-hint "claude-opus-4-7" \
     --parent-user ada \
     --allowed-scopes "tool:read-files,profile" \
     --capabilities '[
       {"urn":"tool:read-files","config":{"paths":["/home/ada/work/**"]}},
       {"urn":"data:tier","config":{"max":2}},
       {"urn":"spend:daily","config":{"max_usd":10}}
     ]' \
     --rate-limit '{"requests_per_minute":60}' \
     --auth-method private-key-jwt \
     --public-key-file agent.pub \
     --expires-in 90d
   ```

   The `parent-user` is **immutable** — to reparent, revoke and
   recreate ([`18-agent-identity.md`](../18-agent-identity.md)).

3. **Create the actor token (signed JWT assertion).**

   Either with a tiny script or via `geoctl agents make-actor-token
   --key agent.key`:

   ```json
   {
     "iss": "summary-bot",
     "sub": "summary-bot",
     "aud": "https://geonosis.example.com/realms/acme",
     "iat": 1700000000,
     "exp": 1700000300,
     "geo:agent": {
       "alias": "summary-bot",
       "model": "claude-opus-4-7",
       "version": "1.4.2"
     }
   }
   ```

   Signed with RS256 using `agent.key`.

4. **Have `ada` obtain a user access token** (recipe 01's
   helper). Call this `$SUBJECT_TOKEN`.

5. **Exchange.**

   ```sh
   curl -fsS https://geonosis.example.com/realms/acme/protocol/openid-connect/token \
     -u acme-web:$CLIENT_SECRET \
     -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
     -d subject_token=$SUBJECT_TOKEN \
     -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
     -d actor_token=$ACTOR_JWT \
     -d actor_token_type=urn:ietf:params:oauth:token-type:jwt \
     -d resource=https://api.acme.com \
     -d scope='tool:read-files profile' | jq
   ```

   Response:

   ```json
   {
     "access_token": "...",
     "token_type": "Bearer",
     "expires_in": 300,
     "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
     "scope": "tool:read-files profile"
   }
   ```

## Verifying

Decode the access token:

```sh
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d | jq '{sub, act, scope, "geo:agent"}'
```

Expected:

```json
{
  "sub": "01HUADA...",
  "act": {
    "sub": "01HASUMMARY...",
    "kind": "agent:assistant",
    "model_hint": "claude-opus-4-7"
  },
  "scope": "tool:read-files profile",
  "geo:agent": {
    "alias": "summary-bot",
    "capabilities": ["tool:read-files","data:tier","spend:daily"]
  }
}
```

Resource server: with `geonosis-verify` (v0.2) the `act` chain is
unwrapped automatically; v0.1 resource servers do it manually:

```ts
const isAgent = !!claims.act;
if (isAgent && claims["geo:agent"]?.capabilities?.includes("tool:read-files")) {
  // grant read access
}
```

## Revocation

If `ada` notices the bot misbehaving:

```sh
geoctl agents revoke --realm acme --alias summary-bot
```

Within ~30 s (agent cache TTL), all pods reject the actor token.
Existing access tokens issued through the agent are also
invalidated (refresh-token family burned, access-token JTI
revoked).

## Troubleshooting

- **`invalid_grant: agent disabled`** — agent is past `expires_at`
  or has been revoked. Check `geoctl agents get --alias
  summary-bot`.
- **`scope ... not allowed`** — agent's `allowed_scopes` doesn't
  include the requested scope. Patch the agent.
- **`subject_token: bad signature`** — the user's token expired
  during the exchange. Refresh first.
- **`actor_token: audience mismatch`** — the actor token's `aud`
  must equal the realm's issuer URL.

## See also

- [`18-agent-identity.md`](../18-agent-identity.md) — Agent
  conceptual model, capability namespace, audit category.
- [`03-protocols-oidc.md`](../03-protocols-oidc.md) — Token
  exchange grant.
