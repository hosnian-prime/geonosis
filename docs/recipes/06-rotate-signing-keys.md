# 06 — Rotate signing keys without breaking tokens in flight

## What you'll have at the end

A new RS256 signing key is Active for your realm; tokens issued
before the rotation still verify (the previous key is in JWKS
under `kid`); zero requests are dropped during the rollover.

## Prerequisites

- A running realm `master`.
- The current Active key has been Active long enough that you're
  comfortable demoting it.

## Steps

1. **Check the current state.**

   ```sh
   geoctl keys list --realm master
   ```

   Should show one or more entries; one of them has
   `state: Active` for `usage: Sig, alg: RS256`.

2. **Generate the new key + promote.**

   ```sh
   geoctl keys rotate --realm master --usage sig --alg RS256
   ```

   This single transaction:
   - Creates a fresh keypair (server-generated, wrapped under the
     master key).
   - Inserts as a new `KeyMaterial` row with `state: Active`.
   - Demotes the previously Active key of the same algorithm to
     `state: PreviousActive`.
   - Emits `pg_notify('geonosis_invalidate', ...)`.
   - Audit event `key.rotated` recorded.

   Within ~100 ms, every pod reloads its in-process JWKS cache.

3. **Verify both keys are in JWKS.**

   ```sh
   curl -fsS http://localhost:8080/realms/master/protocol/openid-connect/jwks | jq '.keys | length'
   ```

   Should be at least 2 (the new Active + the PreviousActive).
   New tokens are now signed with the new key; previously-issued
   tokens still verify against the PreviousActive entry.

4. **Wait for the grace window.**

   The grace window is `max(access_token_lifespan,
   refresh_token_lifespan)` plus a safety margin. For default
   token policies, this is ≤ 24 h.

   No operator action required during this window; the server
   serves both keys via JWKS automatically.

5. **Retire the old key.**

   After the grace window:

   ```sh
   geoctl keys disable --realm master --kid $OLD_KID
   ```

   Sets `state: Disabled`. The key drops out of JWKS; any token
   still claiming this `kid` fails verification (which is the
   correct outcome — those tokens are by now expired anyway).

## Verifying

```sh
# A token issued BEFORE rotation:
echo "$OLD_TOKEN" | cut -d. -f1 | base64 -d | jq .kid
# kid = old kid

# Still verifies against JWKS:
curl -fsS -H "Authorization: Bearer $OLD_TOKEN" \
  http://localhost:8080/realms/master/protocol/openid-connect/userinfo

# Returns 200 with userinfo.

# A token issued AFTER rotation:
echo "$NEW_TOKEN" | cut -d. -f1 | base64 -d | jq .kid
# kid = new kid

# Also verifies.
curl -fsS -H "Authorization: Bearer $NEW_TOKEN" \
  http://localhost:8080/realms/master/protocol/openid-connect/userinfo
```

## Emergency rotation (suspected compromise)

If you believe the old key was compromised, **don't wait the
grace window**. Instead:

```sh
# 1. Rotate (Step 2 above).
geoctl keys rotate --realm master --usage sig --alg RS256

# 2. Disable the old key IMMEDIATELY.
geoctl keys disable --realm master --kid $OLD_KID --force

# 3. Revoke all sessions in the realm.
geoctl sessions revoke-all --realm master --reason "key compromise"
```

Every user re-authenticates on their next request. Audit:
`key.disabled` + `session.revoked` events.

## Troubleshooting

- **`jwks` cache still shows only the old key** — your client is
  caching JWKS too aggressively. Configure the client to refresh
  JWKS on `kid not found` (the recommended SDK behavior).
- **Tokens issued post-rotation fail verification at resource
  server** — resource server hasn't refreshed JWKS. With
  `geonosis-verify` (v0.2), this is automatic via the JWKS cache's
  `unknown_kid` refresh policy.
- **Refresh tokens stop working** — refresh tokens are opaque
  (not signed with realm keys), so key rotation doesn't affect
  them. If they fail, the cause is elsewhere — check
  `token.reuse_detected` audit events.

## See also

- [`12-security-crypto.md`](../12-security-crypto.md) — Key
  lifecycle, KMS interface.
- [`03-protocols-oidc.md`](../03-protocols-oidc.md) — JWKS
  endpoint shape.
