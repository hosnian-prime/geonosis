# 02 — Add a custom claim to client tokens

## What you'll have at the end

Every access token + id token issued for the `master-web` client
carries a `department` claim, sourced from the user's
`department` attribute.

## Prerequisites

- A running realm `master`.
- A user with a `department` attribute already on file (use
  recipe 01's `ada` or set one: `geoctl users patch --realm master
  --user ada --attribute department=engineering`).

## Steps

1. **Declare the attribute in the User Profile.**

   Required so the attribute is admin/UI-editable and writable
   via the API. Add to `master`'s user-profile schema:

   ```sh
   geoctl user-profile patch --realm master --add-attribute '{
     "name": "department",
     "display_name": "Department",
     "permissions": {"view":["admin","user"], "edit":["admin"]},
     "validators": [
       {"kind":"options","values":["engineering","sales","support","finance"]}
     ]
   }'
   ```

   See [`16-user-profile.md`](../16-user-profile.md) for the full
   schema syntax.

2. **Bind the built-in `claim-from-attribute` mapper to the client.**

   ```sh
   geoctl clients mapper-add \
     --realm master \
     --client master-web \
     --mapper-urn builtin:mapper:claim-from-attribute \
     --config '{
       "attribute": "department",
       "token_claim_name": "department",
       "id_token": true,
       "access_token": true,
       "userinfo": true
     }'
   ```

   The dispatch semantic for `mapper` is **Chain** — this mapper
   runs alongside the existing default mappers
   ([`07-spi-wasm.md`](../07-spi-wasm.md) §Dispatch semantics).

3. **(Optional) Restrict by scope.**

   To only emit the claim when the client requests
   `scope=profile:work`, set `requires_scope: "profile:work"` in
   the mapper config. The scope must be in
   `Client.optional_scopes`.

## Verifying

Issue a fresh token (recipe 01's helper, or your real client) and
decode it:

```sh
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d | jq .department
```

Expected: `"engineering"`.

```sh
curl -fsS -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:8080/realms/master/protocol/openid-connect/userinfo | jq .department
```

Returns the same value.

## Troubleshooting

- **Claim missing in token** — check `geoctl users get --realm
  acme --user ada` shows the attribute. Then check the mapper
  binding: `geoctl clients mapper-list --realm master --client
  master-web`. If the binding has `enabled: false`, enable it.
- **`invalid_attribute` on profile update** — the User Profile
  rejects unmanaged attributes by default (see
  [`16-user-profile.md`](../16-user-profile.md) §Unmanaged
  attribute policy). Declare the attribute first (step 1).
- **Claim is `null`** — the user doesn't have the attribute set.
  Either patch the user, or set `default_value` in the mapper
  config.

## More: a custom mapper in WASM

For non-trivial transformations (e.g. derive `tenant_tier` from a
join across the user's organization memberships), write a WASM
mapper against `geonosis:mapper@0.1.0`. See recipe
[04 — Custom authenticator in Rust](./04-custom-authenticator-rust.md)
for the build pipeline; replace the `Authenticator` trait with
`Mapper` from `geonosis-spi-api`.

## See also

- [`docs/07-spi-wasm.md`](../07-spi-wasm.md) — Mapper SPI.
- [`docs/16-user-profile.md`](../16-user-profile.md) — Attribute
  declaration.
- [`docs/03-protocols-oidc.md`](../03-protocols-oidc.md) — Token
  claims.
