# 12 — Add social login (Google / GitHub)

## What you'll have at the end

Your realm's login page shows "Sign in with Google" and "Sign in
with GitHub" buttons. Users clicking them are brokered through the
external IdP and linked (or created) as local Geonosis users.

## Prerequisites

- A running realm `master` with `frontend_url` set (recipe 07).
- OAuth credentials from each provider:
  - **Google**: Cloud Console → APIs → Credentials → OAuth 2.0
    Client ID. Set authorized redirect URI to
    `https://geonosis.example.com/realms/master/broker/google/endpoint`.
  - **GitHub**: Settings → Developer settings → OAuth Apps.
    Set callback URL to
    `https://geonosis.example.com/realms/master/broker/github/endpoint`.

## Steps

### Google (OIDC-compliant)

1. **Register the IdP.**

   ```sh
   geoctl idps create \
     --realm master \
     --alias google \
     --display-name "Google" \
     --kind oidc \
     --config '{
       "issuer": "https://accounts.google.com",
       "discovery_url": "https://accounts.google.com/.well-known/openid-configuration",
       "client_id": "YOUR_GOOGLE_CLIENT_ID",
       "client_auth": "ClientSecretBasic",
       "scopes": ["openid", "profile", "email"],
       "pkce": "Required"
     }' \
     --first-login-flow first-broker-login \
     --sync-mode import
   ```

2. **Store the client secret.**

   ```sh
   geoctl secrets put --realm master --name GOOGLE_CLIENT_SECRET --value "$SECRET"
   geoctl idps patch --realm master --alias google \
     --config-secret-ref GOOGLE_CLIENT_SECRET
   ```

3. **(Enterprise) Restrict to your domain.**

   Add `"hd": "acme.com"` to the config — Google's hosted-domain
   hint restricts the account picker to `@acme.com` users.
   The `spi-google` plugin validates `hd` server-side (never trust
   client-side hints alone).

### GitHub (non-OIDC — needs adapter plugin)

GitHub's OAuth2 is **not** OIDC-compliant (no discovery, no
`id_token`, custom `/user` + `/user/emails` endpoints). The
first-party `spi-github` plugin wraps it.

1. **Register the IdP.**

   ```sh
   geoctl idps create \
     --realm master \
     --alias github \
     --display-name "GitHub" \
     --kind oidc \
     --adapter-urn "wasm:spi-github:broker-adapter" \
     --config '{
       "client_id": "YOUR_GITHUB_CLIENT_ID",
       "scopes": ["read:user", "user:email"],
       "pkce": "IfSupported"
     }' \
     --first-login-flow first-broker-login \
     --sync-mode import
   ```

2. **Store the client secret.**

   ```sh
   geoctl secrets put --realm master --name GITHUB_CLIENT_SECRET --value "$SECRET"
   geoctl idps patch --realm master --alias github \
     --config-secret-ref GITHUB_CLIENT_SECRET
   ```

   **GitHub email gotcha:** users can have multiple emails, some
   unverified. The `spi-github` plugin selects the **primary
   verified** email. If no verified email exists, the
   first-broker-login flow prompts the user to enter one.

## First-login flow behavior

The default `first-broker-login` flow runs **Review profile** —
the user confirms their username and email before an account is
created. This is safer than auto-create because:

- Prevents impersonation when an external email matches an
  existing local user (user must prove ownership via password).
- Lets the operator audit account creation.

For enterprise (trusted) IdPs, switch to `Trust-IdP`:

```sh
geoctl idps patch --realm master --alias google \
  --first-login-flow first-broker-login-trust
```

## Verifying

```sh
# Open in browser:
open "https://geonosis.example.com/realms/master/protocol/openid-connect/auth?\
client_id=master-web&response_type=code&redirect_uri=http://127.0.0.1:8888/callback&scope=openid"
```

The login page should show the two social buttons. After clicking
Google and completing login, the resulting `id_token` carries the
Google user's mapped claims under the Geonosis `sub`.

```sh
geoctl users get --realm master --user ada.google | jq '.federation'
```

Shows `null` (no federation link — broker links are separate from
federation links).

## Troubleshooting

- **`state mismatch`** — the browser's CSRF cookie expired (10 min
  TTL). Usually caused by slow user interaction. Increase
  `SessionPolicy.login_timeout` if needed.
- **`email_already_exists`** — an existing local user has the same
  email. The first-broker-login flow should branch to "link to
  existing" and prompt for the local password.
- **Apple private-relay emails** — the `spi-apple` plugin flags
  `email_relay=true` in user attributes. Don't use relay addresses
  as primary identifiers.
- **GitHub org membership check** — not built in. Use a WASM
  `geonosis:policy@0.1.0` plugin to call GitHub's
  `/orgs/{org}/members/{user}` API at token mint.

## See also

- [`05-identity-broker.md`](../05-identity-broker.md) — Broker
  architecture, first-login policies, security notes.
- [`07-spi-wasm.md`](../07-spi-wasm.md) — Broker adapter SPI.
