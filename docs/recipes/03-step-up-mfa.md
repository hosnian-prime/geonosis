# 03 — Configure step-up MFA

## What you'll have at the end

Users access most of your app with a password; when they hit a
sensitive endpoint, your app passes `acr_values=2` to
`/authorize` and Geonosis runs a **step-up flow** that prompts
for TOTP / WebAuthn before issuing a new token with `acr=2`.

## Prerequisites

- Realm `acme` with users that have either TOTP enrolled
  (`geoctl users credential-add --kind otp ...`) or WebAuthn.
- Client `acme-web` configured for the standard `browser` flow.

## Steps

1. **Confirm or set the ACR policy.**

   The default acme realm ships with `acr_policy` levels 0/1/2/3
   (see [`12-security-crypto.md`](../12-security-crypto.md) §ACR
   Policy). Verify:

   ```sh
   geoctl realm get --realm acme --field acr_policy | jq
   ```

   Should show `level: "2"` requiring `pwd` AND (`otp` OR `wbn`).

2. **Add a `step-up` flow.**

   Geonosis ships `step-up-mfa` pre-installed for level 2. Confirm:

   ```sh
   geoctl flows get --realm acme --alias step-up-mfa | head -30
   ```

   The graph is short: re-validate cookie → branch on whether the
   user has WebAuthn enrolled → `webauthn` step OR `otp` step →
   success. See [`06-auth-flows.md`](../06-auth-flows.md) for the
   DSL shape.

3. **Bind the flow to the realm at the right ACR level.**

   ```sh
   geoctl realm patch --realm acme \
     --acr-bind '{"acr":"2","step_up_flow":"step-up-mfa"}'
   ```

4. **Make your client send `acr_values=2` on sensitive endpoints.**

   In your app, when the user clicks "Settings > Billing", redirect
   them through `/authorize` with `acr_values=2 max_age=600`. If
   the existing session is < 10 min old AND was previously
   step-up'd, the executor short-circuits and re-issues a token
   immediately. Otherwise, the user is prompted for their second
   factor.

   Example (Next.js):

   ```ts
   const url = new URL(`${ISSUER}/protocol/openid-connect/auth`);
   url.searchParams.set("client_id", "acme-web");
   url.searchParams.set("response_type", "code");
   url.searchParams.set("redirect_uri", `${APP}/callback`);
   url.searchParams.set("scope", "openid");
   url.searchParams.set("acr_values", "2");
   url.searchParams.set("max_age", "600");
   url.searchParams.set("code_challenge", challenge);
   url.searchParams.set("code_challenge_method", "S256");
   location.href = url.toString();
   ```

5. **(Optional) Reject tokens that don't carry `acr=2` server-side.**

   In your resource server, after JWT verification:

   ```ts
   if (req.path.startsWith("/billing")) {
     if (claims.acr !== "2") return res.status(401).send("step_up_required");
   }
   ```

## Verifying

After redirecting an existing session through `/authorize` with
`acr_values=2`:

- New id_token has `"acr": "2"` and `"amr": ["pwd","otp"]`.
- The flow shown in the browser only asks for the second factor,
  not the password again (because the password AMR is already
  satisfied within `max_age`).

## Troubleshooting

- **Step-up flow runs the full password step again** — the user's
  session is older than `max_age` or `auth_time` is missing.
  Lower `max_age` or set `SessionPolicy.sso_session_idle` so the
  session is still considered fresh.
- **`interaction_required` returned to the client** — the user has
  no second factor enrolled. Either gate on `required_actions
  contains configure-otp` and surface a "set up MFA" page, or run
  a `passkey-enroll` subflow.
- **ACR doesn't appear in the id_token** — verify
  `TokenPolicy.include_authn_acr = true` for the realm.

## See also

- [`06-auth-flows.md`](../06-auth-flows.md) §Flow kinds.
- [`12-security-crypto.md`](../12-security-crypto.md) §ACR Policy.
- [`03-protocols-oidc.md`](../03-protocols-oidc.md) — `acr_values`
  semantics.
