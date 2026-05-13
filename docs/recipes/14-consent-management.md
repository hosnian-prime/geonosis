# 14 — Configure consent management (system + org-level)

## What you'll have at the end

Client `partner-app` requires user consent before accessing
`profile` and `email` scopes. Organization `customer-co`
pre-approves `profile` for its members (skipping the prompt) and
blocks the `admin:write` scope entirely.

## Prerequisites

- A running realm `acme` with users and the `partner-app` client.
- An organization `customer-co` (recipe 09).

## Steps

### Part A — System-level consent

1. **Enable consent on the client.**

   ```sh
   geoctl clients patch --realm acme --client partner-app \
     --consent '{
       "consent_required": true,
       "display_on_consent_screen": true,
       "consent_screen_text": "Partner App requests access to your profile data.",
       "consent_lifespan": null
     }'
   ```

   `consent_lifespan: null` means "until revoked". Set a duration
   (e.g. `"90d"`) to force re-prompting periodically — useful for
   compliance regimes that require annual re-consent.

2. **Add human-readable scope descriptions.**

   The consent screen needs to show users **what** they're
   granting, not raw OAuth scope strings:

   ```sh
   geoctl scopes upsert --realm acme --scope profile \
     --display-name "Your name and profile picture" \
     --description "Read your display name, avatar, and locale"

   geoctl scopes upsert --realm acme --scope email \
     --display-name "Your email address" \
     --description "Read your email address and verification status"
   ```

3. **Test the consent flow.**

   ```sh
   open "https://geonosis.example.com/realms/acme/protocol/openid-connect/auth?\
   client_id=partner-app&response_type=code&scope=openid+profile+email&\
   redirect_uri=https://partner.example.com/callback"
   ```

   After password authentication, the user sees a consent screen
   listing the requested scopes with descriptions and the client's
   `policy_uri` / `tos_uri` links. On approval, a `ConsentGrant`
   is persisted.

### Part B — Organization-level consent

4. **Create an org consent policy.**

   ```sh
   curl -fsS -X POST \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     https://geonosis.example.com/admin/v1/realms/acme/orgs/customer-co/consent-policies \
     -d '{
       "client_id": "partner-app",
       "mode": "OrgPreApproved",
       "pre_approved_scopes": ["openid", "profile"],
       "blocked_scopes": ["admin:write"],
       "require_admin_approval": false
     }'
   ```

   **Consent evaluation for `customer-co` members:**

   | Scope requested | Result |
   |---|---|
   | `openid` | Pre-approved — no prompt |
   | `profile` | Pre-approved — no prompt |
   | `email` | Not pre-approved — user consent prompt shown |
   | `admin:write` | Blocked — silently removed from grant |

5. **For full org-managed consent (no user prompts):**

   ```sh
   curl -fsS -X POST \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     https://geonosis.example.com/admin/v1/realms/acme/orgs/customer-co/consent-policies \
     -d '{
       "client_id": "internal-dashboard",
       "mode": "OrgManaged",
       "pre_approved_scopes": ["openid", "profile", "email", "groups"],
       "blocked_scopes": [],
       "require_admin_approval": false
     }'
   ```

   In `OrgManaged` mode, org members never see a consent screen
   for this client — the org admin has decided on their behalf.
   This mirrors the "admin consent" pattern in Google Workspace
   and Microsoft Entra ID.

## Verifying

```sh
# List consent grants for a user:
geoctl users consents --realm acme --user ada | jq

# List org consent policies:
curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://geonosis.example.com/admin/v1/realms/acme/orgs/customer-co/consent-policies | jq
```

## Revoking consent

```sh
# User-initiated (or admin on behalf):
geoctl users consent-revoke --realm acme --user ada --client partner-app

# Org-admin bulk revoke for all members:
curl -fsS -X DELETE \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://geonosis.example.com/admin/v1/realms/acme/orgs/customer-co/consent-grants/GRANT_ID
```

On revocation, existing **refresh tokens** for the revoked
client + scope set are invalidated. Access tokens remain valid
until expiry (short-lived by design — default 5 min).

## Troubleshooting

- **Consent screen not showing** — client has
  `consent_required: false`. Patch it.
- **Org policy not taking effect** — the user's session isn't in
  org context. Ensure `?organization=customer-co` or subdomain
  routing is active.
- **`blocked_scopes` still appear in token** — org consent policy
  was created after the user already consented. Revoke the
  existing consent grant; next login applies the policy.
- **`consent_required` error returned to client** — the
  `/authorize` request used `prompt=none` but consent hasn't been
  granted yet. The client must handle this and re-request with
  user interaction.

## See also

- [`15-organizations.md`](../15-organizations.md) §Consent
  management — data model, evaluation order, audit events.
- [`03-protocols-oidc.md`](../03-protocols-oidc.md) — Consent
  in the `/authorize` state machine.
- [`02-data-model.md`](../02-data-model.md) — `ConsentGrant`,
  `OrgConsentPolicy`, `ConsentPolicy` types.
