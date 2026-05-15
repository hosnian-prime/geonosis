# 09 — Set up a B2B Organization and invite members

## What you'll have at the end

Realm `master` hosts a customer Organization `customer-co` with its
own branding, a claimed-and-verified domain `customer-co.example`,
its first members invited by email, and a corporate Okta IdP
bound for SSO.

## Prerequisites

- A running realm `master` with `organizations_enabled = true`
  (default).
- Realm SMTP server configured (for invitation emails).

## Steps

1. **Create the organization.**

   ```sh
   geoctl orgs create \
     --realm master \
     --alias customer-co \
     --display-name "Customer Co." \
     --description "Our first paying customer" \
     --branding '{
       "logo_uri":"https://cdn.customer-co.example/logo.svg",
       "primary_color":"#1f6feb",
       "banner_text":"Welcome to Customer Co."
     }'
   ```

2. **Claim the domain.**

   ```sh
   geoctl orgs domain-add --realm master --alias customer-co --domain customer-co.example
   ```

   Returns a verification token. Add a DNS TXT record:

   ```
   _geonosis-challenge.customer-co.example  TXT  "geonosis-verify=<token>"
   ```

   Then trigger verification:

   ```sh
   geoctl orgs domain-verify --realm master --alias customer-co --domain customer-co.example
   ```

   Audit event: `org.domain.verified`. The domain is now eligible
   for auto-join.

3. **Configure auto-join policy (optional).**

   If you want users registering with a `@customer-co.example`
   email to be automatically offered membership in `customer-co`:

   ```sh
   geoctl orgs policy --realm master --alias customer-co \
     --auto-join-on-domain-match
   ```

4. **Bind a corporate IdP.**

   Assume a realm IdP `okta-customer-co` already configured
   (recipe out of scope; see
   [`05-identity-broker.md`](../05-identity-broker.md)):

   ```sh
   geoctl orgs idp-bind \
     --realm master \
     --alias customer-co \
     --idp okta-customer-co \
     --set-as-default
   ```

   Now the org's login page features the Okta button first, and
   users brokered through it are auto-joined to `customer-co`.

5. **Define org-level roles.**

   ```sh
   geoctl orgs role-create --realm master --alias customer-co --name owner
   geoctl orgs role-create --realm master --alias customer-co --name billing
   geoctl orgs role-create --realm master --alias customer-co --name member
   ```

6. **Invite the first members.**

   ```sh
   geoctl orgs invite \
     --realm master \
     --alias customer-co \
     --email cto@customer-co.example \
     --roles owner,billing \
     --expires-in 14d
   ```

   Geonosis sends an email via the realm SMTP config with a
   single-use link. The invitee follows it, optionally registers
   or logs in, and is added to the org.

## Verifying

```sh
geoctl orgs get --realm master --alias customer-co --field members | jq
```

Lists members with roles + join state.

Token issued to a member, when in org context, carries the `org`
claim:

```json
{
  "sub": "01HUCTO...",
  "org": {
    "id": "01HORG...",
    "alias": "customer-co",
    "roles": ["owner","billing"]
  },
  "realm_access": { "roles": ["user"] }
}
```

Org context is decided by subdomain routing
(`customer-co.tenants.geonosis.example.com`), the `?organization`
URL parameter, or a member-selection page when neither is set.

## Suspending the org

If a customer breaches terms:

```sh
geoctl orgs patch --realm master --alias customer-co --enabled=false
```

Logins from members are blocked at the flow's start node with
error `org_suspended`. Re-enable with `--enabled=true`.

## Troubleshooting

- **DNS verification fails** — wait for TXT propagation (up to
  72 h depending on TTL). Run `dig TXT
  _geonosis-challenge.customer-co.example` to confirm.
- **Auto-join offers the wrong org** — a verified domain can only
  belong to one org at a time; check for collisions with
  `geoctl orgs domain-list --realm master`.
- **Invitation email never arrives** — check realm SMTP config
  + audit log for `org.invitation.sent`. If sent but not delivered,
  it's a deliverability problem on your side.
- **Member can't access org-only resources** — token doesn't carry
  the `org` claim. Their session isn't in org context. Use the
  subdomain or `?organization=customer-co` query parameter.

## See also

- [`15-organizations.md`](../15-organizations.md) — Full
  Organization data model + audit events.
- [`05-identity-broker.md`](../05-identity-broker.md) — IdP
  binding mechanics.
