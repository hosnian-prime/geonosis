# 15 — Configure organization roles and permissions

## What you'll have at the end

Organization `customer-co` has custom roles beyond the built-in
`owner` / `admin` / `member`: a `billing` role that can only manage
consent policies, and a `team-lead` role that can invite members
but not manage IdPs.

## Prerequisites

- A running realm `master` with `organizations_enabled = true`.
- Organization `customer-co` created (recipe 09).

## Steps

1. **List the built-in roles.**

   ```sh
   geoctl orgs role-list --realm master --alias customer-co | jq
   ```

   Every new org ships with three built-in roles:

   | Role | Permissions |
   |---|---|
   | `owner` | `Admin`, `InviteMembers`, `ManageDomains`, `ManageIdps`, `ManageRoles`, `ManageConsent` |
   | `admin` | `Admin`, `InviteMembers`, `ManageDomains`, `ManageRoles` |
   | `member` | `ViewMembers` (implicit) |

   Built-in roles can be renamed but not deleted. At least one
   `owner` must exist at all times.

2. **Create a `billing` role.**

   ```sh
   geoctl orgs role-create \
     --realm master \
     --alias customer-co \
     --name billing \
     --description "Can manage consent policies and view members" \
     --permissions '["ManageConsent", "ViewMembers"]'
   ```

3. **Create a `team-lead` role.**

   ```sh
   geoctl orgs role-create \
     --realm master \
     --alias customer-co \
     --name team-lead \
     --description "Can invite and remove team members" \
     --permissions '["InviteMembers", "ViewMembers"]'
   ```

4. **Assign roles to members.**

   ```sh
   # Assign billing to an existing member:
   geoctl orgs member-roles \
     --realm master \
     --alias customer-co \
     --user cfo@customer-co.example \
     --set '["billing"]'

   # Invite a new member with the team-lead role:
   geoctl orgs invite \
     --realm master \
     --alias customer-co \
     --email lead@customer-co.example \
     --roles team-lead \
     --expires-in 7d
   ```

   A member can hold **multiple roles** simultaneously. Permissions
   are the **union** of all assigned roles.

5. **Create a custom permission (advanced).**

   For app-specific authorization beyond the built-in permissions,
   use `Custom(String)`:

   ```sh
   geoctl orgs role-create \
     --realm master \
     --alias customer-co \
     --name data-steward \
     --permissions '["ViewMembers", {"Custom": "data:approve-export"}]'
   ```

   Custom permissions are emitted in the `org.roles` token claim.
   Your resource server evaluates them — Geonosis enforces only
   the built-in permissions on its admin API.

## Verifying

```sh
# Token for a billing member in org context:
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d | jq '.org'
```

Expected:

```json
{
  "id": "01HORG...",
  "alias": "customer-co",
  "roles": ["billing"]
}
```

```sh
# Billing member tries to invite — should be forbidden:
curl -fsS -X POST \
  -H "Authorization: Bearer $BILLING_TOKEN" \
  https://geonosis.example.com/admin/v1/realms/master/orgs/customer-co/invitations \
  -d '{"email":"new@customer-co.example","roles":["member"]}'
# → 403 Forbidden (InviteMembers permission required)

# Billing member manages consent — should succeed:
curl -fsS -X GET \
  -H "Authorization: Bearer $BILLING_TOKEN" \
  https://geonosis.example.com/admin/v1/realms/master/orgs/customer-co/consent-policies
# → 200 OK
```

## Permission evaluation

The admin API checks permissions in this order:

1. **Realm admin?** → full access to all orgs.
2. **Org member with `Admin` permission?** → full org access.
3. **Org member with specific permission?** → only that operation.
4. **No matching permission?** → `403 Forbidden`.

`Admin` implies all other built-in permissions. Custom permissions
are **not** implied by `Admin` — they're evaluated separately by
resource servers.

## Troubleshooting

- **`cannot delete last owner`** — at least one member must hold
  the `owner` role. Transfer ownership first.
- **Token missing `org.roles`** — session not in org context.
  Add `?organization=customer-co` to the `/authorize` request.
- **Custom permission not in token** — check the role assignment:
  `geoctl orgs member-get --realm master --alias customer-co
  --user the-user | jq '.roles'`.

## See also

- [`15-organizations.md`](../15-organizations.md) — Org roles,
  `OrgPermission` enum, built-in roles.
- [`02-data-model.md`](../02-data-model.md) — `OrgRole`,
  `OrgPermission`, `OrgMembership` types.
- [Recipe 14 — Consent management](./14-consent-management.md) —
  Org-level consent policies (requires `ManageConsent`).
