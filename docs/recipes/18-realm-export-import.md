# 18 — Export and import a realm configuration

## What you'll have at the end

A complete YAML export of realm `master`'s configuration (clients,
flows, roles, groups, IdPs, SPI bindings, policies) that can be
imported into another Geonosis instance or version-controlled
in Git.

## Prerequisites

- A running Geonosis with `geoctl` available.
- The source realm `master` with configuration you want to export.

## Steps

1. **Export the realm.**

   ```sh
   geoctl realm export --realm master --output acme-realm.yaml
   ```

   The export includes:
   - Realm settings (login, session, token, password, OTP, WebAuthn
     policies, ACR policy, security headers, theme binding)
   - Clients (OIDC + SAML SP, with consent policies)
   - Roles (realm + client-scoped, composites)
   - Groups (hierarchy, attributes, role assignments)
   - Auth flows (full graph DSL)
   - Identity providers (broker config, mapper bindings)
   - Federation sources (LDAP config — **excluding bind password**)
   - SPI bindings (priority, config, replaces)
   - Organization structure (orgs, roles, consent policies —
     **excluding member data**)
   - User Profile schema

   **What's excluded** (by design):
   - Users and credentials (use `geoctl users export` separately)
   - Sessions and tokens
   - Signing keys (re-generated on import)
   - Secrets (`Secret<T>` fields exported as `"<REDACTED>"`)
   - Audit events

2. **Review and edit.**

   ```sh
   # The YAML is human-readable and diff-friendly:
   less acme-realm.yaml
   ```

   Common edits before importing to a different environment:
   - Change `frontend_url` to the target's URL.
   - Remove environment-specific IdP client IDs.
   - Adjust `smtp` configuration.

3. **Import to another instance.**

   ```sh
   geoctl realm import --file acme-realm.yaml --realm master-staging
   ```

   If `acme-staging` doesn't exist, it's created. If it exists,
   the import **merges** — existing entities are updated, new ones
   are added. Nothing is deleted (safe by default).

   To force a destructive sync (staging/test only):

   ```sh
   geoctl realm import --file acme-realm.yaml --realm master-staging --mode replace
   ```

4. **Re-inject secrets.**

   The import doesn't carry secrets. After import:

   ```sh
   geoctl secrets put --realm master-staging --name GOOGLE_CLIENT_SECRET --value "$SECRET"
   geoctl secrets put --realm master-staging --name CORP_AD_BIND_PW --value "$AD_PW"
   ```

## Export individual components

```sh
# Export only flows:
geoctl flows export --realm master --output flows.yaml

# Export only clients:
geoctl clients export --realm master --output clients.yaml

# Export a single flow:
geoctl flows get --realm master --alias browser --format yaml > browser-flow.yaml
```

## Version control workflow

```sh
# In your infra repo:
mkdir -p iam/realms/
geoctl realm export --realm production --output iam/realms/production.yaml
git add iam/realms/production.yaml
git commit -m "snapshot realm config after MFA rollout"
```

On deploy:

```sh
geoctl realm import --file iam/realms/production.yaml --realm production
```

## Verifying

```sh
# Compare source and target:
geoctl realm export --realm master-staging --output staging-check.yaml
diff acme-realm.yaml staging-check.yaml
```

Differences should only be in auto-generated fields (IDs, timestamps,
key material).

## Troubleshooting

- **`conflict: client_id already exists`** — the target realm has
  a client with the same `client_id` but different internal ID.
  Use `--mode replace` or rename the conflicting client.
- **`secret field is redacted`** — expected. Re-inject secrets
  manually after import (step 4).
- **Flows reference missing SPI bindings** — import order matters.
  Export + import the full realm (step 1) to ensure all
  dependencies are included.
- **Signing keys differ** — keys are never exported. The target
  realm generates its own. Update downstream JWKS caches.

## See also

- [`06-auth-flows.md`](../06-auth-flows.md) — Flow YAML/JSON
  format.
- [`14-roadmap.md`](../14-roadmap.md) — Full realm
  export/import is v0.1 (flows) + v0.2 (complete realm).
