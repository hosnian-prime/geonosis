# 11 — Federate users from LDAP / Active Directory

## What you'll have at the end

Users in your corporate AD authenticate against Geonosis without
copying passwords. On first login, a local shadow row is created;
subsequent logins delegate credential validation to LDAP via bind.

## Prerequisites

- A running realm `master`.
- Network access from Geonosis pods to the LDAP/AD endpoint.
- A **dedicated read-only service account** in AD (not a domain
  admin — principle of least privilege). The account needs only
  `Read` permission on the user OU.

## Steps

1. **Create the federation source.**

   ```sh
   geoctl federation create \
     --realm master \
     --alias corp-ad \
     --kind ldap \
     --config '{
       "urls": ["ldaps://dc01.corp.example:636", "ldaps://dc02.corp.example:636"],
       "bind_dn": "CN=geonosis-svc,OU=Service Accounts,DC=corp,DC=example",
       "bind_password": "CORP_AD_BIND_PW",
       "base_dn": "OU=Users,DC=corp,DC=example",
       "user_object_classes": ["user"],
       "user_filter": "(&(objectClass=user)(sAMAccountName={username})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
       "page_size": 500,
       "tls": "LDAPS",
       "attribute_map": {
         "username": "sAMAccountName",
         "email": "mail",
         "given_name": "givenName",
         "family_name": "sn"
       },
       "write_policy": "ReadOnly"
     }' \
     --sync-policy '{
       "enabled": true,
       "full_sync_cron": "0 2 * * 0",
       "incremental_sync_cron": "*/15 * * * *",
       "changed_attribute": "uSNChanged"
     }' \
     --priority 100
   ```

   **Key decisions:**

   - **LDAPS** (port 636) over StartTLS — avoids downgrade attacks
     and works reliably behind load balancers. Always validate the
     server certificate.
   - **`sAMAccountName`** for username, not `userPrincipalName` —
     UPN can change on domain rename; `sAMAccountName` is stable
     within a domain.
   - **Disabled-account filter** in `user_filter`
     (`userAccountControl` bit `0x0002`) — prevents disabled AD
     users from even reaching the bind step.
   - **`uSNChanged`** for incremental sync — more reliable than
     `modifyTimestamp` in AD because it's local to the DC.
   - Two URLs for **failover** — round-robin with automatic
     circuit-breaker (5 consecutive failures → `CircuitOpen`).

2. **Store the bind password.**

   ```sh
   geoctl secrets put --realm master --name CORP_AD_BIND_PW --value "$AD_PASSWORD"
   ```

3. **Enable group sync (optional).**

   ```sh
   geoctl federation patch --realm master --alias corp-ad \
     --group-sync '{
       "group_object_classes": ["group"],
       "group_filter": "(objectClass=group)",
       "membership_attribute": "memberOf",
       "group_name_attribute": "cn",
       "create_missing_groups": true
     }'
   ```

   Group sync is **authoritative** by default — LDAP memberships
   replace local ones on each sync run.

4. **Run an initial full sync.**

   ```sh
   geoctl federation sync --realm master --source corp-ad --full
   ```

## Verifying

```sh
# Login as an AD user:
docker run --rm --network host \
  ghcr.io/hosnian-prime/geonosis-quickstart-helper \
  login --realm master --user jdoe --pw 'AD_password'

# Check the user was mirrored:
geoctl users get --realm master --user jdoe | jq '.federation'
```

Shows `source_urn: "builtin:user-storage:ldap:corp-ad"` and
`external_dn`.

## Multi-domain AD forests

For forests with multiple domains, use the **Global Catalog**
(port 3636 for LDAPS) and set `base_dn` to the forest root.
The GC holds a read-only partial attribute set across all domains.

## Troubleshooting

- **`CircuitOpen` after 5 failures** — check network connectivity
  and TLS cert validity. Health probe retries every 30 s;
  `geoctl federation status --realm master --alias corp-ad` shows
  current state.
- **User attributes missing** — the service account may lack
  read permission on the attribute. AD's default deny on
  `mail` in some OUs is common.
- **Login slow (> 2s)** — tune `page_size`, raise LDAP connection
  pool size (default 8), or switch from on-demand to scheduled
  sync to avoid LDAP search on the auth hot path.
- **Tombstoned users still appear enabled** — incremental sync
  checks the deleted-objects container only if `sync_policy` is
  enabled. Run a one-shot: `geoctl federation sync --source
  corp-ad --realm master --incremental`.

## See also

- [`04-federation-ldap.md`](../04-federation-ldap.md) — Full
  config reference, AD tombstone handling, failure semantics.
- [`07-spi-wasm.md`](../07-spi-wasm.md) — Custom non-LDAP
  federation via `geonosis:user-storage@0.1.0`.
