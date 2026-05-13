# 04 — User Federation: LDAP / Active Directory

User federation lets Geonosis authenticate users that live in an
**external** LDAP / Active Directory and act as if they were native
Geonosis users — without copying their passwords.

## Modes

| Mode | What happens |
|---|---|
| **Pass-through bind** (default) | On login, Geonosis binds to LDAP as the user. Password never stored locally. |
| **Mirror (on-demand)** | On first successful bind, a local `User` row is created with `federation = Some(LdapLink{...})`. Subsequent attribute reads use a short LDAP search; results cached. |
| **Mirror (sync)** | A background job pulls users on a schedule (full + incremental via `modifyTimestamp`). Useful when LDAP search is too slow on the auth path. |

`Mirror (on-demand)` is the default v0.1 behavior. The other two are
configurable per `FederationSource`.

## Data model

See [`02-data-model.md`](./02-data-model.md) for `FederationSource`.
A user mirrored from LDAP has:

```rust
struct FederationLink {
    source_id: FederationId,
    external_id: String,          // entryUUID or objectGUID
    external_dn: String,
    last_synced_at: DateTime<Utc>,
}
```

When `federation = Some(_)`, the user's local row is a **shadow**:

- The `credentials` table has no row for the user; password
  validation is always delegated to LDAP.
- Attribute writes are either rejected (read-only mode) or pushed
  back to LDAP (writable mode).
- Hard-deleting the LDAP entry: a sync run marks the local row
  `enabled=false` and emits `federation.removed`. Hard local delete
  is an admin action with a confirm prompt.

## Configuration shape

```rust
struct FederationConfig {
    urls: Vec<LdapUrl>,            // round-robin, with failover
    bind_dn: Option<String>,       // service-account DN
    bind_password: Secret<String>, // pulled from secret store
    base_dn: String,
    user_object_classes: Vec<String>,
    user_filter: String,           // e.g. "(&(objectClass=user)(sAMAccountName={username}))"
    page_size: usize,              // simple paged result, default 1000
    referrals: ReferralPolicy,
    tls: TlsPolicy,                // StartTLS / LDAPS / None
    server_principal: Option<String>, // GSSAPI when binding via Kerberos
    attribute_map: AttributeMap,   // ldap attr -> Geonosis attr
    write_policy: WritePolicy,     // ReadOnly | Writable
    sync_policy: SyncPolicy,
}

struct AttributeMap {
    username: String,              // "sAMAccountName" / "uid"
    email: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    extra: BTreeMap<String, String>,
}

struct SyncPolicy {
    enabled: bool,
    full_sync_cron: Option<String>,
    incremental_sync_cron: Option<String>,
    changed_attribute: String,     // "modifyTimestamp" / "uSNChanged"
}
```

The `bind_password` is **not** stored in plaintext. Configuration
fields of type `Secret<T>` are persisted as ciphertext encrypted with
the realm's `master_secret` key. See [`12-security-crypto.md`](./12-security-crypto.md).

## Authentication flow integration

Federation participates in the auth flow as a **user-storage source**.
When a flow's `LookupUser` step runs, the storage layer queries
sources in priority order:

```
local users → federation sources (by priority) → SPI WasmFederation
```

The first source that returns a match wins. A `UsernamePassword` step
then dispatches the credential validation to that source:

- Local user → bcrypt/argon2 check against `credential` row.
- LDAP user → simple BIND with the supplied password against the
  user's DN.
- WASM federation → `geonosis:federation/validate-credential` call.

## Group sync (optional)

When configured, group memberships in LDAP can be projected to
Geonosis groups:

```rust
struct GroupSyncConfig {
    group_object_classes: Vec<String>,
    group_filter: String,
    membership_attribute: String,  // "memberOf" | "member"
    group_name_attribute: String,
    create_missing_groups: bool,
}
```

On login (or sync run), the user's local group memberships are
**replaced** with the mapped set — group sync is authoritative. A
config switch makes it additive instead, but the default is
authoritative because predictability beats convenience here.

## Connection management

- One **bounded pool** per `FederationSource`. Default size 8.
- Connection liveness: PING via `compare` against the rootDSE.
- Bind failure backoff: exponential, capped at 60 s, with
  jitter. After 5 consecutive failures the source enters
  `CircuitOpen`; logins requiring it return
  `temporarily_unavailable`. A health probe checks every 30 s.

LDAP I/O is **async** via the `ldap3` crate with Tokio. Bind calls run
under a timeout (default 5 s); search calls under a separate timeout
(default 10 s).

## Failure semantics

| Failure | Behavior |
|---|---|
| LDAP unreachable, user is mirrored, `WritePolicy=ReadOnly` | Login proceeds with last-known attributes; password check still requires LDAP, so bind fails closed unless `OfflinePolicy::AllowMirroredPassword` (off by default) |
| LDAP unreachable, user not yet mirrored | Login fails `temporarily_unavailable` |
| Password incorrect | Standard `invalid_grant` / `Invalid username or password` |
| User locked in AD (`userAccountControl` bit set) | Login fails; mirror row marked `enabled=false` |
| LDAP TLS handshake fails | Source enters `CircuitOpen`; alert |

## Migration / data loading

There is no big-bang import. The first time a user logs in, we mirror
them. Operators wanting eager mirroring run a one-shot sync job via
`geoctl federation sync --source corp-ad --full`.

## Custom federation via SPI

A WASM module implementing `geonosis:federation@0.1.0` can supply a
non-LDAP source (SCIM, REST API, internal HR system). The contract is
in [`07-spi-wasm.md`](./07-spi-wasm.md). The runtime treats it
identically to LDAP from the resolver's perspective.

## Non-goals

- **Pushing local users back to LDAP** (Geonosis as the master) —
  out of scope.
- **Two-way password sync** — out of scope, always.
- **NTLM / SPNEGO browser SSO** — v0.2 with WASM SPI; v0.1 has the
  LDAP credential path only.
- **eDirectory and Tivoli DS quirks** — supported via attribute
  mapping but not specifically tested.

## Open

- **AD recycle-bin tombstone handling** during incremental sync —
  needs spec.
- **Page cookie vs simple paged results** — pick simple paged for
  v0.1; VLV deferred.
- **Kerberos pass-through** binding — design exists, ship v0.2.
