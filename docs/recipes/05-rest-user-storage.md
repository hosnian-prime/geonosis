# 05 — Federate users from a REST-backed user store

## What you'll have at the end

Geonosis authenticates users against your existing user service
(REST API in front of your Postgres `users` table — or anything
else). The built-in local store is bypassed entirely.

## Why this shape (not direct DB)

WASM modules don't open arbitrary DB sockets — the sandbox routes
egress through the host's allowlisted HTTP client (see
[`07-spi-wasm.md`](../07-spi-wasm.md) §Sandbox). Wrap your user
service in a small HTTP layer and the WASM provider calls that.

## Prerequisites

- Your existing REST API supporting at minimum:
  - `GET /users?username={u}` → `200 {id, email, name, attributes}` or `404`
  - `POST /users/{id}/verify-credential` → `200 {valid: true}` or `403`
- A running Geonosis realm.

## Steps

1. **Author the WASM provider.**

   Create a Rust crate (same scaffolding as recipe 04 but
   implementing `UserStorageProvider`):

   ```rust
   use geonosis_spi_api::user_storage::*;
   use geonosis_spi_api::host;
   use serde::Deserialize;

   #[derive(Deserialize)]
   struct StoreConfig {
       base_url: String,
       auth_secret_key: String,    // host secret name
   }

   struct RestUserStorage;

   impl UserStorageProvider for RestUserStorage {
       fn describe() -> ProviderInfo {
           ProviderInfo { id: "rest-store".into(), display_name: "REST User Store".into(), config_schema: "{}".into() }
       }

       fn find_by_username(realm: &str, username: &str, cfg: &[u8])
           -> Result<LookupOutcome<ExternalUser>, ProviderError>
       {
           let cfg: StoreConfig = serde_json::from_slice(cfg)
               .map_err(|e| ProviderError::InvalidConfig(e.to_string()))?;
           let secret = host::secrets::read(&cfg.auth_secret_key)?;
           let resp = host::http_client::get(
               &format!("{}/users?username={}", cfg.base_url, urlencoding::encode(username)),
               &[("authorization", &format!("Bearer {}", std::str::from_utf8(&secret).unwrap()))],
           )?;
           match resp.status {
               404 => Ok(LookupOutcome::NotFound),
               200 => {
                   let u: ExternalUserRaw = serde_json::from_slice(&resp.body)?;
                   Ok(LookupOutcome::Found(u.into_external(realm)))
               }
               s => Err(ProviderError::NetworkError(format!("unexpected status {s}"))),
           }
       }

       // find_by_id, find_by_email, validate_credential, search — same shape.
       // For read-only operation: implement create/update/delete as Unsupported.
   }

   export_user_storage_provider!(RestUserStorage);
   ```

   Build with `cargo build --target wasm32-wasip2 --release`.

2. **Upload + replace the local store.**

   ```sh
   geoctl spi install \
     --realm acme \
     --interface geonosis:user-storage@0.1.0 \
     --alias acme-internal-store \
     --module target/wasm32-wasip2/release/geonosis_spi_rest_store.wasm \
     --config '{
       "base_url":"https://users.acme.internal",
       "auth_secret_key":"INTERNAL_USERS_API_KEY"
     }' \
     --priority 100 \
     --replaces builtin:user-storage:local
   ```

   `--replaces` is the explicit override of the built-in local
   store — see [`07-spi-wasm.md`](../07-spi-wasm.md)
   §Override patterns. Once enabled, the local store is skipped
   entirely.

3. **Add the secret.**

   ```sh
   geoctl secrets put --realm acme --name INTERNAL_USERS_API_KEY --value "$INTERNAL_API_KEY"
   ```

   Stored encrypted under the master key
   ([`12-security-crypto.md`](../12-security-crypto.md)).

4. **Test a login.**

   ```sh
   docker run --rm --network host \
     ghcr.io/hosnian-prime/geonosis-quickstart-helper \
     login --realm acme --user $USER_FROM_YOUR_REST_API --pw 'pw'
   ```

## Verifying

The `app_user` Postgres table sees no traffic on the auth path:

```sh
docker compose exec postgres psql -U geonosis -c \
  "SELECT count(*) FROM app_user WHERE realm_id = (SELECT id FROM realm WHERE slug='acme')"
```

Stays at the bootstrap count (3) even after many logins.

Audit log:

```sh
geoctl audit list --realm acme --action 'login.success'
```

shows `source_urn: wasm:acme-internal-store:user-storage`.

## Troubleshooting

- **Token mint fails with `user_not_found`** — your REST API
  returned 200 but the response shape didn't match `ExternalUser`.
  Run with `RUST_LOG=geonosis_spi_host=debug`.
- **Login slow (> 1s)** — increase `host.http-client` connection
  pool and lower the verify endpoint's latency. Default fuel for
  user-storage is 200 M (~2 s wall-clock).
- **Rolling back to the built-in store** — clear `replaces` on
  the binding: `geoctl spi patch --realm acme --alias
  acme-internal-store --clear-replaces`. The local store
  re-activates within 100 ms via NOTIFY.

## See also

- [`07-spi-wasm.md`](../07-spi-wasm.md) — Provider registry,
  override semantics.
- [`04-federation-ldap.md`](../04-federation-ldap.md) — LDAP is
  the same registry, just a different built-in provider.
