# 20 — Write a custom token mapper in WASM

## What you'll have at the end

A WASM mapper that computes a `tenant_tier` claim by looking up
the user's organization membership and adds it to every access
token — logic that the built-in `claim-from-attribute` mapper
can't express.

## Prerequisites

- Rust ≥ 1.83 with `wasm32-wasip2` target.
- A running realm `master` with organizations configured.
- Familiarity with recipe 04 (custom authenticator) — the build
  pipeline is the same.

## Steps

1. **Create the mapper crate.**

   ```sh
   cargo new --lib geonosis-mapper-tenant-tier
   cd geonosis-mapper-tenant-tier
   ```

   `Cargo.toml`:

   ```toml
   [package]
   name = "geonosis-mapper-tenant-tier"
   version = "0.1.0"
   edition = "2021"

   [lib]
   crate-type = ["cdylib"]

   [dependencies]
   geonosis-spi-api = "0.1"
   serde = { version = "1", features = ["derive"] }
   serde_json = "1"
   ```

2. **Implement the `Mapper` trait.**

   `src/lib.rs`:

   ```rust
   use geonosis_spi_api::mapper::*;
   use serde::Deserialize;

   #[derive(Deserialize)]
   struct TierConfig {
       tier_attribute: String,      // org attribute key
       default_tier: String,        // fallback when org has no tier
   }

   struct TenantTierMapper;

   impl Mapper for TenantTierMapper {
       fn describe() -> ProviderInfo {
           ProviderInfo {
               id: "tenant-tier".into(),
               display_name: "Tenant Tier Mapper".into(),
               config_schema: include_str!("../config.schema.json").into(),
           }
       }

       fn map_claims(ctx: MapperContext, input: ClaimSet, cfg: &[u8]) -> Result<Claims, ProviderError> {
           let cfg: TierConfig = serde_json::from_slice(cfg)
               .map_err(|e| ProviderError::InvalidConfig(e.to_string()))?;

           // Start from the existing claim set and add our claims
           let mut claims = Claims::from(input);

           // Read the user's org context from the mapper context
           if let Some(org) = &ctx.organization {
               let tier = org.attributes
                   .get(&cfg.tier_attribute)
                   .and_then(|v| v.as_str())
                   .unwrap_or(&cfg.default_tier);

               claims.insert("tenant_tier".into(), tier.into());
               claims.insert("tenant_id".into(), org.alias.clone().into());
           } else {
               claims.insert("tenant_tier".into(), cfg.default_tier.clone().into());
           }

           Ok(claims)
       }
   }

   export_mapper_provider!(TenantTierMapper);
   ```

   **Performance note:** mappers run on **every token mint**
   (access token, id token, userinfo). Keep them fast — under
   5 ms. This mapper does no I/O (reads from context only), so
   it's sub-microsecond. If you need external data, cache
   aggressively or pre-compute into user attributes.

3. **Build.**

   ```sh
   cargo build --target wasm32-wasip2 --release
   ```

4. **Upload and bind.**

   ```sh
   geoctl spi install \
     --realm master \
     --interface geonosis:mapper@0.1.0 \
     --alias tenant-tier \
     --module target/wasm32-wasip2/release/geonosis_mapper_tenant_tier.wasm \
     --config '{
       "tier_attribute": "subscription_tier",
       "default_tier": "free"
     }' \
     --priority 500
   ```

5. **Bind to a client (optional scope-gating).**

   ```sh
   geoctl clients mapper-add \
     --realm master \
     --client master-web \
     --mapper-urn wasm:tenant-tier:mapper \
     --config '{
       "tier_attribute": "subscription_tier",
       "default_tier": "free",
       "access_token": true,
       "id_token": true,
       "userinfo": false
     }'
   ```

## Verifying

```sh
# Issue a token in org context:
echo "$ACCESS_TOKEN" | cut -d. -f2 | base64 -d | jq '{tenant_tier, tenant_id}'
```

Expected:

```json
{
  "tenant_tier": "enterprise",
  "tenant_id": "customer-co"
}
```

## Testing locally

Before deploying, test the mapper with `geoctl spi test`:

```sh
geoctl spi test \
  --interface geonosis:mapper@0.1.0 \
  --module target/wasm32-wasip2/release/geonosis_mapper_tenant_tier.wasm \
  --config '{"tier_attribute":"subscription_tier","default_tier":"free"}' \
  --context '{
    "user": {"id":"01HU...","username":"ada"},
    "organization": {"alias":"customer-co","attributes":{"subscription_tier":"enterprise"}}
  }'
```

Returns the claims the mapper would produce — no server needed.

## When to use built-in vs custom mappers

| Use case | Built-in | Custom WASM |
|---|---|---|
| Copy user attribute to claim | `claim-from-attribute` | |
| Map groups to roles | `groups-to-roles` | |
| Hardcoded static claim | `hardcoded-claim` | |
| Cross-entity logic (user + org) | | **this recipe** |
| External API enrichment | | WASM with `host::http_client` |
| Computed/derived values | | WASM |

## Troubleshooting

- **Claim missing** — mapper may not be bound to the client.
  Check `geoctl clients mapper-list --realm master --client
  master-web`.
- **`quarantined` after upload** — mapper crashed or exceeded
  fuel. Default fuel for mappers is 50 M (200 ms wall-clock). Check logs
  for the panic message.
- **Mapper runs but claim is `null`** — the `MapperContext` may
  not include org data because the session isn't in org context.

## See also

- [`07-spi-wasm.md`](../07-spi-wasm.md) — Mapper SPI contract,
  dispatch semantics (Chain), fuel limits.
- [Recipe 02 — Add a custom claim](./02-add-custom-claim.md) —
  Simpler path using built-in mappers.
