# 04 — Write a custom authenticator in Rust

## What you'll have at the end

A WASM SPI plugin implementing
`geonosis:authn@0.1.0`, uploaded into your realm, bound as a step
in the `browser` flow, sandboxed and hot-reloadable.

Worked example: a **captcha** authenticator that validates a
hCaptcha token before allowing the next flow step.

## Prerequisites

- Rust ≥ 1.83 with the `wasm32-wasip2` target installed:
  ```sh
  rustup target add wasm32-wasip2
  ```
- A running realm (recipe 01 quickstart is fine).
- `geoctl` available locally.

## Steps

1. **Create the plugin crate.**

   ```sh
   cargo new --lib geonosis-spi-captcha
   cd geonosis-spi-captcha
   ```

   Replace `Cargo.toml`:

   ```toml
   [package]
   name = "geonosis-spi-captcha"
   version = "0.1.0"
   edition = "2021"

   [lib]
   crate-type = ["cdylib"]

   [dependencies]
   geonosis-spi-api = "0.1"
   serde = { version = "1", features = ["derive"] }
   serde_json = "1"
   ```

2. **Implement the `Authenticator` trait.**

   `src/lib.rs`:

   ```rust
   use geonosis_spi_api::authn::*;
   use geonosis_spi_api::host;
   use serde::Deserialize;

   #[derive(Deserialize)]
   struct CaptchaConfig {
       secret_env: String,            // host secrets key
       endpoint: String,              // hCaptcha verify URL
       required_score: f32,
   }

   struct CaptchaAuthn;

   impl Authenticator for CaptchaAuthn {
       fn describe() -> ProviderInfo {
           ProviderInfo {
               id: "captcha".into(),
               display_name: "hCaptcha gate".into(),
               config_schema: include_str!("../config.schema.json").into(),
           }
       }

       fn process(
           ctx: FlowContext,
           input: StepInput,
           cfg: &[u8],
       ) -> Result<StepOutput, ProviderError> {
           let cfg: CaptchaConfig = serde_json::from_slice(cfg)
               .map_err(|e| ProviderError::InvalidConfig(e.to_string()))?;

           // First entry: render the captcha widget
           let token = match input {
               StepInput::Submit(form) => form.get("h-captcha-response").cloned(),
               _ => None,
           };

           let Some(token) = token else {
               return Ok(StepOutput::Render(RenderInstruction {
                   template: "login/captcha.html".into(),
                   locals: Default::default(),
                   csrf: ctx.csrf,
               }));
           };

           // Validate with the host's HTTP client
           let secret = host::secrets::read(&cfg.secret_env)?;
           let resp = host::http_client::post_form(
               &cfg.endpoint,
               &[("secret", std::str::from_utf8(&secret).unwrap()),
                 ("response", &token)],
           )?;
           let body: serde_json::Value = serde_json::from_slice(&resp.body)
               .map_err(|e| ProviderError::Internal(e.to_string()))?;

           if body["success"].as_bool() == Some(true)
               && body["score"].as_f64().unwrap_or(0.0) as f32 >= cfg.required_score
           {
               Ok(StepOutput::Success(AuthenticatorSuccess::default()))
           } else {
               Ok(StepOutput::Failure(FailureKind::Rejected))
           }
       }
   }

   export_authn_provider!(CaptchaAuthn);
   ```

3. **Build.**

   ```sh
   cargo build --target wasm32-wasip2 --release
   ```

   Output: `target/wasm32-wasip2/release/geonosis_spi_captcha.wasm`
   (~ 350 KiB).

4. **Upload to your realm.**

   ```sh
   geoctl spi install \
     --realm acme \
     --interface geonosis:authn@0.1.0 \
     --alias acme-captcha \
     --module target/wasm32-wasip2/release/geonosis_spi_captcha.wasm \
     --config '{
       "secret_env":"HCAPTCHA_SECRET",
       "endpoint":"https://hcaptcha.com/siteverify",
       "required_score":0.7
     }' \
     --priority 200
   ```

   `--priority 200` puts it before the password step (priority
   1000 for the built-in).

5. **Bind it into the `browser` flow.**

   Edit `geoctl flows edit --realm acme --alias browser` and add
   a node with `provider: wasm:acme-captcha:authn` before the
   password step. See [`06-auth-flows.md`](../06-auth-flows.md)
   §Authenticators.

## Verifying

```sh
docker run --rm --network host \
  ghcr.io/hosnian-prime/geonosis-quickstart-helper login --realm acme --user ada
```

The helper now displays a captcha challenge before the password
prompt. Audit log emits:

```sh
geoctl audit list --realm acme --action 'spi.*'
```

includes `spi.module_recompiled` (on upload) and your captcha
processing's tracing spans (`spi.provider_urn=wasm:acme-captcha:authn`).

## Troubleshooting

- **`quarantined`** after upload — three consecutive trap/timeout
  failures auto-quarantine. Check `geoctl audit list --action
  spi.quarantined` and adjust your code or fuel/memory limits.
- **`http-client not authorized`** — the host capability is gated;
  your `Cargo.toml` and plugin's WIT world must import
  `host.http-client` (the SDK does this by default).
- **Captcha never appears** — your flow's `browser` graph might
  not include the new node. Re-export YAML, edit, re-import.

## See also

- [`07-spi-wasm.md`](../07-spi-wasm.md) — SPI host model, fuel
  limits, quarantine.
- [`06-auth-flows.md`](../06-auth-flows.md) — Flow editor + graph
  DSL.
