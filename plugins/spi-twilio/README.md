# spi-twilio — Twilio SMS event listener

First-party Geonosis WASM plugin that turns audit events of shape
`{ action: "sms.send", detail: { to, body } }` into Twilio SMS sends.
The `phone-otp` built-in authenticator emits these whenever it issues
an OTP, so installing this plugin completes the phone-OTP flow without
modifying the authenticator.

## Why a separate plugin?

The audit's WS2.7 deliverable. Bundling Twilio (or any SMS vendor) into
the core binary would tie the OSS server to a commercial dependency.
Plugins keep the choice with the operator: install `spi-twilio`,
`spi-messagebird`, `spi-sns`, or write a custom one against the same
`geonosis:event@0.1.0` WIT contract.

## Build

```bash
rustup target add wasm32-wasip1
cargo install cargo-component
cd plugins/spi-twilio
cargo component build --release
```

Output: `target/wasm32-wasip1/release/spi_twilio.wasm`.

## Install

```bash
geoctl spi install \
  --realm master \
  --interface geonosis:event@0.1.0 \
  --alias spi-twilio \
  --module target/wasm32-wasip1/release/spi_twilio.wasm \
  --config '{"filter_action": "sms.send"}'
```

The realm's audit pipeline will now fan-out every event to this
listener alongside the Postgres + webhook sinks.

## Secrets

The plugin reads three operator-managed secrets via the host's
`geonosis:host/secrets` capability:

| Key | Value |
|-----|-------|
| `spi-twilio.account-sid` | Twilio Account SID |
| `spi-twilio.auth-token`  | Twilio Auth Token  |
| `spi-twilio.from`        | E.164 number Twilio sends from |

In v0.1 these are configured via the storage layer's `wasm_modules`
secret-blob mechanism; the `geoctl spi set-secret` command surfaces it
in v0.1.x.

## Audit shape this plugin reacts to

The plugin only acts on events whose top-level `action` field equals
`sms.send`. The `detail` payload MUST carry:

```json
{
  "action": "sms.send",
  "detail": {
    "to":   "+15558675309",
    "body": "Your Geonosis code: 871-329"
  }
}
```

Other actions pass through unchanged. Malformed events are logged at
warn level and dropped (fire-forget — never blocks the producing
request).

## Resource limits

Per `docs/07-spi-wasm.md` event-listener budget:

- Fuel: 10M
- Wall clock: 100 ms
- Memory: 16 MiB

A Twilio call takes ~150 ms in practice, so the host extends event
runtimes that need network I/O with the same wall-clock budget as
broker adapters (5 s) — controlled by `ResourceLimits::event()` vs
`broker_adapter()` at install time.
