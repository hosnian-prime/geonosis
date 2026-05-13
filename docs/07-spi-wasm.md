# 07 — SPI: WebAssembly Extension Model

The **SPI** (Service Provider Interface) is how operators extend
Geonosis without forking it. The choice — agreed in the design
discussion — is **WebAssembly components** with **WASI 0.2**
interfaces declared in **WIT**. Modules run inside a per-pod
`wasmtime` engine, sandboxed, hot-reloadable, language-agnostic.

This document defines the host architecture, the WIT contracts, the
trust model, and the operational story.

## Why WASM (in one paragraph)

It's the only mainstream option that's simultaneously
**sandboxed at the instruction level**, **hot-swappable** (recompile
in-process, atomic table swap), **language-agnostic** (Rust, Go, JS,
Python, C/C++ all compile to WASM), and **performant enough** (single-
digit-percent overhead for the kinds of work an authenticator does).
Dynamic libraries are faster but unsafe and operationally painful;
sidecars are operationally fine but every call is a network hop. WASM
lands cleanly in the middle of the trade-off triangle.

## Engine layout

```
                            geonosis-spi-host
                  ┌─────────────────────────────────────┐
                  │  Wasmtime Engine (shared)           │
                  │   - linker preconfigured with WASI  │
                  │   - module compilation cache (disk) │
                  └─────────────────────────────────────┘
                            │
                            ▼
       ┌─────────────────────────────────────────────────┐
       │  per-realm SpiRegistry                          │
       │   { interface → [Provider]  ordered by priority │
       │     provider: { module_id, config, instance? } }│
       └─────────────────────────────────────────────────┘
                            │
                ┌───────────┴────────────┐
                ▼                        ▼
       per-realm pools           per-call instances
       (long-lived stores)       (short-lived stores)
```

- **Engine is shared** across all realms and modules: amortizes JIT
  cost and code cache. Configured with epoch-based interruption +
  fuel for safety.
- **Per-realm `SpiRegistry`** indexes providers by interface name.
- **Stores** (Wasmtime's per-instance state) are pooled for hot
  interfaces (authenticators, mappers) to avoid instantiation cost.
  Pool entries have **bounded reuse** (epoch + memory limits) and are
  destroyed when stale.
- **Authoritative invalidation** flows through `pg_notify`; uploading
  a new module bumps the registry on every pod.

## Sandbox & resource limits

Per-call defaults, configurable per realm:

- **Fuel:** 50 million units (a complex mapper takes ~1M).
- **Memory cap:** 32 MiB.
- **Wall-clock timeout:** 200 ms for synchronous authn/mapper steps;
  2 s for federation steps; 5 s for sync jobs.
- **No filesystem.** No `wasi:filesystem` permissions are granted by
  default. A future `geonosis:storage` interface mediates persistence.
- **No outbound network** by default. A future
  `geonosis:http-client@0.1.0` interface gates outbound HTTP through
  an explicit allowlist plus connection pool that the host owns.
- **Random and clock** from WASI but the clock is monotonic-only for
  determinism in tests.
- **No CPU pinning, no threads** beyond what the component itself
  declares. Wasmtime epoch interruption preempts.

A misbehaving module hits a limit → host returns
`ProviderError::ResourceExceeded` to the calling code path, which
the flow handles per the node's failure semantics (typically:
quarantine the provider after N consecutive failures).

## Compilation cache

Modules are stored as `*.wasm` bytecode in object storage (or DB blob
for small ones). On first use per pod:

1. Hash check vs. in-memory cache.
2. Compile with `wasmtime`, persist the resulting `cwasm` to local
   disk under `/var/cache/geonosis/spi/{sha256}.cwasm`.
3. Next start, deserialize from disk (microseconds).

This means a rolling restart of a pod doesn't re-JIT every plugin.

## Defined WIT worlds

WIT files live in `wit/` at the repo root and are versioned per
interface. Plugin authors depend on `geonosis-spi-api`, which
re-exports the generated bindings.

### `geonosis:authn@0.1.0`

```wit
package geonosis:authn@0.1.0;

interface authenticator {
  use types.{flow-context, step-input, step-output, error};

  /// Returns provider metadata (display name, supported configs).
  describe: func() -> provider-info;

  /// Process one step. Pure-ish; side effects through provided host APIs.
  process: func(
      ctx: flow-context,
      input: step-input,
      config: list<u8>,
  ) -> result<step-output, error>;
}

world authn-provider {
  import host: geonosis:host/v0.1.0;
  export authenticator;
}
```

`step-output` mirrors the built-in `AuthenticatorOutput`:
`success | continue | skip | failure`.

### `geonosis:mapper@0.1.0`

Transforms claims for id/access tokens or first-login users.

```wit
package geonosis:mapper@0.1.0;

interface mapper {
  use types.{mapper-context, claim-set, error};

  describe: func() -> provider-info;

  /// Given current claims and mapper config, return the new claim-set.
  map-claims: func(
      ctx: mapper-context,
      input: claim-set,
      config: list<u8>,
  ) -> result<claim-set, error>;
}
```

### `geonosis:federation@0.1.0`

Custom user storage source.

```wit
interface user-source {
  find-by-username: func(realm: string, username: string)
      -> result<option<external-user>, error>;
  find-by-id: func(realm: string, id: string)
      -> result<option<external-user>, error>;
  validate-credential: func(realm: string, id: string, credential: credential)
      -> result<validation-result, error>;
  search: func(realm: string, query: search-query)
      -> result<search-page, error>;
}
```

### `geonosis:event@0.1.0`

Receive events (login.success, password.changed, federation.sync, ...).

```wit
interface event-listener {
  on-event: func(event: event) -> result<_, error>;
}
```

This is **fire-and-forget**. Errors are logged but do not affect the
triggering operation.

### `geonosis:broker-adapter@0.1.0`

Per-IdP behavior for non-generic providers (Google quirks, GitHub's
non-OIDC flow, Apple's `form_post` + private-relay email, etc.).
Used by the first-party plugins listed in
[`05-identity-broker.md`](./05-identity-broker.md).

```wit
package geonosis:broker-adapter@0.1.0;

interface broker-adapter {
  use types.{idp-config, authn-request, raw-callback,
             broker-assertion, claim-set, error};

  describe: func() -> provider-info;

  /// Build the URL to redirect the user-agent to, given a fresh
  /// state/nonce and the realm's bound IdP config.
  build-authn-url: func(
      req: authn-request,
      config: idp-config,
  ) -> result<string, error>;

  /// Parse the inbound callback (query string for redirect,
  /// form body for form_post) into a normalized raw assertion.
  parse-callback: func(
      raw: raw-callback,
      config: idp-config,
  ) -> result<broker-assertion, error>;

  /// Validate signatures, audience, nonce, freshness. Plugin
  /// reports its findings; core enforces top-level invariants too.
  validate-assertion: func(
      assertion: broker-assertion,
      config: idp-config,
  ) -> result<broker-assertion, error>;

  /// Optional enrichment step: pull `/user`-style endpoints,
  /// merge with assertion, produce a final claim set the rest of
  /// the broker pipeline consumes.
  enrich-claims: func(
      assertion: broker-assertion,
      config: idp-config,
  ) -> result<claim-set, error>;
}

world broker-adapter-provider {
  import host: geonosis:host/v0.1.0;   // logging, http-client, secrets
  export broker-adapter;
}
```

Resource limits for adapter calls are higher than for inline-flow
SPIs (network round-trip expected): default 5 s timeout, 100 MiB
peak memory, fuel cap 500 million.

### `geonosis:policy@0.1.0`

Decision points the server consults (e.g. "is this client allowed
this scope right now?").

```wit
interface policy {
  evaluate: func(decision-point: string, ctx: policy-context)
      -> result<policy-decision, error>;
}
```

### Host interface — `geonosis:host@0.1.0`

What the host gives plugins back. Kept tiny and explicit; no surprise
capabilities.

```wit
interface logging {
  log: func(level: log-level, msg: string);
}

interface secrets {
  /// Read a secret declared in the provider's config under a named key.
  /// The host knows the binding; the plugin never sees raw env or files.
  read: func(key: string) -> result<list<u8>, error>;
}

interface http-client {
  /// Allowlisted HTTP egress; bodies <= 1 MiB.
  request: func(req: http-request) -> result<http-response, error>;
}
```

Plugins only see hosts they import; the linker rejects imports not
declared in the registered world.

## Authoring a plugin (Rust)

```toml
# Cargo.toml
[package]
name = "my-authn-provider"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
geonosis-spi-api = "0.1"
```

```rust
use geonosis_spi_api::authn::*;

struct MyProvider;

impl Authenticator for MyProvider {
    fn describe() -> ProviderInfo {
        ProviderInfo {
            id: "acme-magic".into(),
            display_name: "Acme Magic Auth".into(),
            config_schema: include_str!("config.schema.json").into(),
        }
    }

    fn process(ctx: FlowContext, input: StepInput, cfg: &[u8])
        -> Result<StepOutput, ProviderError>
    {
        // ...
    }
}

export_authn_provider!(MyProvider);
```

Build: `cargo build --target wasm32-wasip2 --release`.
Output: `target/wasm32-wasip2/release/my_authn_provider.wasm`.

Upload to a realm:

```sh
geoctl spi install \
  --realm acme \
  --interface geonosis:authn@0.1.0 \
  --alias acme-magic \
  --module target/wasm32-wasip2/release/my_authn_provider.wasm \
  --config provider.toml
```

## Configuration schema

Each provider declares a JSON Schema for its config. The admin UI
renders a form from the schema; validation happens at install time
and on every read. The compiled config bytes are passed to `process`
so plugins don't re-parse on every call.

## Versioning

- WIT interfaces are versioned: `geonosis:authn@0.1.0`, `0.2.0`, ...
- A plugin declares the **world** it implements. Host accepts plugins
  for any supported world; if a plugin's world is unsupported, install
  fails with a clear error.
- Geonosis MAY ship two adjacent versions of a world simultaneously
  during a deprecation window (e.g. `authn@0.1.0` and `authn@0.2.0`).

## Trust model

Plugins are **operator code, not user code**. Only realm admins (or
master-realm admins, depending on policy) can install. The sandbox
exists to prevent a buggy plugin from taking down a pod, not to
defend against a malicious plugin uploaded by an attacker who already
has admin rights.

Recommended operator practice (documented in
[`12-security-crypto.md`](./12-security-crypto.md)):

- Sign plugins out-of-band; configure Geonosis with a public key
  allowlist (`spi.signature_keys`).
- Review the WIT world a plugin imports; reject plugins that import
  `http-client` if the operator doesn't expect outbound calls.

## Failure handling

- **Hard fail in `describe()`** → install rejected.
- **Resource exceeded in `process()`** → returned as `ProviderError`
  to caller. If three consecutive calls fail with `ResourceExceeded`,
  the provider is marked `Quarantined` and skipped; an alert is
  raised; flows degrade per `requirement` semantics.
- **Trap (WASM panic)** → caught by `wasmtime`, same handling as
  `ResourceExceeded`.

## Observability

For every plugin call we emit a tracing span with:

- `spi.interface`, `spi.provider_alias`, `spi.module_sha256`
- `spi.fuel_consumed`, `spi.memory_peak_bytes`
- `spi.outcome` (`success` / `error_kind`)

Metrics: `geonosis_spi_call_duration_seconds`,
`geonosis_spi_call_total{interface,outcome}`,
`geonosis_spi_quarantined_total`.

## Non-goals

- **Browser-side plugins.** The admin UI is themable but not
  WASM-pluggable from the browser. Customization on the server
  produces customized rendered output.
- **Multi-language SDKs in v0.1.** Only `geonosis-spi-api` (Rust)
  ships in v0.1. Go (`geonosis-spi-go`, TinyGo) and JavaScript
  (`geonosis-spi-js`, ComponentizeJS) SDKs follow in v0.2.
- **Distributed plugin coordination** — plugins are pure (or read
  state via host APIs). They don't have their own cluster state.

## Decisions and open items

- **Authoring SDKs**: Rust v0.1; Go (TinyGo) + JS/TS
  (ComponentizeJS) v0.2; Python deferred. WIT contracts are the
  same across languages — SDKs are convenience layers.
- **Module store**: Postgres `bytea` for v0.1 (simple, ACID,
  cluster-trivial). An S3-backed store with Postgres metadata rows
  ships behind a feature flag in the same release; operators with
  many large plugins enable it.
- **Default fuel budgets** (placeholders; calibrated during Phase 1
  bench work):
  - `authn`, `mapper`, `policy`: 50 M fuel, 200 ms wall, 32 MiB
  - `event`: 10 M fuel, 100 ms wall, 16 MiB
  - `broker-adapter`: 500 M fuel, 5 s wall, 100 MiB (network)
  - `federation` (custom user-storage): 200 M fuel, 2 s wall, 64 MiB
- **`epoch_interruption_period`**: 1 ms ticks. Re-evaluate during
  benchmarks.
