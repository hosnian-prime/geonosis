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

## Provider registry & override patterns

This section is the **central principle** of Geonosis's extension
model. It is what lets operators **replace** any built-in subsystem
with their own, not just **add** new providers alongside them.

### The principle: built-ins are plugins

Every customizable subsystem in Geonosis is mediated by a **Provider
trait**. The trait has both:

- **Rust-native implementations** (the "built-ins" we ship — e.g.
  `LocalUserStorage`, `BuiltinPasswordAuthn`, `BuiltinGroupsMapper`,
  the LDAP federation source).
- **WASM-backed implementations** dispatched via wit-bindgen
  (operator-supplied modules).

They live in **the same per-realm registry** under stable
**provider URNs**. The registry is a priority-sorted list of
enabled providers. Built-ins and WASM impls are indistinguishable
to the dispatcher.

Concretely, in Rust:

```rust
#[async_trait]
pub trait UserStorageProvider: Send + Sync {
    fn urn(&self) -> &str;                         // stable id
    fn capabilities(&self) -> ProviderCapabilities;

    async fn find_by_username(
        &self,
        realm: RealmId,
        username: &str,
        config: &Bytes,
        cx: &ProviderContext,
    ) -> Result<LookupOutcome<ExternalUser>, ProviderError>;

    async fn find_by_id(/* ... */)    -> Result<LookupOutcome<ExternalUser>, ProviderError>;
    async fn find_by_email(/* ... */) -> Result<LookupOutcome<ExternalUser>, ProviderError>;

    async fn validate_credential(/* ... */) -> Result<ValidationResult, ProviderError>;
    async fn search(/* ... */) -> Result<SearchPage, ProviderError>;

    // Optional write capabilities (return Unsupported if read-only)
    async fn create_user(/* ... */) -> Result<ExternalUser, ProviderError>;
    async fn update_user(/* ... */) -> Result<ExternalUser, ProviderError>;
    async fn delete_user(/* ... */) -> Result<(), ProviderError>;
}

pub enum LookupOutcome<T> {
    Found(T),
    NotFound,         // "I don't handle this user; dispatcher: try next"
}

pub struct ProviderRegistry<T: ?Sized> {
    realm_id: RealmId,
    /// priority-asc; lower priority value = higher precedence.
    /// Both built-ins and WASM providers live here.
    providers: Vec<RegisteredProvider<T>>,
}

pub struct RegisteredProvider<T: ?Sized> {
    pub urn: String,
    pub priority: i32,
    pub enabled: bool,
    pub config: Bytes,
    pub inner: Arc<T>,
    pub origin: ProviderOrigin,                    // Builtin | Wasm { module_id, alias }
}
```

The built-in `LocalUserStorage` is just another `Arc<dyn
UserStorageProvider>` in the registry, registered at realm seed
time with `priority = 1000` and `enabled = true`. A WASM custom
store registered with `priority = 100` runs **before** the local
store; if it returns `NotFound`, the dispatcher moves on to the
local store.

### Dispatch semantics (fixed per interface)

Each interface declares **one** dispatch mode. The mode is part of
the interface contract — operators don't pick.

| Interface | Dispatch | Semantics |
|---|---|---|
| `user-storage` | **FirstMatch** | Run providers in priority order until one returns `Found`. |
| `authn` | **NamedSelect** | A flow node names the provider by URN; no chain. |
| `mapper` | **Chain** | All enabled providers run in priority order; each transforms the claim set. |
| `event-listener` | **ChainFireForget** | All enabled fire-and-forget in priority order; errors logged but do not stop the chain. |
| `policy` | **FirstDecision** | First non-`Abstain` decision wins. |
| `broker-adapter` | **NamedSelect** | An IdP names its adapter by URN. |
| `user-profile-validator` | **NamedAttach** | Bound to specific attributes by name. |
| KMS (`KeyManagementService`) | **Single** | One active backend per realm. |

`NamedSelect` means *the configuration explicitly names which
provider to invoke*. Override here is "operator points the binding
at a different URN". No priority ordering at runtime.

### The three override patterns, expressed via the registry

Every override an operator can perform in our reference IAM maps
to one of three operations on the registry:

#### 1. Augment (add alongside built-ins)

The default, simplest case. Install a WASM provider; it joins the
priority list. Built-ins remain enabled.

Example: a custom `geonosis:event` listener that streams audit
events to a SIEM. Just add it.

#### 2. Replace (disable the built-in, add a custom one)

Two equivalent ways to express this:

- **Soft replace**: install a custom provider with a more
  precedent priority and have it return `Found` for every relevant
  query. (Works but the built-in still wastes a query when the
  custom returns `NotFound`.)
- **Explicit replace**: set the new binding's
  `replaces = Some("builtin:user-storage:local")`. The registry
  enforces: as long as the replacement binding is enabled, the
  target binding is treated as `enabled = false` regardless of its
  stored flag.

Use `replaces` when the intent is "the built-in is no longer
authoritative; do not consult it".

#### 3. Decorate (run before; conditionally fall through)

The provider acts as middleware: do some work, then either return
`Found` (short-circuit) or `NotFound` (delegate to the rest of
the chain).

In Rust this requires no special middleware abstraction —
`NotFound` is already the "delegate" signal. The chain dispatcher
does the rest. A WASM author writes:

```rust
fn find_by_username(realm, username, cfg, cx) -> LookupOutcome<ExternalUser> {
    if !cx.matches(cfg.handled_prefix(username)) {
        return LookupOutcome::NotFound;       // not mine — delegate
    }
    let user = my_external_call(realm, username)?;
    LookupOutcome::Found(user)
}
```

For interfaces where the next-in-chain call must happen mid-logic
(true Tower-style middleware), the WIT contract exposes a host
function `host.dispatch_next(args) -> result`. This is reserved for
the `mapper` interface, where transforming a claim set before/after
the chain is a real use case. Other interfaces don't need it.

### Provider URN scheme

All providers — built-in and WASM — have a stable URN. The
dispatcher, the admin UI, the audit log, and the cache key all
agree on this string.

```
builtin:{interface-short}:{provider-name}[:{instance-alias}]
wasm:{module-alias}:{export-name}
```

Examples:

| URN | What |
|---|---|
| `builtin:user-storage:local` | The Postgres-backed local user store |
| `builtin:user-storage:ldap:corp-ad` | An LDAP/AD federation source aliased `corp-ad` (one per source) |
| `builtin:authn:password` | The password authenticator |
| `builtin:authn:otp-totp` | TOTP authenticator |
| `builtin:authn:webauthn` | WebAuthn authenticator |
| `builtin:authn:idp-redirect` | Built-in broker redirect authenticator |
| `builtin:mapper:claim-from-attribute` | Default attribute-to-claim mapper |
| `builtin:mapper:realm-role` | Default `realm_access.roles` mapper |
| `builtin:mapper:client-role` | Default `resource_access` mapper |
| `builtin:mapper:groups` | Default `groups` claim mapper |
| `builtin:event:postgres-audit` | Built-in audit-event writer |
| `builtin:event:webhook` | Built-in webhook event sink |
| `builtin:policy:default-scope-policy` | The default scope-grant policy |
| `builtin:broker-adapter:oidc-generic` | Generic OIDC IdP adapter |
| `builtin:broker-adapter:saml-generic` | Generic SAML 2.0 SP adapter |
| `wasm:acme-custom-store:user-storage` | A third-party WASM user-storage module |
| `wasm:spi-google:broker-adapter` | The first-party Google broker-adapter plugin |

URNs are case-folded, `[a-z0-9:-]+`, max 128 chars. The
`builtin:` namespace is **reserved** — WASM modules cannot register
under it. This prevents a malicious uploader from impersonating a
built-in.

### The `SpiBinding` row, revisited

```rust
pub struct SpiBinding {
    pub id: SpiBindingId,
    pub realm_id: RealmId,
    pub interface: WitInterfaceName,        // e.g. "geonosis:user-storage@0.1.0"
    pub provider_urn: String,               // stable id (built-in or wasm)
    pub priority: i32,                      // smaller = earlier
    pub enabled: bool,
    pub config: serde_json::Value,
    pub replaces: Option<String>,           // forcibly disables this URN
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

Realm seed inserts the built-in bindings. Subsequent operator
edits adjust `priority`, flip `enabled`, set `config`, or add
WASM bindings with their own URN.

### Loading the registry

At realm load (or on `NOTIFY`-triggered invalidation):

```rust
async fn build_user_storage_registry(realm: &Realm) -> ProviderRegistry<dyn UserStorageProvider> {
    let bindings = storage.list_spi_bindings(realm.id, "geonosis:user-storage@0.1.0").await?;
    let mut providers = Vec::new();
    let mut replaced: HashSet<&str> = HashSet::new();

    for binding in &bindings {
        if let Some(target) = &binding.replaces {
            if binding.enabled { replaced.insert(target.as_str()); }
        }
    }

    for binding in bindings {
        if !binding.enabled { continue; }
        if replaced.contains(binding.provider_urn.as_str()) { continue; }

        let provider: Arc<dyn UserStorageProvider> = match binding.origin() {
            ProviderOrigin::Builtin => builtin_factory(&binding.provider_urn, &binding.config)?,
            ProviderOrigin::Wasm    => wasm_factory(&binding.provider_urn, &binding.config).await?,
        };

        providers.push(RegisteredProvider {
            urn: binding.provider_urn,
            priority: binding.priority,
            enabled: true,
            config: binding.config.into(),
            inner: provider,
            origin: binding.origin(),
        });
    }

    providers.sort_by_key(|p| p.priority);
    ProviderRegistry { realm_id: realm.id, providers }
}
```

The registry itself is cached (see [`09-cache-invalidation.md`](./09-cache-invalidation.md))
under `spi/{realm}`; admin edits issue a NOTIFY and pods rebuild
their registry within the usual envelope.

### Admin UI affordances

The admin UI presents one **integrated list per interface** with
both built-ins and WASM providers, an explicit visual marker for
built-ins, drag-to-reorder for priority, and a per-row "replace"
indicator showing which built-in (if any) is shadowed.

Disabling the last enabled user-storage provider raises a
**confirmation modal** ("no user storage will be active; logins
will fail until you re-enable or add a provider"). The admin API
returns `409 conflict` if the operator confirms-then-disables-all.

### Worked example: replacing the local user store with a REST-based store

Operator goal: keep users in their existing company-internal user
service (REST API), bypass the built-in Postgres-backed
`app_user` table entirely for one realm.

1. Operator builds a WASM module against the
   `geonosis:user-storage@0.1.0` WIT contract. Module exports the
   six required functions; uses `host.http-client` for outbound
   calls. Build target `wasm32-wasip2`.
2. Operator uploads the module via admin API or
   `geoctl spi install --realm master --module ... --alias acme-internal-store`.
3. Operator adds a binding:
   ```yaml
   interface: geonosis:user-storage@0.1.0
   provider_urn: wasm:acme-internal-store:user-storage
   priority: 100
   enabled: true
   replaces: builtin:user-storage:local
   config:
     base_url: "https://users.acme.internal"
     auth_header_secret: { secret_ref: "INTERNAL_USERS_API_KEY" }
   ```
4. On save, NOTIFY fans out. Every pod rebuilds its user-storage
   registry: `builtin:user-storage:local` is excluded (replaced);
   the WASM provider is the only enabled entry.
5. Subsequent logins resolve users via the WASM provider's
   `find_by_username` / `validate_credential` calls. The
   `app_user` table sees no traffic.
6. To roll back: disable the WASM binding (or re-enable
   `builtin:user-storage:local` by clearing `replaces`). The
   change propagates in under 100 ms via NOTIFY.

### Worked example: chaining a captcha BEFORE the built-in password authenticator

1. Operator builds a `geonosis:authn` provider performing captcha
   validation; uploads as `wasm:acme-captcha:authn`.
2. In the realm's `browser` flow, the password node is replaced by
   a `sequence` of:
   - `wasm:acme-captcha:authn` step (configured to require captcha)
   - `builtin:authn:password` step
3. No registry override — the flow editor names the providers
   by URN. The dispatcher mode for `authn` is `NamedSelect`, so
   priority is irrelevant; the flow's ordering wins.

### Why this design (the trade-offs)

- **Built-ins-as-plugins** means the operator's mental model is
  one list, not "built-in vs. extension". The admin UI is simpler.
- **`replaces`** is enforced by the registry, not by external
  convention. Replacing a built-in cannot be done by accident, and
  cannot leave both the built-in and a custom provider racing.
- **Dispatch mode is per-interface, not per-binding**. Operators
  configure priority/enabled/config; the dispatch behavior is a
  contract. This prevents the "I set this to FirstMatch and now
  events stopped firing" class of misconfiguration.
- **No runtime cross-language inheritance**. A WASM module can't
  subclass a built-in; it implements the WIT contract. Decoration
  is expressed by a higher-priority provider returning `NotFound`
  when it doesn't handle the case. This is honest in the type
  system.
- **`Single`-dispatch interfaces** still benefit from the registry
  because swapping the active provider becomes an audited admin
  action with `replaces`, not a hidden config flag.

### Backwards-compatibility & migration

WIT contracts are versioned (`@0.1.0`, `@0.2.0`). The host MAY
support two adjacent versions of the same interface concurrently.
A binding declares the version it targets; the registry handles
both. When a WIT version is deprecated and removed, bindings on
the old version surface a `deprecated` warning in the admin UI
during the grace window.

### Open

- **Middleware host call** (`host.dispatch_next`) for the `mapper`
  interface — designed; implementation pencilled for Phase 4
  with the SPI host work. Other interfaces don't need it in v0.1.
- **Cross-realm built-in defaults**: should an operator be able to
  set a cluster-wide "all new realms get this WASM by default"?
  Considered, deferred to v0.2 (it's a master-realm-level binding
  policy).
- **Provider hot-rollback**: if a newly-installed WASM provider
  causes errors, fall back to the previous binding state. v0.2
  candidate; v0.1 has explicit disable.

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
  import host: geonosis:host@0.1.0;
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

### `geonosis:user-storage@0.1.0`

The unified user-storage contract. Both **the built-in local
store** and **operator-supplied custom stores** (REST, SCIM, LDAP,
mainframe IMS, anything) implement this interface. Dispatch mode:
**FirstMatch**.

```wit
package geonosis:user-storage@0.1.0;

interface user-storage-provider {
  use types.{external-user, user-draft, user-patch, credential,
             validation-result, search-query, search-page,
             credential-info, error};

  describe: func() -> provider-info;

  // Lookup (read)
  find-by-username: func(realm: string, username: string) -> result<lookup-outcome, error>;
  find-by-id:       func(realm: string, id: string)       -> result<lookup-outcome, error>;
  find-by-email:    func(realm: string, email: string)    -> result<lookup-outcome, error>;

  // Credential validation
  validate-credential: func(realm: string, id: string, credential: credential)
      -> result<validation-result, error>;
  list-credentials: func(realm: string, id: string)
      -> result<list<credential-info>, error>;

  // Optional admin / write capabilities
  create-user: func(realm: string, draft: user-draft) -> result<external-user, error>;
  update-user: func(realm: string, id: string, patch: user-patch) -> result<external-user, error>;
  delete-user: func(realm: string, id: string) -> result<_, error>;

  search: func(realm: string, query: search-query) -> result<search-page, error>;
}

variant lookup-outcome {
  not-found,                          // delegate to next provider in chain
  found(external-user),
}

world user-storage-provider-world {
  import host: geonosis:host@0.1.0;
  export user-storage-provider;
}
```

Providers that don't support a write operation return
`error.kind=unsupported` instead of implementing it. The admin UI
honors capability flags from `describe()` to grey out unsupported
actions.

### `geonosis:event@0.1.0`

Receive events (login.success, password.changed, federation.sync, ...).

```wit
interface event-listener {
  on-event: func(event: event) -> result<_, error>;
}
```

This is **fire-and-forget**. Errors are logged but do not affect the
triggering operation.

### `geonosis:user-profile-validator@0.1.0`

Per-attribute custom validators invoked by the
[`16-user-profile.md`](./16-user-profile.md) validator chain.
Bound to specific attribute names by the `UserProfile`'s
`AttributeValidator::Custom { module, config }` variant. **Phase:
v0.1**.

```wit
package geonosis:user-profile-validator@0.1.0;

interface validator {
  use types.{validation-error};

  describe: func() -> provider-info;

  validate: func(
      attribute: string,
      values: list<string>,
      config: list<u8>,
  ) -> result<_, validation-error>;
}

world user-profile-validator-world {
  import host: geonosis:host@0.1.0;
  export validator;
}
```

### `geonosis:ui-component@0.1.0`

Server-side admin / login UI component overrides. Bound at the
theme layer per [`08-admin-ui.md`](./08-admin-ui.md) §Component
overrides (themes). **Phase: v0.1.** Trait surface is the Leptos
`Surface` slot trait; the WIT contract here wraps the rendered
output.

```wit
package geonosis:ui-component@0.1.0;

interface ui-component {
  use types.{component-context, rendered-html, error};

  describe: func() -> component-info;

  /// Render the component to HTML given a typed locals payload.
  /// The host pre-sanitizes locals; output is appended into the
  /// page DOM at the slot's anchor with CSP nonces injected.
  render: func(
      slot: string,
      ctx: component-context,
      locals: list<u8>,                // bincode-encoded typed payload
  ) -> result<rendered-html, error>;
}

world ui-component-world {
  import host: geonosis:host@0.1.0;
  export ui-component;
}
```

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
  import host: geonosis:host@0.1.0;   // logging, http-client, secrets
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
  --realm master \
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

- `spi.interface`, `spi.provider_urn`, `spi.module_sha256`
- `spi.fuel_consumed`, `spi.memory_peak_bytes`
- `spi.outcome` (`success` / `error_kind`)

Metrics: `geonosis_spi_call_duration_seconds`,
`geonosis_spi_call_total{interface,outcome}`,
`geonosis_spi_quarantined_total`.

## Future / deferred WIT interfaces

Placeholders kept here so 07 remains the authoritative SPI catalog.
Full signatures land with the phase they're committed to in
[`14-roadmap.md`](./14-roadmap.md).

### `geonosis:scim-mapper@0.1.0` (v0.2)

Per-target SCIM resource transform — runs on push (outbound) and on
receive (inbound). Used by [`19-scim.md`](./19-scim.md) for
sensitive-attribute masking, vendor-specific schema bending, etc.
Signature shape (preview):

```
describe: func() -> provider-info;
map-outbound: func(resource: list<u8>, config: list<u8>) -> result<list<u8>, error>;
map-inbound:  func(resource: list<u8>, config: list<u8>) -> result<list<u8>, error>;
```

### `geonosis:scim-target-auth@0.1.0` (v0.2)

Custom authentication for non-standard SCIM endpoints (AWS SigV4 on
private SCIM-like APIs, mTLS-token-bound endpoints, etc.). Signature
preview:

```
describe: func() -> provider-info;
prepare-request: func(req: http-request, config: list<u8>) -> result<http-request, error>;
```

### `geonosis:agent-attestation@0.1.0` (v0.2)

Validate the contents of an actor token before token exchange (e.g.
enforce a trusted attestation server's signature on the agent's
model name + version). Signature preview:

```
describe: func() -> provider-info;
attest: func(actor-token: list<u8>, config: list<u8>) -> result<attestation-result, error>;
```

### `geonosis:vc-issuer@0.1.0` (v0.3)

Verifiable Credentials issuance (SD-JWT VC / W3C VC). Lands with
the v0.3 protocol work; signature shape TBD.

### `geonosis:storage@0.1.0` (future)

Long-lived per-realm storage for plugins (key-value, append-only
log). Sandboxed; quota-bound; no direct filesystem access. Lands
when a real plugin needs it; not in v0.1 or v0.2.

### `geonosis:http-client@0.1.0` (future, currently inline in `geonosis:host`)

In v0.1, outbound HTTP is exposed as the `http-client` interface
**inside** the `geonosis:host@0.1.0` world (see Host interface
above). A future split into its own `geonosis:http-client` package
may happen if egress controls grow elaborate; the embedded shape
is intentional in v0.1 to keep host capabilities under one roof.

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
