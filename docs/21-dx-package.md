# 21 — Developer Experience Package

A deliberate, scoped commitment to **what an outside developer
encounters in the first 30 minutes** of meeting Geonosis. Bad DX
loses adoption regardless of the back-end's quality; we treat DX
as a first-class deliverable, not a documentation afterthought.

## What's in the package

| Asset | Time-to-success target | Phase |
|---|---|---|
| **5-minute quickstart** — single `docker run` + 3 cURL commands to a working OIDC token | 5 min | v0.1 |
| **Framework example apps** — minimal, working integration in four ecosystems | 15 min each | v0.1 (2 apps) + v0.2 (2 apps) |
| **Task-oriented docs** — recipes ("How do I add MFA?", "How do I add a custom claim?") | n/a | v0.1 / v0.2 |
| **`geonosis-verify` crate** — embeddable JWT validator + JWKS cache for any Rust service | n/a | v0.2 |
| **OpenAPI spec** for the admin REST API + auto-generated SDKs | n/a | v0.2 |
| **Postman / Bruno collection** | n/a | v0.2 |
| **Test-mode realms** — disposable, opt-in realms with synthetic data | 1 min | v0.2 |
| **Migration guides** from incumbent IAMs (concept-mapping, no automated converter) | n/a | v0.2 |

## The 5-minute quickstart (v0.1)

The single-page document `docs/quickstart/README.md` (published at
GA) walks a developer through:

1. `docker run` Geonosis with a one-shot bootstrap realm + admin user.
2. Visit `http://localhost:8080/admin` — login as the bootstrap admin.
3. Create a client `my-app` via UI or one cURL POST.
4. `cURL` the discovery doc, the `/authorize` (gets a login page),
   complete a manual login, exchange the code at `/token`, decode
   the JWT.
5. Read `userinfo`.

Target: a developer with no prior Geonosis knowledge has a token in
hand within 5 minutes. The Docker image bootstraps everything
(Postgres included for the quickstart only; with a `compose.yml`).

The bootstrap path **never** runs in production. It's gated by an
explicit `GEONOSIS_BOOTSTRAP_QUICKSTART=1` env var that the
production Helm chart never sets.

## Framework example apps

Living at `examples/` in the main repo (not separate repos — bumped
in lockstep with the server release):

| Phase | Example | Stack |
|---|---|---|
| v0.1 | `examples/nextjs-app/` | Next.js 15 + Auth.js (OIDC provider config for Geonosis) |
| v0.1 | `examples/axum-resource-server/` | Rust axum API + `geonosis-verify` JWT validation |
| v0.2 | `examples/sveltekit-app/` | SvelteKit + Lucia/native OAuth |
| v0.2 | `examples/fastapi-resource-server/` | Python FastAPI + Authlib |
| v0.3 | `examples/spring-boot-app/` | Java Spring Boot + Spring Security OAuth2 (for migration audiences) |
| v0.3 | `examples/django-app/` | Django + django-allauth |

Each example app:

- Boots against the same `compose.yml` Geonosis used in the
  quickstart.
- Has a README with **exact** commands.
- Includes a screenshot at the end of "what success looks like".
- Has a `bin/test.sh` that runs an end-to-end smoke against the
  quickstart Geonosis. CI runs all of them on every PR.

We deliberately keep these tiny. The point isn't a reference app;
it's a *cargo-cult-able* starting point.

## Task-oriented recipes

Companion to the architecture docs: a `docs/recipes/` directory
with focused, ≤ 500-word how-to documents:

- "How do I add a custom claim to every token issued for client X?"
- "How do I configure step-up MFA for sensitive endpoints?"
- "How do I provision users from Entra ID via SCIM?"
- "How do I write a custom authenticator in Rust?"
- "How do I write a custom authenticator in Go (TinyGo) / JS?"
- "How do I federate users from an existing PostgreSQL `users` table?"
- "How do I rotate signing keys without breaking tokens in flight?"
- "How do I run Geonosis behind Caddy / nginx / Traefik / cert-manager?"
- "How do I migrate from an incumbent IAM realm export?"
- ...

Recipes ship with the docs and are linked from the relevant
architecture sections. They use real cURL / YAML / Rust snippets —
no pseudocode.

## `geonosis-verify` (v0.2 separately-published crate)

A small Rust crate published to crates.io, independent of the
server binary:

```rust
use geonosis_verify::{Verifier, VerifierConfig};

let verifier = Verifier::builder()
    .issuer("https://geonosis.example.com/realms/acme")
    .audience("my-resource-api")
    .cache_jwks(Duration::from_secs(900))
    .build()
    .await?;

let claims = verifier.verify(bearer_token).await?;
println!("user = {}", claims.sub);
```

- Lazy-loads JWKS from the `/jwks` endpoint, caches it.
- Verifies `iss`, `aud`, `exp`, `nbf`, signature.
- Supports DPoP-bound (v0.2) and mTLS-bound (v0.2) tokens.
- Supports `act` chain unwrapping for agent tokens
  (see [`18-agent-identity.md`](./18-agent-identity.md)).
- Optional `introspect` fallback for opaque tokens.
- Zero external runtime deps beyond `reqwest` + `josekit`.
- Suitable for Cloudflare Workers (WASM target), Lambda, edge
  validators.

The verifier becomes a network-effect lever: every Rust service
that consumes Geonosis tokens uses our crate, by default. Plays
into the Komino + Rust-everywhere story.

## OpenAPI + SDKs

The admin REST API (`/admin/v1/*`) is built with `utoipa` annotations
on every handler; CI generates `openapi.yaml`. From the spec we
publish (v0.2):

- TypeScript SDK (`@geonosis/admin-sdk`)
- Python SDK (`geonosis-admin`)
- Go SDK (`github.com/hosnian-prime/geonosis-go`)
- Rust SDK (`geonosis-admin-client`)

SDKs are **strictly thin**: just typed wrappers over the REST API.
The "thick client" logic (token refresh, retry, pagination) lives in
the SDKs. They are auto-generated; we don't hand-maintain them
beyond template improvements.

## Test-mode realms (v0.2)

A `geoctl realm create --kind test --auto-seed` creates a realm
with:

- 20 pre-seeded users (predictable emails like `alice@test.local`,
  passwords known).
- 3 sample clients (browser SPA, SSR app, resource API).
- A pre-built `browser` flow with optional MFA on a flag.
- Auto-purge after N days unless `--persistent`.

Test-mode realms are explicitly flagged in the admin UI ("⚠ Test
mode — synthetic data, not for production") and ineligible for
production audit-event retention SLAs.

## Docs site

Beyond the in-repo docs:

- v0.2: `docs.geonosis.dev` (or whatever the domain becomes) —
  Docusaurus-style site rendering the same Markdown plus the
  OpenAPI surface plus the recipes.
- v0.2: Algolia search across the docs (or equivalent).
- v0.3: interactive playground (run a one-off ephemeral
  Geonosis-in-WASM in the browser, send sample requests).

## Phase mapping summary

| Asset | v0.1 | v0.2 | v0.3 |
|---|---|---|---|
| 5-minute quickstart | ✅ | refine | refine |
| Next.js example | ✅ | | |
| axum resource-server example | ✅ | | |
| SvelteKit example | | ✅ | |
| FastAPI example | | ✅ | |
| Spring Boot example | | | ✅ |
| Django example | | | ✅ |
| Recipes set 1 (10 most common) | ✅ | grow | grow |
| `geonosis-verify` crate | | ✅ | DPoP/mTLS support polished |
| OpenAPI + 4 SDKs | | ✅ | |
| Test-mode realms | | ✅ | |
| Docs site | | ✅ | playground |

## SOLID notes

The DX package itself is a UX surface, not a software module, but
the underlying choices follow SOLID:

- **Single Responsibility**: the quickstart Docker image bootstraps
  ONLY the quickstart use case; production Helm chart doesn't.
  Test-mode realms ARE realms (no parallel concept) flagged with a
  realm attribute.
- **Open/Closed**: example apps and recipes are content;
  contributions extend without changing core. Adding a new framework
  example is a new directory, not a core change.
- **Liskov**: SDKs implement the same admin REST contract; switching
  language doesn't change semantics.
- **Interface Segregation**: `geonosis-verify` exposes only what a
  resource server needs; it doesn't import server-side code.
- **Dependency Inversion**: SDKs depend on the OpenAPI contract,
  not on internal server types. Generated, not hand-coupled.

## Non-goals

- **A managed dev-account on geonosis.cloud** — that's part of
  [`22-cloud-offering.md`](./22-cloud-offering.md), separate
  product surface.
- **Drag-and-drop integration builder** — recipes are text; this
  isn't a low-code product.
- **AI-generated integration code** — out of scope here; if we
  ship anything like that it goes through the same recipe
  format.

## Decisions and open items

- **Quickstart Docker image** bundles Postgres for first-run
  convenience; production Helm chart never does. Bootstrap
  realm creation is gated by `GEONOSIS_BOOTSTRAP_QUICKSTART=1`.
- **`geonosis-verify` crate** publishes independently of the
  server binary so resource servers don't track server release
  cadence.
- **SDKs** are auto-generated from the OpenAPI spec; we don't
  hand-maintain language-specific clients beyond template tuning.
- **Example app repos**: stay in-tree under `examples/`; bumped
  in lockstep with the server release.
- **Recipe count promise**: 10 in v0.1 (the most common operator
  tasks), 10 more in v0.2, growing organically thereafter.
