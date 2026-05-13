# 08 — Admin UI and Theming (Leptos)

The admin UI is **embedded** in the `geonosis-server` binary and
rendered with [**Leptos**](https://leptos.dev/) using **SSR + island
hydration**. The same crate also drives the **login UI** (theme
templates) so customization is a single mental model.

## Two surfaces, one runtime

| Surface | Path | Audience |
|---|---|---|
| Login / consent / account-pages | `/realms/{slug}/login-actions/...` | end users |
| Admin console | `/admin/...` | realm admins, master admins |

Both are Leptos applications. They share component primitives
(buttons, forms, layout) but live in separate top-level modules
because their auth contexts and threat models differ.

## Why Leptos (rationale recap)

- **One language across the stack** — no separate Node toolchain, no
  TypeScript/Rust impedance mismatch.
- **Fine-grained reactivity** → small, fast hydration.
- **SSR-first** → embedded UI works without a build server, login
  pages stay fast for users on slow networks.
- **Component-as-trait** → operators override pieces without forking
  the whole UI.

The cost: smaller ecosystem than React. We mitigate by:

- Keeping the design system small and self-contained.
- Plain HTML form posts as the primary admin interaction (works
  without JS for everything except the flow editor).
- Documenting clearly which paths require hydration.

## Layered architecture

```
┌───────────────────────────────────────────────────────────┐
│                  geonosis-admin-ui (crate)                │
│                                                           │
│   ┌─────────────────────────────────────────────────┐     │
│   │  routes (server functions + Leptos routes)      │     │
│   │   - realms, users, clients, flows, themes, ...  │     │
│   └────────────────────────────┬────────────────────┘     │
│                                │                          │
│   ┌────────────────────────────▼────────────────────┐     │
│   │  view components                                │     │
│   │   - <UserTable/>, <ClientForm/>, <FlowEditor/>  │     │
│   │   - each is a `trait Component` impl            │     │
│   └────────────────────────────┬────────────────────┘     │
│                                │                          │
│   ┌────────────────────────────▼────────────────────┐     │
│   │  design system (geonosis-ui-kit)                │     │
│   │   - <Button/>, <Card/>, <Field/>, <Toast/>      │     │
│   │   - tokens (colors, spacing, type) via CSS vars │     │
│   └─────────────────────────────────────────────────┘     │
└───────────────────────────────────────────────────────────┘
            ▲                                ▲
            │                                │
   ┌────────┴────────┐              ┌────────┴────────┐
   │ geonosis-theme  │              │  admin server   │
   │  overlay engine │              │  fns (REST shim)│
   └─────────────────┘              └─────────────────┘
```

## Component overrides (themes)

A `Theme` is a directory with:

```
my-theme/
├── theme.toml                  # metadata
├── login/
│   ├── login.html              # optional plain template (Maud/Askama-style)
│   ├── otp.html
│   ├── overrides.rs.wasm       # optional Leptos component overrides (built)
│   └── assets/
│       ├── logo.svg
│       └── theme.css
└── email/
    ├── verify-email.html
    └── ...
```

Two override mechanisms:

1. **Template overlay** (the *Keycloak FreeMarker equivalent*):
   plain HTML/CSS, no recompile. Replaces a named page entirely.
   The renderer falls back through theme → parent-theme → built-in.
   Hot-reloadable by file watcher.
2. **Component override** (the *Leptos-native* path): an operator
   ships a Leptos component compiled to a WASM module exporting
   `geonosis:ui-component@0.1.0`. The renderer asks the registry
   for `LoginPasswordForm`; if the realm's theme provides one, it
   is used instead of the built-in. This is for non-trivial UIs
   (flow editor extensions, custom inputs).

Most operators will use only template overlays. Component overrides
are the power-user escape hatch.

## Slot-based component API

Every built-in page is decomposed into named slots. Slots are
declared in a `Surface` map and the theme can replace any slot
without redefining the page.

```rust
pub enum LoginPasswordSlot {
    Header,
    UsernameField,
    PasswordField,
    SubmitButton,
    BrokerList,
    Footer,
}

#[component]
pub fn LoginPassword<S: Surface>(s: S) -> impl IntoView {
    view! {
        <div class="auth-card">
            <S::Render slot=LoginPasswordSlot::Header />
            <form method="post">
                <S::Render slot=LoginPasswordSlot::UsernameField />
                <S::Render slot=LoginPasswordSlot::PasswordField />
                <S::Render slot=LoginPasswordSlot::SubmitButton />
            </form>
            <S::Render slot=LoginPasswordSlot::BrokerList />
            <S::Render slot=LoginPasswordSlot::Footer />
        </div>
    }
}
```

`Surface` is implemented by both the built-in surface (uses default
components) and the WASM-backed surface (delegates to the theme's
modules). The result is: a theme can change a logo, the password
field's helper text, *or* the entire flow page, with monotonically
increasing customization cost.

## Internationalization

- All user-facing strings are i18n keys.
- Translation bundles ship in `geonosis-i18n` as FTL files (Project
  Fluent — works well with Rust ecosystem).
- A theme can declare its own bundle that overlays the built-in.
- Language negotiation: explicit user preference > realm default >
  `Accept-Language` > English.

## Admin REST API

The admin UI is a thin layer over a versioned REST API:

```
GET    /admin/v1/realms
POST   /admin/v1/realms
GET    /admin/v1/realms/{slug}
PUT    /admin/v1/realms/{slug}
DELETE /admin/v1/realms/{slug}
GET    /admin/v1/realms/{slug}/users
POST   /admin/v1/realms/{slug}/users
...
GET    /admin/v1/realms/{slug}/clients/{client_id}/secret    [POST to rotate]
GET    /admin/v1/realms/{slug}/flows/{alias}
PUT    /admin/v1/realms/{slug}/flows/{alias}                [save graph]
POST   /admin/v1/realms/{slug}/spi/install
GET    /admin/v1/realms/{slug}/spi
GET    /admin/v1/realms/{slug}/events?...
```

Admin auth: a bearer token issued by the **master realm** (or, for a
single-realm install, by the realm itself in a special `realm-admin`
client). Same OAuth 2.1 path as application clients. UI uses
`private_key_jwt` with browser-local key when feasible, falls back to
session cookie + CSRF.

Errors are RFC 7807 problem+json with stable `type` URIs.

## Flow editor (special case)

The flow editor is the **only** admin page that requires extensive
client-side state and hydration. It is implemented as a Leptos
**island**: the server renders the static skeleton; a hydrated
sub-tree loads on demand.

Graph state lives client-side during editing; save POSTs the full
graph (JSON form of the DSL) and the server-side validator returns
errors inline. The canvas itself is canvas/SVG, hand-rolled — no
heavy graph editor library; the node set is small and tightly
typed.

## Asset pipeline

- CSS/JS for the UI are built at server build time, embedded with
  `rust-embed`. No external CDN, no separate static server. Cache
  headers + content-hashed paths.
- Theme assets live on a writable volume (typically a K8s `PersistentVolume`
  or object-store-backed CSI). The theme loader maps a realm's bound
  theme name to a directory, watches with the `notify` crate, and
  invalidates rendered partials on changes.

## Hot reload

| Change | Path | Mechanism |
|---|---|---|
| Template file edited | theme volume | `notify` watcher → invalidate render cache |
| Theme assets edited | theme volume | served via content-hash; updated on next request |
| Component-override module updated | admin API upload | WASM SPI hot-swap (per [`07-spi-wasm.md`](./07-spi-wasm.md)) |
| Theme binding changed (realm setting) | admin API | DB write → `NOTIFY` → cache invalidate |

## Accessibility & security baselines

- All forms have explicit labels, `aria-describedby`, focus rings.
- Targets WCAG 2.1 AA.
- CSP enforced: `default-src 'self'`, `style-src 'self' 'nonce-...'`,
  `script-src 'self' 'nonce-...'`. Themes can extend via theme.toml
  declarations (audited at install).
- HTML escaped by default at template boundary. `unsafe_inner_html`
  is used only with linted call sites.

## Non-goals

- **Client-side state libraries** (Redux/SWR) — Leptos signals are
  enough.
- **Server-driven SPA** as the main interaction mode — admin UI is
  mostly classical form submits; only the flow editor escalates.
- **Native mobile admin** — out of scope.
- **Drag-drop UI builder** for login pages — themes are file/code,
  not visual. Visual builder for flows only.

## Open

- **`<FlowEditor/>` testing** — Playwright vs Leptos's own e2e
  helpers; pick by mid-implementation.
- **RTL languages** in the design system — ensure CSS logical
  properties everywhere from day one.
- **Theme sandboxing** — a malicious template SHOULD NOT exfiltrate
  data; templating engine guarantees this, but we need to write down
  the threat model explicitly.
