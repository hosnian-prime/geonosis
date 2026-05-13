# 06 — Authentication Flows

An **authentication flow** is the path a user walks to prove identity
during a login (or registration, or password reset, or direct grant).
Geonosis models flows as **directed graphs of typed nodes** plus a
serializable DSL. Operators edit them visually in the admin UI, and
flows hot-reload without dropping requests.

This is the most user-visible customization surface, so the design
target is: **trivial cases are trivial, complex cases are possible**.

## Why a graph, not a list

The classic IAM model — an ordered list of steps tagged
`REQUIRED / ALTERNATIVE / OPTIONAL / DISABLED` — is loved for simple
cases and resented for complex ones. Branching ("if user logged in
via Google in the last 24h, skip MFA"), parallel choices ("MFA: pick
TOTP or WebAuthn"), and post-step side effects all bend the list
model out of shape.

We pay the modest extra complexity of a graph because:

- Branching is first-class (`Switch` nodes).
- Subflows are just edges into another graph node.
- Each node has explicit `inputs` / `outputs`, so the editor can
  type-check the graph and prevent unreachable steps.

## Node types

```rust
pub enum FlowNode {
    Start(StartNode),
    Render(RenderNode),                // shows UI to user
    Authenticator(AuthenticatorNode),  // built-in or WASM SPI
    Broker(BrokerNode),                // external IdP step
    Switch(SwitchNode),                // branch on a typed expression
    SubFlow(SubFlowNode),              // call another flow by id
    Action(ActionNode),                // side effect (set required action, link account)
    Success(SuccessNode),
    Failure(FailureNode),
}
```

A `FlowGraph` is `{ nodes: Vec<FlowNode>, edges: Vec<Edge>, start: NodeId }`.
Edges carry an optional **guard** expression (Switch-like inline
branching). Graphs must be:

- **Acyclic** (no loops; retry is modelled by the same node consuming
  retries internally).
- **Connected** from `start`.
- **Terminating** — every path ends in `Success` or `Failure`.

The graph compiler enforces these at save time.

## Built-in authenticators (v0.1)

| Alias | Purpose |
|---|---|
| `password` | Username + password against local store / federation |
| `otp` | TOTP / HOTP |
| `webauthn` | WebAuthn assertion |
| `recovery-code` | One-time recovery code |
| `magic-link` | Email link with single-use token |
| `consent` | OAuth consent screen |
| `cookie` | Re-use existing SSO cookie |
| `idp-redirect` | Begin a `broker-step` (see [`05-identity-broker.md`](./05-identity-broker.md)) |
| `require-action` | Verify-email, update-password, etc. |
| `risk-score` | Returns a risk decision; used by Switch nodes |

Custom authenticators are WASM modules implementing
`geonosis:authn@0.1.0`.

## Render nodes

A `RenderNode` declares a **page template alias** and a set of
parameters. The theme engine resolves the template from the realm's
bound login theme. Template overrides happen there, not in the flow.

```rust
struct RenderNode {
    id: NodeId,
    template: String,           // "login/password.html" / "login/otp.html"
    title_key: String,          // i18n key
    inputs: Vec<FieldDecl>,     // form fields with kind + validator
}
```

Edges out of a `RenderNode` are guarded by **form submission action
ids**. The user posting `action=submit-password` matches the edge to
the password authenticator.

## Switch and guards

Guards are a tiny pure-evaluation expression language: variables
from the **context**, comparison/logic, no I/O. Implemented in Rust
with a parsed AST; **no embedded scripting** for security and
performance reasons. Examples:

```
context.user.email_verified == false
context.session.amr contains "pwd" and context.client.flow_kind == "step-up"
context.broker.last_login_age_seconds < 86400
```

The set of context variables is fixed and documented; tenants cannot
inject new variables here. To branch on something custom, install a
**Switch via WASM** authenticator that returns a discrete decision
(`yes`, `no`, `skip`).

## DSL (serialized form)

YAML is the persisted form (also accepted on import). JSON renders the
same shape.

```yaml
alias: browser
version: 7
start: n_start
nodes:
  - id: n_start
    kind: start
  - id: n_login
    kind: render
    template: login/login.html
    inputs:
      - { name: username, kind: text, required: true }
      - { name: action,   kind: action, enum: [submit-password, idp-google] }
  - id: n_password
    kind: authenticator
    provider: password
    config: { allow-reset: true }
  - id: n_idp
    kind: broker
    idp: google
  - id: n_otp
    kind: authenticator
    provider: otp
    config: { policy: required-if-enrolled }
  - id: n_done
    kind: success
edges:
  - { from: n_start,    to: n_login }
  - { from: n_login,    to: n_password, when: "action == 'submit-password'" }
  - { from: n_login,    to: n_idp,      when: "action == 'idp-google'" }
  - { from: n_password, to: n_otp,      when: "context.user.requires_otp" }
  - { from: n_password, to: n_done }
  - { from: n_otp,      to: n_done }
  - { from: n_idp,      to: n_done }
```

A flow's `version` is monotonic. Saving an edited flow inserts a new
`auth_flow` row with `version=N+1`; in-flight executions on `N`
finish under their own graph snapshot. Old versions get garbage-
collected after the longest possible step TTL (default 30 min).

## Executor

```rust
trait FlowExecutor {
    async fn step(
        &self,
        flow: &CompiledFlow,
        state: &mut FlowState,
        input: StepInput,
    ) -> Result<StepOutput, FlowError>;
}

enum StepOutput {
    Render(RenderInstruction),
    Redirect(Url),
    Done(Subject),
    Failed(FlowFailure),
}
```

`FlowState` is the per-attempt state machine:

```rust
struct FlowState {
    flow_id: FlowId,
    flow_version: i32,
    current: NodeId,
    history: Vec<(NodeId, Outcome)>,
    context: FlowContext,         // user-resolved? broker assertion? ...
    started_at: DateTime<Utc>,
    last_activity_at: DateTime<Utc>,
    csrf: CsrfToken,
}
```

Persisted in Postgres in `flow_state` keyed by an opaque cookie. TTL
30 min idle / 60 min absolute. Each step transition rewrites the row;
contention is per-user-per-flow so it is naturally low.

The executor is **synchronous from the user's perspective** — each
HTTP request advances exactly one step. There's no background
progression of a flow.

## Authenticator contract (built-in)

```rust
#[async_trait]
trait Authenticator {
    fn provider_id(&self) -> &'static str;

    async fn process(
        &self,
        ctx: &mut FlowContext,
        config: &Self::Config,
        input: AuthenticatorInput,
    ) -> Result<AuthenticatorOutput, AuthenticatorError>;
}
```

`AuthenticatorOutput` is one of:

- `Success { credentials_satisfied: Vec<CredentialKind>, amr: Vec<Amr> }`
- `Continue { render: RenderInstruction }`
- `Skip` (e.g. cookie already valid)
- `Failure(FailureKind)` (terminal for this node; flow may continue)

The same shape is mirrored by the WASM `geonosis:authn` interface so
built-in and SPI authenticators are interchangeable.

## Compilation and hot reload

Saving a flow:

1. **Parse** YAML/JSON to graph.
2. **Validate** (acyclic, connected, terminating, all node providers
   resolved, all template aliases existent in the bound theme).
3. **Insert** `auth_flow` row with new `version`.
4. `pg_notify('geonosis_invalidate', '{"kind":"flow","id":"<id>"}')`.
5. Each pod: invalidate cache entry. New executions compile fresh.

Compilation produces a `CompiledFlow` (graph indexed by `NodeId`,
guards parsed to an AST, providers resolved to vtables). Compilation
is pure and quick (< 1 ms typical).

## UI editor

The admin UI renders a graph editor. The wire format the editor uses
is the YAML/JSON DSL above; the editor is "just a viewer + writer of
the DSL" — operators can also edit YAML directly. Power-user features:

- Side-by-side YAML + canvas.
- Per-version diff view.
- Dry-run with a synthetic context to preview branch decisions.

## Flow kinds

A flow has a **kind** that determines when the executor picks it.
Built-in kinds:

| Kind | When picked |
|---|---|
| `browser` | Interactive `/authorize` requests |
| `direct-grant` | `grant_type=password` |
| `registration` | Self-service signup |
| `reset-credentials` | Forgot-password page |
| `first-broker-login` | First login via external IdP |
| `client-authentication` | Alternative client auth (e.g. private_key_jwt + extra checks) |
| `step-up` | `/authorize` with `acr_values` requesting a level not yet satisfied by the current session |

A realm can host **multiple `step-up` flows**, distinguished by the
`acr` they target. The executor consults the realm's `acr_policy`
(see [`12-security-crypto.md`](./12-security-crypto.md)) to:

1. Compute the **current ACR** of the session (from AMR + sender-
   constraint).
2. If the request's `acr_values` lists a stronger level not currently
   held, look up the `step-up` flow whose binding targets that level.
3. Run it; on success, augment session AMR and re-evaluate.

A typical step-up flow is short: skip if cookie says "user already
satisfied this level recently", else demand WebAuthn or OTP.

## Built-in flows (out of the box)

Every realm comes with these flows pre-installed; operators can
clone-and-edit:

- `browser` — interactive login
- `direct-grant` — `password` grant
- `registration` — self-service signup
- `reset-credentials` — forgot password
- `first-broker-login` — first login via external IdP
- `client-authentication` — alternative auth for clients
- `step-up-mfa` — example `step-up` flow targeting ACR level 2 (MFA)

## Forced flows (admin override)

Two complementary mechanisms let admins force a user through an
out-of-band flow at the next login:

- **`required_actions`** on `app_user`: an enumerated list
  (`verify-email`, `update-password`, `configure-otp`, ...).
  The `browser` flow's start node consults this list and detours to
  the corresponding built-in subflow. Best for **simple, additive
  steps** — fixing one credential, accepting a new ToS, etc.
- **`required_flow`** column on `app_user` (nullable `FlowAlias`):
  forces the entire login through a designated flow instead of the
  client's normal `browser` flow. Best for **bespoke onboarding**
  (e.g. risk-review, manager-approval, escalated identity
  verification). Cleared by the flow itself on success.

Both are evaluated at the `Start` node of the executor:

```
Start
 ├─ if user.required_flow.is_some() → jump to that flow
 ├─ else if user.required_actions non-empty → enter actions subflow
 └─ else continue with client's bound browser flow
```

The two are independent and additive — an admin can both queue a
`required_flow` (e.g., security review) and a `required_action`
(e.g., update password) on the same user.

## Non-goals

- **Loops / retries as graph cycles** — retry is internal to a node.
- **Concurrent parallel steps** — the user does one thing at a time.
- **Server-side scripting in guards** — guards are a fixed expression
  language; complex logic goes into a WASM authenticator.

## Decisions and open items

- **Step-up authentication**: dedicated `step-up` flow kind picked
  by the executor based on requested `acr_values` and the realm's
  `acr_policy`.
- **Admin-forced flows**: both `required_actions` (simple, additive)
  and `required_flow` (full override). Specified above.
- **Editor templating / public flow registry** — deferred; flows
  are exported/imported as YAML via `geoctl`, but there's no
  curated central marketplace.
