# 16 — User Profile (Declarative Attribute Schema)

The **User Profile** is a per-realm schema that defines what
attributes a user has, who can read/write them, how they are
validated, and how they appear in admin / registration / account
forms.

Without a User Profile, attributes are a free-form `BTreeMap<String,
AttributeValue>` — anybody can write anything. The User Profile
turns that map into a typed, enforced contract.

This is direct parity with Keycloak's User Profile feature
(introduced in Keycloak 15, declarative format from 24+).

## Why a schema

- **Validation at write time**: admin can't accidentally write
  `email=not-an-email`.
- **Forms generated automatically**: the registration page, the
  account console, and the admin user-edit page all read this
  schema; no per-form HTML.
- **Token claim contracts**: scopes can include "all attributes
  marked `view=Anyone`" — operators set what's public without
  ad-hoc mappers.
- **Multi-step migrations**: adding a required attribute can be
  expand-only (declare `required: OnRegistration` to grandfather
  existing users).

## Built-in attributes

Every realm comes with a default User Profile that declares the
four built-ins:

| Attribute | Required | Permissions | Validators |
|---|---|---|---|
| `username` | Always | view: Admin, User; edit: Admin (User: when `edit_username_allowed`) | UsernameProhibitedChars, Length(1, 255) |
| `email`    | when `verify_email_required` or `login_with_email_allowed` | view: Anyone (with `email` scope); edit: User, Admin | Email |
| `firstName`| OnRegistration default true | view: User, Admin; edit: User, Admin | PersonNameProhibitedChars, Length(1, 255) |
| `lastName` | OnRegistration default true | view: User, Admin; edit: User, Admin | PersonNameProhibitedChars, Length(1, 255) |

Operators may rename display names, change permissions, or relax
`required` — but not remove these four (the protocol layer depends on
them).

## Custom attributes

Operators add custom attributes via the admin UI or the API:

```yaml
# PUT /admin/v1/realms/acme/user-profile
attributes:
  - name: username
    display_name: "${username}"            # i18n key
    required: { always: true }
    permissions:
      view: [admin, user]
      edit: [admin]
    validators:
      - { kind: username-prohibited-chars }
      - { kind: length, min: 3, max: 64 }

  - name: email
    display_name: "${email}"
    required: { conditional: "realm.login.verify_email_required" }
    permissions:
      view: [anyone]
      edit: [user, admin]
    validators:
      - { kind: email }

  - name: department
    display_name: "Department"
    group: "work"
    display_order: 10
    required: { on_registration: false }
    permissions:
      view: [admin, user]
      edit: [admin]
    validators:
      - { kind: options, values: ["eng", "sales", "support", "finance"] }
    annotations:
      ui.widget: select

  - name: phone
    display_name: "Mobile phone"
    group: "personal"
    multivalued: true
    permissions:
      view: [user, admin]
      edit: [user, admin]
    validators:
      - { kind: regex, pattern: "^\\+?[0-9 ()-]{6,30}$" }

groups:
  - name: work
    display_name: "Work info"
    display_order: 1
  - name: personal
    display_name: "Personal details"
    display_order: 2

unmanaged_attribute_policy: reject     # reject any write to undeclared keys
```

## Permission audiences

- `User` — the owning user, in the account console.
- `Admin` — realm admins via API or admin UI.
- `Anyone` — public. An attribute with `view: [anyone]` is published
  in `userinfo` and id-token when its scope is granted.

A request to mutate an attribute is denied unless the actor is in
the `edit` audience for that attribute. The handler enforces this;
RLS is a defense-in-depth backup.

## Validators

```rust
pub enum AttributeValidator {
    Length { min: Option<u32>, max: Option<u32> },
    Email,
    Url,
    Regex(String),
    LocalDate,                            // YYYY-MM-DD
    Integer { min: Option<i64>, max: Option<i64> },
    Double { min: Option<f64>, max: Option<f64> },
    Options(Vec<String>),                 // discrete enum
    PersonNameProhibitedCharacters,       // emoji, control chars, etc.
    UsernameProhibitedCharacters,
    UriPattern,                           // accepts URI templates
    Custom { module: WasmModuleId, config: serde_json::Value },
}
```

`Custom` dispatches to a WASM module exporting
`geonosis:user-profile-validator@0.1.0`:

```wit
interface validator {
  validate: func(
      attribute: string,
      values: list<string>,
      config: list<u8>,
  ) -> result<_, validation-error>;
}
```

Same sandboxing as other SPI calls (50 M fuel, 200 ms, 32 MiB).

## `required` modes

```rust
pub enum AttributeRequirement {
    Always,                     // must be present on every write
    OnRegistration,             // only enforced at user creation
    Never,                      // optional always
    Conditional(GuardExpr),     // requires when expression evaluates true
}
```

`Conditional` reuses the same tiny guard language as flow edges (see
[`06-auth-flows.md`](./06-auth-flows.md)). Variables:
`user.required_actions`, `realm.login.verify_email_required`, etc.

## How forms are generated

- **Registration form**: includes every attribute with
  `required.on_registration=true`, ordered by `display_order` then
  attribute name, grouped by `group`. Themes can override the page
  but the field set is data-driven.
- **Account console** (v0.2): same, restricted to attributes with
  `User` in `view` permissions.
- **Admin form**: every declared attribute, no permission filter
  (admin can see all by definition).

`annotations.ui.widget` accepts: `text`, `textarea`, `select`,
`checkbox`, `radio`, `password`, `date`, `multi-input`. The theme
maps it to a component.

## Unmanaged attributes

Attributes not declared in the User Profile are governed by
`unmanaged_attribute_policy`:

| Policy | Behavior |
|---|---|
| `Reject` (default) | Writes to undeclared keys fail `invalid_attribute`. |
| `Allow` | Undeclared keys accepted; not shown in admin UI by default. |
| `Hidden` | Undeclared keys accepted but never returned to API responses (admin can opt-in). |

Strict-by-default. Operators migrating from a free-form attributes
era flip to `Allow` long enough to clean up data, then back.

## Versioning

The User Profile is a single row per realm. Edits bump
`updated_at`; old versions are kept in audit history but not
operationally referenced — there's only one current schema. Schema
changes that tighten validation are evaluated against existing rows
lazily (on next write) unless an admin runs
`geoctl users validate-against-profile --fix=mark-for-action`.

## Hot reload

User Profile lives in cache class `user-profile`. Edits issue a
cache invalidation; forms and validators reload across pods within
the usual NOTIFY/pub-sub envelope (< 100 ms typical).

## Audit events

| Action | Detail |
|---|---|
| `user-profile.updated` | by, diff |
| `user.attribute.rejected` | user, attribute, validator |

## Non-goals

- **Per-organization User Profiles** — schema is realm-wide.
- **Conditional fields with cross-field dependencies** beyond
  `Conditional` requirement — keep the editor simple; complex
  validation is a WASM `Custom` validator.
- **Auto-migrating malformed data** — explicit operator step.

## Decisions and open items

- **Default policy**: `Reject` unmanaged. Strict by default.
- **`Custom` validators**: WASM SPI, contract above.
- **Account-console form**: v0.2.
- **Conditional dependencies in admin form** (e.g. show
  "supervisor" only if `role=manager`): out of scope v0.1; can be
  added via theme override on the admin form.
