# 08 — Admin Console

The admin console is **embedded** in the `geonosis-server` binary and
rendered with [**Leptos**](https://leptos.dev/) using **SSR + island
hydration**. It exposes every backend capability through a structured,
realm-scoped UI backed by the versioned `/admin/v1/...` REST API.

---

## 1  Information architecture

### 1.1  Global chrome

Every admin page shares a persistent shell:

```
┌──────────────────────────────────────────────────────────────┐
│  [logo] Geonosis    [realm selector ▾]   [☀/☾] [👤 Profile] │
├──────────────┬───────────────────────────────────────────────┤
│  Sidebar     │  Main content                                 │
│              │                                                │
│  Realms      │  Breadcrumb: Realm › Section › Entity          │
│              │                                                │
│  MANAGE      │  Page title              [+ Create]            │
│   Users      │                                                │
│   Groups     │  ┌─────────────────────────────────────┐       │
│   Organizations  │  Tab bar (when on a detail page)  │       │
│   Agents     │  │  General │ Credentials │ Roles │.. │       │
│   Sessions   │  └─────────────────────────────────────┘       │
│              │                                                │
│  CONFIGURE   │  Content area                                  │
│   Clients    │                                                │
│   Roles      │                                                │
│   Flows      │                                                │
│   IdPs       │                                                │
│   Federation │                                                │
│   Keys       │                                                │
│              │                                                │
│  EXTENSIONS  │                                                │
│   SPI        │                                                │
│              │                                                │
│  MONITOR     │                                                │
│   Events     │                                                │
│              │                                                │
│  ─────       │                                                │
│  Settings    │                                                │
└──────────────┴───────────────────────────────────────────────┘
```

**Header bar** (right-aligned controls):

- **Realm selector** — dropdown to switch the active realm without
  navigating away.
- **Theme toggle** — light/dark mode switch (sun/moon icon). Persisted
  in `localStorage`; respects `prefers-color-scheme` on first visit.
- **Profile icon** — circular avatar (initials or gravatar). Clicking
  opens the **user profile page** (`/admin/profile`) where both admin
  and regular users can manage their own account: change password,
  configure MFA (OTP / WebAuthn), manage active sessions, update name
  and email. Profile is NOT realm-scoped — it applies to the
  authenticated admin user across all realms.

**Sidebar** — grouped, realm-scoped navigation. Groups are collapsible
section headers (not links themselves). Clicking a group header
expands/collapses its children. When no realm is selected (realm list
page), only "Realms" is shown. Once inside a realm, all groups appear
expanded by default. The active item is highlighted; the active group
header is bold.

Sidebar is sticky on desktop; on mobile (< 768 px) it collapses into
a hamburger-triggered slide-over drawer.

**Breadcrumbs** — `Realms > acme > Clients > acme-web`. Every detail
page shows its position in the hierarchy.

### 1.2  Sidebar groups

The sidebar organizes items into logical groups. Group headers are
rendered as uppercase muted labels (not clickable links). Items within
each group are indented.

| Group        | Item           | Path                                 |
|--------------|----------------|--------------------------------------|
| *(top-level)*| Realms         | `/admin/realms`                      |
| **Manage**   | Users          | `/admin/realms/{slug}/users`         |
|              | Groups         | `/admin/realms/{slug}/groups`        |
|              | Organizations  | `/admin/realms/{slug}/orgs`          |
|              | Agents         | `/admin/realms/{slug}/agents`        |
|              | Sessions       | `/admin/realms/{slug}/sessions`      |
| **Configure**| Clients        | `/admin/realms/{slug}/clients`       |
|              | Roles          | `/admin/realms/{slug}/roles`         |
|              | Flows          | `/admin/realms/{slug}/flows`         |
|              | Identity providers | `/admin/realms/{slug}/idps`      |
|              | Federation     | `/admin/realms/{slug}/federation`    |
|              | Keys           | `/admin/realms/{slug}/keys`          |
| **Extensions**| SPI plugins   | `/admin/realms/{slug}/spi`           |
| **Monitor**  | Audit events   | `/admin/realms/{slug}/events`        |
| *(bottom)*   | Settings       | `/admin/realms/{slug}/settings`      |

When the user clicks a sidebar item the main content area loads the
corresponding list or detail page. Sub-navigation within an entity
(e.g. User → General | Credentials | Roles) is handled by a **tab
bar** at the top of the main content area — not by sidebar nesting.

### 1.3  User profile page — `/admin/profile`

Accessible from the profile icon in the header. Shows the
authenticated user's own account (admin or otherwise). Tabs:

| Tab            | Content                                         |
|----------------|-------------------------------------------------|
| General        | Username (read-only), email, name, email verified |
| Password       | Change password form (current + new + confirm)  |
| OTP            | TOTP/HOTP setup (QR code + manual key)          |
| WebAuthn       | Register / remove security keys                 |
| Sessions       | List active sessions, revoke sessions           |
| Sign out       | Confirm sign-out button                         |

This page reuses the same field components as the admin user-detail
page but operates on the authenticated user's own record (no admin
privilege required — any authenticated user can view/edit their own
profile).

### 1.4  Light / dark mode

The UI ships with two color schemes. Implementation:

- CSS custom properties define all colors. Two sets of values are
  declared: `:root` (dark, default) and `:root[data-theme="light"]`.
- A toggle button in the header switches `data-theme` on `<html>` and
  persists the choice to `localStorage`.
- On first visit, `prefers-color-scheme: light` auto-selects light
  mode; otherwise dark is the default.
- All component styles reference `var(--gn-color-*)` tokens — **no
  hardcoded color values** anywhere outside `:root` declarations.
  This is the DRY principle: every color is defined exactly once per
  theme, not duplicated across components.
- The login page respects the same toggle (persisted via
  `localStorage`, not a server round-trip).

### 1.5  Typography and sizing

The UI uses a larger base font for readability:

| Token                    | Value           |
|--------------------------|-----------------|
| `--gn-font-size-base`   | 15px            |
| `--gn-font-size-sm`     | 13px            |
| `--gn-font-size-lg`     | 18px            |
| `--gn-font-size-xl`     | 24px            |
| `--gn-font-size-2xl`    | 30px            |
| `--gn-font-size-3xl`    | 36px            |

Buttons use the base font size with generous padding
(`padding: 10px 20px` for default, `padding: 12px 24px` for primary
actions). Touch targets are at least 44 px tall per WCAG 2.5.8.

### 1.6  Responsive design

Three breakpoints:

| Breakpoint | Layout                                          |
|------------|-------------------------------------------------|
| > 1024 px  | **Desktop**: 260 px sticky sidebar + fluid main |
| 768–1024   | **Tablet**: 220 px sidebar, compact padding     |
| < 768 px   | **Mobile**: sidebar hidden behind hamburger icon; full-width main; tab bars scroll horizontally; tables switch to card layout for narrow screens |

Key responsive behaviors:

- **Sidebar**: fixed on desktop, slide-over drawer on mobile with
  backdrop overlay.
- **Tables**: on mobile, each row renders as a stacked card with
  label: value pairs instead of columnar layout.
- **Tab bars**: horizontally scrollable with overflow arrows on mobile.
- **Forms**: single-column layout on all breakpoints (no side-by-side
  fields that break on narrow screens).
- **Header**: realm selector and profile icon always visible; theme
  toggle collapses into the profile dropdown on mobile.
- **Buttons**: full-width on mobile, inline on desktop.

### 1.7  Common UI patterns

Every list page follows the same pattern:

- **Header row**: page title + "Create" button (where applicable).
- **Filter bar**: search input + filter dropdowns (where applicable).
- **Table**: sortable columns, row hover highlight, action column with
  edit/delete links. On mobile, renders as stacked cards.
- **Pagination**: cursor-based (limit + next-cursor), default 25 rows.
- **Empty state**: friendly message + create CTA.

Every detail/edit page follows:

- **Breadcrumbs** at top.
- **Tab bar** for sub-sections (e.g. User → General | Credentials |
  Roles | Groups | Sessions | Consents). Tabs are rendered in the main
  content area, not in the sidebar.
- **Form** with labeled fields, inline validation, help text.
- **Action bar** at bottom: Save, Cancel, Delete (with confirmation).

---

## 2  Page inventory

### 2.1  Realms

#### Realm list — `/admin/realms`

| Column        | Source               |
|---------------|----------------------|
| Slug          | `realm.slug`         |
| Display name  | `realm.display_name` |
| Enabled       | badge                |
| Created       | `realm.created_at`   |

**Actions**: Create realm (button → form), click row → realm detail.

**API**: `GET /admin/v1/realms`, `POST /admin/v1/realms`

#### Realm detail — `/admin/realms/{slug}`

Dashboard card layout showing realm overview:

- **Quick stats**: user count, client count, active session count.
- **Cards**: link to each sub-section (Clients, Users, Flows, etc.)
  with entity count badges.
- **Actions**: Edit realm settings, Disable/Enable realm, Delete realm
  (with type-to-confirm).

**API**: `GET /admin/v1/realms/{slug}`, `PUT /admin/v1/realms/{slug}`,
`DELETE /admin/v1/realms/{slug}`

---

### 2.2  Realm settings — `/admin/realms/{slug}/settings`

Tabbed configuration page for all realm-level policies. Each tab maps
to a nested config object on the `Realm` entity.

#### Tab: General

| Field                | Type       | Source                      |
|----------------------|------------|-----------------------------|
| Display name         | text       | `realm.display_name`        |
| Frontend URL         | url        | `realm.frontend_url`        |
| Admin frontend URL   | url        | `realm.admin_frontend_url`  |
| SSL required         | select     | `realm.ssl_required` (None / External / All) |
| Enabled              | toggle     | `realm.enabled`             |
| Orgs enabled         | toggle     | `realm.organizations_enabled` |

#### Tab: Login

| Field                       | Type    | Source                             |
|-----------------------------|---------|-------------------------------------|
| User registration           | toggle  | `login.registration`                |
| Forgot password             | toggle  | `login.reset_password`              |
| Remember me                 | toggle  | `login.remember_me`                 |
| Login with email            | toggle  | `login.email_login`                 |
| Email as username            | toggle  | `registration.email_as_username`    |
| Duplicate emails             | toggle  | `login.duplicate_emails`            |
| Verify email                | toggle  | `login.verify_email`                |
| Edit username               | toggle  | `login.edit_username`               |
| Require terms acceptance    | toggle  | `registration.require_terms_acceptance` |

#### Tab: Sessions

| Field                    | Type     | Source                        |
|--------------------------|----------|-------------------------------|
| SSO session idle         | duration | `session_policy.sso_session_idle`   |
| SSO session max          | duration | `session_policy.sso_session_max`    |
| Remember-me idle         | duration | `session_policy.remember_me_idle`   |
| Remember-me max          | duration | `session_policy.remember_me_max`    |

#### Tab: Tokens

| Field                         | Type     | Source                              |
|-------------------------------|----------|-------------------------------------|
| Access token lifespan         | duration | `token_policy.access_token_lifespan`      |
| Implicit access token lifespan| duration | `token_policy.access_token_lifespan_implicit` |
| Refresh token lifespan        | duration | `token_policy.refresh_token_lifespan`     |
| Auth code lifespan            | duration | `token_policy.auth_code_lifespan`         |
| Revoke refresh on use         | toggle   | `token_policy.revoke_on_use`              |
| Max refresh reuse             | number   | `token_policy.max_reuse`                  |
| Default signing algorithm     | select   | `token_policy.default_signing_alg` (RS256/ES256/EdDSA) |
| Allowed signing algorithms    | multi    | `token_policy.allowed_signing_algs`       |

#### Tab: Security — Password policy

Renders the `password_policy.rules` array. Each rule is a row with
type selector + config value:

| Rule type        | Config field    |
|------------------|-----------------|
| Length            | min             |
| Special chars    | min count       |
| Uppercase        | min count       |
| Lowercase        | min count       |
| Digits           | min count       |
| Not username     | —               |
| Not email        | —               |
| Password history | depth           |
| Pwned check      | —               |
| Expire           | max age (days)  |
| Regex blocklist  | pattern         |
| Hash iterations  | count           |
| Hash algorithm   | select          |

**Actions**: Add rule, remove rule, reorder.

#### Tab: Security — Brute force

| Field                | Type    | Source                       |
|----------------------|---------|------------------------------|
| Enabled              | toggle  | `brute_force.enabled`        |
| Permanent lockout    | toggle  | `brute_force.permanent_lockout` |
| Max failures         | number  | `brute_force.max_failures`   |
| Wait increment (s)   | number  | `brute_force.wait_increment` |
| Max wait (s)         | number  | `brute_force.max_wait`       |
| Failure reset (s)    | number  | `brute_force.failure_reset`  |

#### Tab: Security — OTP

| Field                | Type    | Source                   |
|----------------------|---------|--------------------------|
| Kind                 | select  | `otp_policy.kind` (TOTP/HOTP) |
| Algorithm            | select  | SHA-1/SHA-256/SHA-512    |
| Digits               | select  | 6 / 8                    |
| Period (s)           | number  | `otp_policy.period_seconds` |
| Look-ahead window    | number  | `otp_policy.look_ahead_window` |
| Initial counter      | number  | (HOTP only)              |

#### Tab: Security — WebAuthn

| Field                    | Type    | Source                              |
|--------------------------|---------|-------------------------------------|
| RP ID                    | text    | `webauthn_policy.relying_party_id`  |
| RP name                  | text    | `webauthn_policy.relying_party_name`|
| Signature algorithms     | multi   | list of COSE algorithms             |
| Attestation conveyance   | select  | none/indirect/direct/enterprise     |
| Authenticator attachment | select  | platform/cross-platform/any         |
| Require resident key     | toggle  |                                     |
| User verification        | select  | required/preferred/discouraged      |

#### Tab: Themes

| Field          | Type    | Source                           |
|----------------|---------|----------------------------------|
| Login theme    | select  | `theme_binding.login`            |
| Account theme  | select  | `theme_binding.account`          |
| Admin theme    | select  | `theme_binding.admin`            |
| Email theme    | select  | `theme_binding.email`            |

#### Tab: Localization

| Field               | Type    | Source                               |
|---------------------|---------|--------------------------------------|
| Default locale      | select  | `localization.default_locale`        |
| Supported locales   | multi   | `localization.supported_locales`     |

#### Tab: Events

| Field                 | Type    | Source                   |
|-----------------------|---------|--------------------------|
| Login events enabled  | toggle  | `events.login_enabled`   |
| Admin events enabled  | toggle  | `events.admin_enabled`   |
| Retention (days)      | number  | `events.retention_days`  |
| Event listeners       | multi   | `events.events_listeners`|

#### Tab: ACR policy

Table of ACR levels, each with:

| Field         | Type     | Source                      |
|---------------|----------|-----------------------------|
| Value         | text     | ACR string                  |
| Display name  | text     | label shown in UI           |
| Requirement   | select   | Any/AmrContains/AllOf/AnyOf |

**Actions**: Add level, remove level, reorder.

#### Tab: Organization policy

| Field                        | Type    | Source                                      |
|------------------------------|---------|---------------------------------------------|
| Default invitation TTL (d)   | number  | `organization_policy.default_invitation_ttl_days` |
| Default self-signup role     | text    | `organization_policy.default_role_for_self_signup` |
| Require domain verification | toggle  | `organization_policy.require_domain_verification` |
| Auto-join on domain match   | toggle  | `organization_policy.auto_join_on_domain_match`   |

#### Tab: Default roles & groups

- **Default roles**: multi-select from realm roles. New users
  auto-receive these roles.
- **Default groups**: multi-select from groups. New users auto-join
  these groups.

**API**: `PUT /admin/v1/realms/{slug}` (full realm object update)

---

### 2.3  Clients — `/admin/realms/{slug}/clients`

#### Client list

| Column       | Source              |
|--------------|---------------------|
| Client ID    | `client.client_id`  |
| Display name | `client.display_name` |
| Kind         | badge (Public/Confidential/Service/SAML SP) |
| Enabled      | badge               |

**Actions**: Create client, click row → client detail.

**API**: `GET /admin/v1/realms/{slug}/clients`

#### Client create — modal or page

| Field        | Type    | Required | Notes                      |
|--------------|---------|----------|----------------------------|
| Client ID    | text    | yes      | OAuth public identifier    |
| Display name | text    | no       |                            |
| Kind         | select  | yes      | Confidential/Public/BearerOnly/ServiceAccount/SamlSP |
| Auth method  | select  | yes      | Derived from kind defaults |

**API**: `POST /admin/v1/realms/{slug}/clients`

#### Client detail — `/admin/realms/{slug}/clients/{client_id}`

Tabbed detail page.

##### Tab: General

| Field              | Type    | Source                       |
|--------------------|---------|------------------------------|
| Client ID          | text    | read-only                    |
| Display name       | text    | `client.display_name`        |
| Kind               | badge   | read-only after create       |
| Enabled            | toggle  | `client.enabled`             |
| Auth method        | select  | `client.auth_method`         |
| Access token type  | select  | JWT / Opaque                 |

##### Tab: URIs

| Field                         | Type       | Source                          |
|-------------------------------|------------|---------------------------------|
| Redirect URIs                 | repeater   | `client.redirect_uris`         |
| Post-logout redirect URIs     | repeater   | `client.post_logout_redirect_uris` |
| Web origins (CORS)            | repeater   | `client.web_origins`           |

Each repeater row: text input + remove button. "Add URI" button below.
Redirect URIs show `wildcard_path` toggle per entry.

##### Tab: Grant types

Checkbox group mapping to `GrantPolicy`:

| Grant               | Field                          |
|----------------------|--------------------------------|
| Authorization code   | `grants.authorization_code`   |
| Refresh token        | `grants.refresh_token`        |
| Client credentials   | `grants.client_credentials`   |
| Password (direct)    | `grants.password`             |
| Device code          | `grants.device_code`          |
| Token exchange       | `grants.token_exchange`       |

##### Tab: Scopes

- **Default scopes**: multi-select tag input. Applied automatically.
- **Optional scopes**: multi-select. Requires explicit `scope=` request.

##### Tab: Flow bindings

| Flow slot              | Type    | Source                        |
|------------------------|---------|-------------------------------|
| Browser flow           | select  | `flow_binding.browser`        |
| Direct-grant flow      | select  | `flow_binding.direct_grant`   |
| Registration flow      | select  | `flow_binding.registration`   |
| Reset credentials flow | select  | `flow_binding.reset_credentials` |
| Client auth flow       | select  | `flow_binding.client_authentication` |

Dropdowns populated from `GET /admin/v1/realms/{slug}/flows`.

##### Tab: Consent

| Field                        | Type    | Source                           |
|------------------------------|---------|----------------------------------|
| Consent required             | toggle  | `consent.required`               |
| Display on consent screen    | toggle  | `consent.display_on_consent_screen` |
| Consent screen text          | textarea| `consent.consent_screen_text`    |

##### Tab: Token overrides

| Field                       | Type     | Source                              |
|-----------------------------|----------|-------------------------------------|
| Access token lifespan       | duration | `client.access_token_lifespan`      |
| Refresh token lifespan      | duration | `client.refresh_token_lifespan`     |
| Access token signing alg    | select   | `client.access_token_signing_alg`   |
| Pairwise subject algorithm  | select   | `client.pairwise_sub_algorithm`     |

##### Tab: Logout

| Field                         | Type    | Source                                  |
|-------------------------------|---------|-----------------------------------------|
| Front-channel logout enabled  | toggle  | `client.front_channel_logout_enabled`   |
| Backchannel logout URL        | url     | `client.backchannel_logout_url`         |

##### Tab: SAML SP (conditional — shown when kind == SamlServiceProvider)

| Field                         | Type    | Source                       |
|-------------------------------|---------|------------------------------|
| Entity ID                     | text    | `saml_sp_config.entity_id`   |
| ACS URL                       | url     | `saml_sp_config.acs_url`     |
| SLO URL                       | url     | `saml_sp_config.slo_url`     |
| Name ID format                | select  | persistent/transient/email   |
| Sign assertions               | toggle  |                              |
| Encrypt assertions            | toggle  |                              |

##### Tab: Client authentication keys (conditional — private_key_jwt)

Table of registered public keys:

| Column | Source |
|--------|--------|
| Key ID | `kid`  |
| Algorithm | `alg` |
| Created | timestamp |

**Actions**: Add key (paste JWK), remove key.

**Actions (page-level)**: Save, Delete client (confirm modal).

**API**: `GET/PUT/DELETE /admin/v1/realms/{slug}/clients/{client_id}`

---

### 2.4  Users — `/admin/realms/{slug}/users`

#### User list

| Column    | Source           |
|-----------|------------------|
| Username  | `user.username`  |
| Email     | `user.email`     |
| Enabled   | badge            |
| Created   | `user.created_at`|

**Search**: full-text over username, email, name. Filter by
enabled/disabled.

**Actions**: Create user, click row → user detail.

**API**: `GET /admin/v1/realms/{slug}/users?search=&limit=&cursor=`

#### User create — modal or page

| Field           | Type    | Required |
|-----------------|---------|----------|
| Username        | text    | yes      |
| Email           | email   | no       |
| First name      | text    | no       |
| Last name       | text    | no       |
| Enabled         | toggle  | default true |
| Email verified  | toggle  | default false |
| Initial password| password| no (set separately) |

**API**: `POST /admin/v1/realms/{slug}/users`

#### User detail — `/admin/realms/{slug}/users/{username}`

Tabbed detail page.

##### Tab: General

| Field           | Type    | Source                      |
|-----------------|---------|------------------------------|
| Username        | text    | read-only                    |
| Email           | email   | `user.email`                 |
| Email verified  | toggle  | `user.email_verified`        |
| First name      | text    | `user.name.given`            |
| Last name       | text    | `user.name.family`           |
| Enabled         | toggle  | `user.enabled`               |
| Required actions| multi   | `user.required_actions` (UpdatePassword / ConfigureOtp / VerifyEmail / ...) |
| Forced flow     | select  | `user.required_flow`         |

**Actions**: Save, Verify email (`POST .../verify-email`),
Disable/Enable, Delete (confirm).

##### Tab: Attributes

Key-value editor for `user.attributes`. Respects the realm's user
profile schema — unknown attributes shown with a warning badge if
`unmanaged_policy == Allow`.

| Column    | Type    |
|-----------|---------|
| Key       | text    |
| Value     | dynamic (text/number/boolean per schema) |

**Actions**: Add attribute, edit value, remove attribute.

##### Tab: Credentials

Lists `user.credentials`:

| Column    | Source                    |
|-----------|---------------------------|
| Type      | badge (Password/OTP/WebAuthn/...) |
| Label     | `credential.label`        |
| Created   | `credential.created_at`   |
| Last used | `credential.last_used_at` |

**Actions**:
- **Set password** (`PUT .../password`) — modal with new password +
  confirm. Optional "temporary" toggle (forces UpdatePassword action).
- **Delete credential** — remove OTP/WebAuthn entries.

##### Tab: Role assignments

Two sections: **Realm roles** and **Client roles** (grouped by client).

| Column    | Source |
|-----------|--------|
| Role name | link to role detail |
| Scope     | Realm / Client ID |

**Actions**: Assign role (select from available), Unassign role.

**API**: `GET/POST/DELETE /admin/v1/realms/{slug}/users/{id}/roles`

##### Tab: Groups

| Column    | Source           |
|-----------|------------------|
| Group     | `group.path`     |
| Name      | `group.name`     |

**Actions**: Join group (select from available), Leave group.

**API**: `GET/POST/DELETE /admin/v1/realms/{slug}/users/{id}/groups`

##### Tab: Organizations

| Column        | Source                   |
|---------------|--------------------------|
| Organization  | `org.display_name`       |
| Roles         | comma-separated role names |
| State         | badge (Active/Invited/Suspended) |
| Joined        | `membership.joined_at`   |

**API**: `GET /admin/v1/realms/{slug}/users/{id}/orgs`

##### Tab: Sessions

User-scoped session list (filtered to this user):

| Column      | Source                |
|-------------|------------------------|
| Session ID  | truncated              |
| Started     | `session.started_at`   |
| Last seen   | `session.last_seen_at` |
| IP          | (if available)         |
| Clients     | count                  |

**Actions**: Revoke session, Revoke all sessions.

##### Tab: Consents

Per-client consent grants:

| Column      | Source                    |
|-------------|---------------------------|
| Client      | `consent.client_id`       |
| Scopes      | `consent.granted_scopes`  |
| Granted     | `consent.granted_at`      |

**Actions**: Revoke consent.

---

### 2.5  Roles — `/admin/realms/{slug}/roles`

#### Role list

| Column      | Source             |
|-------------|---------------------|
| Name        | `role.name`         |
| Description | `role.description`  |
| Scope       | badge: Realm / Client `{client_id}` |
| Composites  | count of child roles |

**Filter**: toggle between "Realm roles" and "Client roles" (filter by
`client_id` presence).

**Actions**: Create role, click row → role detail.

**API**: `GET /admin/v1/realms/{slug}/roles?client_id=`

#### Role create — modal

| Field       | Type    | Required |
|-------------|---------|----------|
| Name        | text    | yes      |
| Description | textarea| no       |
| Client      | select  | no (empty = realm role) |

#### Role detail — `/admin/realms/{slug}/roles/{name}`

##### Tab: General

Name, description, attributes editor.

##### Tab: Composites

A role can include other roles. Two panels:

- **Included realm roles**: multi-select from available realm roles.
- **Included client roles**: grouped by client, multi-select per client.

**API**: `PUT /admin/v1/realms/{slug}/roles/{name}` (update composites
field)

##### Tab: Assigned users

List of users who have this role directly assigned.

##### Tab: Assigned groups

List of groups who have this role assigned.

**Actions**: Save, Delete role (confirm).

---

### 2.6  Groups — `/admin/realms/{slug}/groups`

#### Group tree + list

Groups are hierarchical. Display as a collapsible tree:

```
/ (root)
├── engineering
│   ├── backend
│   └── frontend
├── marketing
└── finance
```

Table view as alternate layout:

| Column       | Source            |
|--------------|-------------------|
| Path         | `group.path`      |
| Name         | `group.name`      |
| Members      | count             |
| Realm roles  | count             |

**Actions**: Create group (with optional parent), click → group detail.

**API**: `GET /admin/v1/realms/{slug}/groups`

#### Group detail — `/admin/realms/{slug}/groups/{id}`

##### Tab: General

| Field       | Type    | Source          |
|-------------|---------|-----------------|
| Name        | text    | `group.name`    |
| Path        | text    | read-only       |
| Parent      | select  | (for reparenting) |

##### Tab: Attributes

Key-value editor for `group.attributes`.

##### Tab: Role assignments

Assign realm roles and client roles to this group. All group members
inherit these roles.

**API**: `GET/POST/DELETE /admin/v1/realms/{slug}/groups/{id}/roles`

##### Tab: Members

List of users in this group.

| Column    | Source           |
|-----------|------------------|
| Username  | link to user     |
| Email     | `user.email`     |

**Actions**: Add member, remove member.

**API**: `GET/POST/DELETE /admin/v1/realms/{slug}/users/{id}/groups`

---

### 2.7  Organizations — `/admin/realms/{slug}/orgs`

#### Organization list

| Column        | Source                    |
|---------------|---------------------------|
| Alias         | `org.alias`               |
| Display name  | `org.display_name`        |
| Default IdP   | `org.default_idp_alias`   |
| Enabled       | badge                     |

**Actions**: Create org, click row → org detail.

**API**: `GET /admin/v1/realms/{slug}/orgs`

#### Org detail — `/admin/realms/{slug}/orgs/{alias}`

##### Tab: General

| Field            | Type     | Source                   |
|------------------|----------|--------------------------|
| Alias            | text     | read-only                |
| Display name     | text     | `org.display_name`       |
| Description      | textarea | `org.description`        |
| Default IdP      | select   | `org.default_idp_alias`  |
| Redirect URL     | url      | `org.redirect_url`       |
| Enabled          | toggle   | `org.enabled`            |

##### Tab: Branding

| Field          | Type    | Source                        |
|----------------|---------|-------------------------------|
| Logo URL       | url     | `org.branding.logo_url`       |
| Primary color  | color   | `org.branding.primary_color`  |
| Theme          | select  | `org.branding.theme`          |

##### Tab: Domains

| Column       | Source                     |
|--------------|----------------------------|
| Domain       | `domain.domain`            |
| Verified     | badge                      |
| Verified at  | `domain.verified_at`       |

**Actions**: Add domain (generates verification token), Verify domain
(shows DNS TXT record instructions), Remove domain.

**API**: `GET/POST/DELETE /admin/v1/realms/{slug}/orgs/{alias}/domains`

##### Tab: Members

| Column    | Source                      |
|-----------|-----------------------------|
| Username  | link to user detail         |
| Email     | user email                  |
| Roles     | comma-separated org roles   |
| State     | badge (Active/Invited/Suspended) |
| Joined    | `membership.joined_at`      |

**Actions**: Add member (select user + roles), Edit member roles,
Remove member, Suspend/Activate.

**API**: `GET/POST/DELETE /admin/v1/realms/{slug}/orgs/{alias}/memberships`

##### Tab: Invitations

| Column    | Source                      |
|-----------|-----------------------------|
| Email     | `invitation.email`          |
| Roles     | assigned roles              |
| Invited by| `invitation.invited_by`     |
| Expires   | `invitation.expires_at`     |
| Status    | badge (Pending/Accepted/Expired) |

**Actions**: Send invitation (email + roles), Resend, Revoke.

**API**: `GET/POST/DELETE /admin/v1/realms/{slug}/orgs/{alias}/invitations`

##### Tab: Org roles

| Column       | Source              |
|--------------|----------------------|
| Name         | `role.name`          |
| Description  | `role.description`   |
| Permissions  | permission badges    |
| Built-in     | badge                |

Built-in roles (owner, admin, member) shown but not deletable.

**Actions**: Create custom role (name + permissions), Edit, Delete.

**API**: `GET/POST/PUT/DELETE /admin/v1/realms/{slug}/orgs/{alias}/roles`

##### Tab: IdP bindings

| Column    | Source               |
|-----------|----------------------|
| IdP alias | link to IdP detail   |
| Priority  | number               |

**Actions**: Bind IdP (select from realm IdPs), Unbind.

**API**: `GET/POST/DELETE /admin/v1/realms/{slug}/orgs/{alias}/idp-bindings`

##### Tab: Consent policies

Per-client consent override:

| Column        | Source                        |
|---------------|-------------------------------|
| Client        | `policy.client_id`            |
| Mode          | badge (UserDecides/OrgPreApproved/OrgManaged) |
| Pre-approved  | scope list                    |
| Blocked       | scope list                    |

**Actions**: Add policy (select client + mode + scopes), Edit, Delete.

**API**: `GET/POST/DELETE /admin/v1/realms/{slug}/orgs/{alias}/consent-policies`

---

### 2.8  Agents — `/admin/realms/{slug}/agents`

#### Agent list

| Column       | Source                  |
|--------------|--------------------------|
| Alias        | `agent.alias`            |
| Display name | `agent.display_name`     |
| Kind         | badge (Assistant/Scraper/Webhook/Batch/Custom) |
| Vendor       | `agent.vendor`           |
| Model hint   | `agent.model_hint`       |
| Parent       | user / service-account / org |
| Enabled      | badge                    |

**Actions**: Create agent, click row → agent detail.

**API**: `GET /admin/v1/realms/{slug}/agents`

#### Agent detail — `/admin/realms/{slug}/agents/{alias}`

##### Tab: General

| Field          | Type     | Source                    |
|----------------|----------|---------------------------|
| Alias          | text     | read-only                 |
| Display name   | text     | `agent.display_name`      |
| Kind           | select   | `agent.kind`              |
| Model hint     | text     | `agent.model_hint`        |
| Vendor         | text     | `agent.vendor`            |
| Version        | text     | `agent.version`           |
| Parent subject | text     | read-only (immutable)     |
| Auth method    | select   | PrivateKeyJwt/DpopBoundKey/TokenExchangeOnly |
| Enabled        | toggle   |                           |
| Expires at     | datetime |                           |

##### Tab: Capabilities

Repeater of URN-based capabilities:

| Column    | Source                      |
|-----------|-----------------------------|
| URN       | `capability.urn` (e.g. `tool:read-files`) |
| Config    | JSON                        |

**Actions**: Add capability, edit config, remove.

##### Tab: Scopes & audiences

- **Allowed scopes**: multi-select tag input.
- **Allowed audiences**: multi-select tag input.

##### Tab: Rate limits

| Field                 | Type   | Source                        |
|-----------------------|--------|-------------------------------|
| Requests per minute   | number | `rate_limit.requests_per_minute` |
| Tokens per day        | number | `rate_limit.tokens_per_day`   |

##### Tab: Public key

JWK display/upload for `private_key_jwt` or `dpop_bound_key` auth.

**Actions**: Save, Revoke agent (confirm), Delete (confirm).

**API**: `GET/PUT/DELETE /admin/v1/realms/{slug}/agents/{alias}`

---

### 2.9  Authentication flows — `/admin/realms/{slug}/flows`

#### Flow list

| Column       | Source               |
|--------------|----------------------|
| Alias        | `flow.alias`         |
| Display name | `flow.display_name`  |
| Version      | `flow.version`       |
| Nodes        | count                |

Built-in flows shown with a badge. Cannot delete built-in flows.

**Actions**: Create custom flow, click row → flow editor.

#### Flow editor — `/admin/realms/{slug}/flows/{alias}`

The flow editor is the **one** admin page that requires extensive
client-side state and hydration. It is implemented as a Leptos
**island**: the server renders the static skeleton; a hydrated
sub-tree loads on demand.

**Canvas view** (primary): SVG-based node graph with drag-to-reposition.

- Node types rendered as styled rectangles: Start (green), Authenticator
  (blue), Broker (purple), Switch (orange), SubFlow (gray), Action
  (yellow), Success (green check), Failure (red X).
- Edges rendered as SVG paths with arrowheads.
- Click node → property panel (side drawer).
- Drag from output port → new edge.
- Delete node/edge via context menu or keyboard.
- Guard expressions on conditional edges.

**JSON view** (fallback): raw JSON editor with syntax highlighting.
Server-side validation on save (`geonosis_flow::compile`).

**Dry run** panel: paste a synthetic context, POST to
`/admin/v1/realms/{slug}/flows/{alias}/dry-run`, display step-by-step
execution trace.

Graph state lives client-side during editing; save POSTs the full
graph (JSON form of the DSL) and the server-side validator returns
errors inline.

**API**: `GET/PUT /admin/v1/realms/{slug}/flows/{alias}`,
`POST /admin/v1/realms/{slug}/flows/{alias}/dry-run`

---

### 2.10  Identity providers — `/admin/realms/{slug}/idps`

#### IdP list

| Column       | Source                   |
|--------------|---------------------------|
| Alias        | `idp.alias`               |
| Display name | `idp.display_name`        |
| Kind         | badge (OIDC / SAML)       |
| Enabled      | badge                     |

**Actions**: Add IdP, click row → IdP detail.

**API**: `GET /admin/v1/realms/{slug}/idps`

#### IdP create — form

Step 1: Select kind (OIDC or SAML) + alias.
Step 2: Protocol-specific configuration.

#### IdP detail — `/admin/realms/{slug}/idps/{alias}`

##### Tab: General

| Field               | Type    | Source                          |
|---------------------|---------|----------------------------------|
| Alias               | text    | read-only                        |
| Display name        | text    | `idp.display_name`               |
| Kind                | badge   | read-only                        |
| Enabled             | toggle  | `idp.enabled`                    |
| Link only           | toggle  | `idp.link_only`                  |
| First-login flow    | select  | `idp.first_login_flow_alias`     |
| Post-login flow     | select  | `idp.post_login_flow_alias`      |
| Adapter URN         | text    | `idp.adapter_urn` (optional)     |

##### Tab: OIDC configuration (when kind == Oidc)

| Field                  | Type    | Source                        |
|------------------------|---------|-------------------------------|
| Issuer                 | url     | `config.issuer`               |
| Discovery URL          | url     | override (optional)           |
| Authorization endpoint | url     | override (optional)           |
| Token endpoint         | url     | override (optional)           |
| Userinfo endpoint      | url     | override (optional)           |
| JWKS URI               | url     | override (optional)           |
| Client ID              | text    | `config.client_id`            |
| Client secret          | secret  | `config.client_secret`        |
| Scopes                 | multi   | `config.scopes`               |
| PKCE                   | toggle  | `config.pkce`                 |
| Client auth method     | select  | `config.client_auth`          |
| Prompt                 | select  | none/consent/login/select_account |

##### Tab: SAML configuration (when kind == Saml)

Entity ID, SSO URL, SLO URL, signing certificates, bindings,
NameID format, signature validation settings.

##### Tab: Mappers

List of attribute mappers applied to assertions from this IdP.
Each mapper transforms external claims → Geonosis user attributes.

**Actions**: Save, Delete IdP (confirm).

**API**: `GET/PUT/DELETE /admin/v1/realms/{slug}/idps/{alias}`

---

### 2.11  Federation — `/admin/realms/{slug}/federation`

#### LDAP source list

| Column    | Source                   |
|-----------|---------------------------|
| Alias     | `source.alias`            |
| Server    | `config.server`           |
| Base DN   | `config.base_dn`          |
| Priority  | `source.priority`         |
| Enabled   | badge                     |

**Actions**: Add LDAP source, click row → detail.

#### LDAP source detail

##### Tab: Connection

| Field       | Type    | Source               |
|-------------|---------|----------------------|
| Alias       | text    | read-only            |
| Server URL  | url     | `config.server`      |
| Bind DN     | text    | `config.bind_dn`     |
| Bind secret | secret  | `config.bind_secret` |
| Base DN     | text    | `config.base_dn`     |
| TLS mode    | select  | None/StartTLS/LDAPS  |
| Page size   | number  | `config.page_size`   |

##### Tab: Attribute mapping

Repeater mapping LDAP attributes to Geonosis user fields:

| LDAP attribute | Geonosis field | Sync direction |
|----------------|----------------|----------------|
| `cn`           | `username`     | Read-only      |
| `mail`         | `email`        | Read-only      |
| `givenName`    | `firstName`    | Read/Write     |

##### Tab: Sync

| Field                  | Type    | Source                    |
|------------------------|---------|---------------------------|
| Full sync schedule     | cron    | `sync_policy.full`        |
| Changed-only schedule  | cron    | `sync_policy.incremental` |

**Actions**: Trigger sync now, View last sync status.

**API**: `GET/PUT/DELETE /admin/v1/realms/{slug}/federation/{alias}`

---

### 2.12  SPI plugins — `/admin/realms/{slug}/spi`

#### Module list

| Column       | Source                     |
|--------------|----------------------------|
| Alias        | `module.alias`             |
| SHA-256      | truncated hash             |
| Size         | bytes                      |

**Actions**: Upload WASM module.

**API**: `GET /admin/v1/realms/{slug}/spi/modules`,
`POST /admin/v1/realms/{slug}/spi/install`

#### Binding list

| Column       | Source                       |
|--------------|-------------------------------|
| Interface    | `binding.interface`           |
| Provider URN | `binding.provider_urn`        |
| Origin       | badge (Builtin / WASM)        |
| Priority     | `binding.priority`            |
| Enabled      | badge                         |

**Actions**: Create binding, edit priority/config, disable, delete.

**API**: `GET/POST/PUT/DELETE /admin/v1/realms/{slug}/spi/bindings`

---

### 2.13  Sessions — `/admin/realms/{slug}/sessions`

#### Session list

| Column      | Source                    |
|-------------|---------------------------|
| Session ID  | truncated                 |
| User        | link to user detail       |
| Auth level  | badge (Single/MFA/...)    |
| IdP         | `session.idp_alias`       |
| Started     | `session.started_at`      |
| Last seen   | `session.last_seen_at`    |
| Clients     | count                     |

**Filter**: by user ID, by start date range.

**Actions**: Revoke session (delete with confirmation), Revoke all
sessions for a user.

**API**: `GET /admin/v1/realms/{slug}/sessions`,
`DELETE /admin/v1/realms/{slug}/sessions/{id}`

---

### 2.14  Audit events — `/admin/realms/{slug}/events`

#### Event viewer

| Column      | Source                   |
|-------------|--------------------------|
| Timestamp   | `event.occurred_at`      |
| Actor       | User / Client / System / AdminApi |
| Action      | `event.action` (dotted)  |
| Target      | entity type + ID         |
| Detail      | expandable JSON          |

**Filters**: action (select/text), actor type, date range (from/until),
target type.

Clicking a row expands the detail JSON inline.

**API**: `GET /admin/v1/realms/{slug}/events?action=&actor=&from=&until=&limit=`

---

### 2.15  Keys — `/admin/realms/{slug}/keys`

#### Key list

| Column      | Source               |
|-------------|----------------------|
| Key ID      | `key.id`             |
| Algorithm   | badge (RS256/ES256/EdDSA) |
| Usage       | badge (Sig / Enc)    |
| State       | badge (Active / Legacy / Retired) |
| Created     | `key.created_at`     |
| Rotated     | `key.rotated_at`     |

**Actions**: Generate new key (select algorithm), Rotate active key
(demotes current Active → Legacy, promotes new → Active), Disable key.

JWKS preview: collapsible panel showing the public JWK JSON for each
active key.

**API**: `GET /admin/v1/realms/{slug}/keys`

---

### 2.16  User profile schema — `/admin/realms/{slug}/settings` (Profiles tab)

Alternatively a standalone page at `/admin/realms/{slug}/user-profile`.

#### Attribute list

| Column         | Source                           |
|----------------|----------------------------------|
| Name           | `attr.name`                      |
| Display name   | `attr.display_name`              |
| Group          | `attr.group`                     |
| Required       | badge (Always/Registration/No)   |
| Multivalued    | toggle                           |
| Permissions    | Admin view/edit, User view/edit  |

Built-in attributes (username, email, firstName, lastName) shown with
badge; not removable.

**Actions**: Add attribute, edit attribute (validators, permissions),
reorder, remove.

#### Validator configuration (per attribute)

| Validator          | Config fields           |
|--------------------|--------------------------|
| Length             | min, max                 |
| Pattern            | regex                   |
| Email              | —                       |
| URI                | schemes                 |
| Integer            | min, max                |
| Double             | min, max                |
| Options            | allowed values list     |
| PersonName chars   | —                       |
| Username chars     | —                       |
| Custom (WASM)      | provider URN            |

#### Unmanaged attribute policy

Radio: Reject / Allow / Hidden.

**API**: `GET/PUT /admin/v1/realms/{slug}/user-profile`

---

## 3  Authentication & authorization

### 3.1  Admin login

The admin console is protected by session-based authentication (HTML
UI) and bearer token authentication (REST API).

- `GET /admin/login` — renders login form.
- `POST /admin/login` — validates credentials against the first realm
  (v0.1; multi-realm admin auth planned for v0.1.x). Sets
  `geonosis_admin_sid` cookie (HttpOnly, SameSite=Lax, Path=/admin).
- `POST /admin/logout` — deletes session, clears cookie.
- Unauthenticated browser requests → 302 redirect to `/admin/login`.
- Unauthenticated API requests → 401 with `WWW-Authenticate: Bearer`.

Admin status is determined by the `admin: true` user attribute.

### 3.2  Bearer token auth (API)

API consumers authenticate with `Authorization: Bearer <jwt>`. The
middleware verifies the JWT signature via the realm's KMS, checks
expiration, and requires `"admin"` in `realm_access.roles`.

### 3.3  Audit trail

Every state-changing admin action emits an `AuditEvent` with
`Actor::AdminApi { user_id, ip }`. The action namespace follows the
dotted convention: `realm.created`, `user.updated`, `client.deleted`,
`flow.updated`, `agent.revoked`, etc.

---

## 4  Architecture

### 4.1  Two surfaces, one runtime

| Surface | Path | Audience |
|---|---|---|
| Login / consent / account pages | `/realms/{slug}/login-actions/...` | end users |
| Admin console | `/admin/...` | realm admins |

Both are Leptos applications sharing `geonosis-ui-kit` primitives.
They live in separate modules because their auth contexts and threat
models differ.

### 4.2  Layered crate structure

```
┌───────────────────────────────────────────────────────────┐
│                  geonosis-admin-ui (crate)                │
│                                                           │
│   ┌─────────────────────────────────────────────────┐     │
│   │  routes (Leptos routes + server functions)      │     │
│   │   - realms, users, clients, flows, orgs, ...    │     │
│   └────────────────────────────┬────────────────────┘     │
│                                │                          │
│   ┌────────────────────────────▼────────────────────┐     │
│   │  view components                                │     │
│   │   - <UserTable/>, <ClientForm/>, <FlowEditor/>  │     │
│   │   - <OrgMemberList/>, <RoleComposites/>         │     │
│   └────────────────────────────┬────────────────────┘     │
│                                │                          │
│   ┌────────────────────────────▼────────────────────┐     │
│   │  design system (geonosis-ui-kit)                │     │
│   │   - <Button/>, <Card/>, <Field/>, <Toast/>      │     │
│   │   - <Badge/>, <Table/>, <TabBar/>, <Modal/>     │     │
│   │   - tokens (colors, spacing, type) via CSS vars │     │
│   └─────────────────────────────────────────────────┘     │
└───────────────────────────────────────────────────────────┘
```

### 4.3  Admin REST API

The admin UI is a thin layer over a versioned REST API. Every page
consumes one or more `/admin/v1/...` endpoints. The full endpoint
inventory:

```
# Realms
GET/POST         /admin/v1/realms
GET/PUT/DELETE   /admin/v1/realms/{slug}

# Clients
GET/POST         /admin/v1/realms/{slug}/clients
GET/PUT/DELETE   /admin/v1/realms/{slug}/clients/{client_id}

# Users
GET/POST         /admin/v1/realms/{slug}/users
GET/PUT/DELETE   /admin/v1/realms/{slug}/users/{username}
POST             /admin/v1/realms/{slug}/users/{username}/verify-email
PUT              /admin/v1/realms/{slug}/users/{username}/password

# User profile schema
GET/PUT          /admin/v1/realms/{slug}/user-profile

# Roles
GET/POST         /admin/v1/realms/{slug}/roles
GET/PUT/DELETE   /admin/v1/realms/{slug}/roles/{name}
GET/POST         /admin/v1/realms/{slug}/users/{id}/roles
DELETE           /admin/v1/realms/{slug}/users/{id}/roles/{name}
GET/POST         /admin/v1/realms/{slug}/groups/{id}/roles
DELETE           /admin/v1/realms/{slug}/groups/{id}/roles/{name}

# Groups
GET/POST         /admin/v1/realms/{slug}/groups
GET/PUT/DELETE   /admin/v1/realms/{slug}/groups/{id}
GET/POST         /admin/v1/realms/{slug}/users/{id}/groups
DELETE           /admin/v1/realms/{slug}/users/{id}/groups/{group_id}

# Organizations
GET/POST         /admin/v1/realms/{slug}/orgs
GET/PUT/DELETE   /admin/v1/realms/{slug}/orgs/{alias}
GET/POST/DELETE  /admin/v1/realms/{slug}/orgs/{alias}/domains
GET/POST/DELETE  /admin/v1/realms/{slug}/orgs/{alias}/memberships
GET/POST/DELETE  /admin/v1/realms/{slug}/orgs/{alias}/invitations
POST             /admin/v1/realms/{slug}/orgs/{alias}/invitations/{token}/accept
GET/POST         /admin/v1/realms/{slug}/orgs/{alias}/roles
PUT/DELETE       /admin/v1/realms/{slug}/orgs/{alias}/roles/{name}
GET/POST/DELETE  /admin/v1/realms/{slug}/orgs/{alias}/consent-policies
GET/POST/DELETE  /admin/v1/realms/{slug}/orgs/{alias}/idp-bindings

# Agents
GET/POST         /admin/v1/realms/{slug}/agents
GET/PUT/DELETE   /admin/v1/realms/{slug}/agents/{alias}

# Identity providers
GET/POST         /admin/v1/realms/{slug}/idps
GET/PUT/DELETE   /admin/v1/realms/{slug}/idps/{alias}

# Flows
GET/PUT          /admin/v1/realms/{slug}/flows/{alias}
POST             /admin/v1/realms/{slug}/flows/{alias}/dry-run

# Sessions
GET              /admin/v1/realms/{slug}/sessions
DELETE           /admin/v1/realms/{slug}/sessions/{id}

# Audit events
GET              /admin/v1/realms/{slug}/events

# Keys
GET              /admin/v1/realms/{slug}/keys

# SPI
GET              /admin/v1/realms/{slug}/spi
POST             /admin/v1/realms/{slug}/spi/install
```

Errors follow RFC 7807 (problem+json) with stable `type` URIs.

---

## 5  Theming

### 5.1  Component overrides

A `Theme` is a directory:

```
my-theme/
├── theme.toml
├── login/
│   ├── login.html
│   ├── otp.html
│   ├── overrides.rs.wasm
│   └── assets/
│       ├── logo.svg
│       └── theme.css
└── email/
    ├── verify-email.html
    └── ...
```

Two override mechanisms:

1. **Template overlay** — plain HTML/CSS, no recompile. Replaces a
   named page entirely. Falls back through theme → parent-theme →
   built-in. Hot-reloadable by file watcher.
2. **Component override** — a Leptos component compiled to WASM
   exporting `geonosis:ui-component@0.1.0`. The renderer asks the
   registry for a named component; if the realm's theme provides one,
   it is used instead of the built-in.

### 5.2  Slot-based component API

Every built-in page is decomposed into named slots. The theme can
replace any slot without redefining the page.

### 5.3  Internationalization

- All user-facing strings are i18n keys.
- Translation bundles in `geonosis-i18n` as FTL files (Project Fluent).
- Themes can overlay built-in translations.
- Negotiation: explicit user pref > realm default > `Accept-Language` > en.

### 5.4  Theme sandbox

A theme is operator-supplied code and may be buggy or hostile.

| Concern | Defense |
|---|---|
| Read other realms' data | Template variables scoped to current realm; templates have no I/O primitives. |
| Exfiltrate via outbound request | CSP `default-src 'self'`; remote assets blocked. |
| XSS | All substitutions HTML-escaped; `unsafe_inner_html` linted. |
| Steal cookies | `HttpOnly` cookies; CSRF double-submit. |
| Override admin chrome | Themes apply to login surface only; admin chrome is non-overridable. |

---

## 6  Hot reload

| Change | Mechanism |
|---|---|
| Template file edited | `notify` watcher → invalidate render cache |
| Theme assets edited | Content-hash URLs; updated on next request |
| Component override module updated | WASM SPI hot-swap |
| Theme binding changed (realm setting) | DB write → `NOTIFY` → cache invalidate |
| User profile schema updated | Cache invalidate; forms reload within ~100 ms |

---

## 7  Accessibility, i18n, and security baselines

- All forms have explicit labels, `aria-describedby`, focus rings.
- Targets WCAG 2.1 AA.
- **RTL day-one**: CSS logical properties (`margin-inline-start`,
  `padding-block-end`); `dir="auto"` on text containers. CI lint
  forbids physical-axis CSS.
- CSP enforced: `default-src 'self'`, `style-src 'nonce-...'`,
  `script-src 'nonce-...'`.
- HTML escaped by default; `unsafe_inner_html` linted.

---

## 8  End-to-end testing

Playwright in CI for the admin UI:

- SVG/canvas interactions (flow editor).
- Vendor-neutral: headless Chromium / Firefox / WebKit.
- Visual-regression snapshotting.
- Test fixtures: clean Postgres + deterministic seed realm.
- Complementary `cargo nextest` smoke harness for backend-only paths.

Trade-off: Node toolchain in CI, isolated in its own Dockerfile.

---

## 9  Delivery tiers

### v0.1 (current)

- Realm list + detail dashboard.
- Client list + basic create.
- User list (placeholder; search pending).
- Role, group, org, agent, IdP, session, event list views.
- Flow editor (canvas view + JSON fallback).
- Admin login/logout with session cookies.
- Dark mode only.

### v0.1.x (next)

**Chrome & UX**:
- **Grouped sidebar** — Manage / Configure / Extensions / Monitor
  groups with collapsible headers.
- **Profile icon** in header — opens `/admin/profile` page (password
  change, MFA setup, session management, sign out).
- **Light / dark mode toggle** — sun/moon icon in header; persisted in
  `localStorage`; respects `prefers-color-scheme`.
- **Realm selector dropdown** in header.
- **Breadcrumb navigation** on all detail pages.
- **Larger fonts and buttons** — base 15 px, buttons with generous
  padding.
- **Responsive mobile layout** — hamburger sidebar, stacked card
  tables, full-width buttons, horizontally scrollable tabs.

**Pages**:
- **Realm settings** — all policy tabs (login, sessions, tokens,
  password, brute force, OTP, WebAuthn, themes, localization, events,
  ACR, org policy, default roles/groups).
- **Client detail** — all tabs (URIs, grants, scopes, flow bindings,
  consent, token overrides, logout, SAML, auth keys).
- **User detail** — all tabs (general, attributes, credentials, roles,
  groups, orgs, sessions, consents).
- **User profile page** (`/admin/profile`) — own account management
  (password, OTP, WebAuthn, sessions, sign out).
- **Role detail** — composites, attribute editor, assigned users/groups.
- **Group detail** — hierarchy tree, members, role assignments.
- **Organization full UI** — all tabs (general, branding, domains,
  members, invitations, org roles, IdP bindings, consent policies).
- **Agent detail** — capabilities, scopes, rate limits, public key.
- **IdP detail** — OIDC/SAML config forms, mapper bindings.
- **Session revocation** — inline revoke button.
- **Keys** — list with rotate/disable actions.
- **User profile schema editor**.

### v0.2

- Federation (LDAP) admin pages.
- SPI plugin management (upload, bind, configure).
- Full-text search across entities.
- Pagination with cursor support.
- Bulk operations (delete multiple, export/import).
- Audit event analytics and export.
- SMTP configuration page.
- Test-mode realms.
- Admin RBAC (role-based access within admin console).
- User impersonation.

---

## 10  Non-goals

- **Client-side state libraries** (Redux/SWR) — Leptos signals suffice.
- **Server-driven SPA** as main mode — classical form submits;
  only the flow editor escalates.
- **Native mobile admin** — out of scope.
- **Drag-drop UI builder** for login pages — themes are file/code.
  Visual builder for flows only.
