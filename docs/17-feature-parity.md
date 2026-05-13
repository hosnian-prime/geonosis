# 17 — Feature Scope Audit

A living map of the **target feature surface** for an enterprise
IAM and Geonosis's coverage of each item. Each row tells you
**where in our docs/code** the feature lives, **what we have**,
and **what's deferred**. When a feature is commonly expected and
we do not provide it, the row makes that explicit.

The audit is organized to match the navigation an experienced IAM
operator expects: realm settings, clients, roles, groups, users,
identity providers, federation, flows, organizations, sessions,
events, SPI surface, admin API, account console.

## Legend

- ✅ in scope, declared in v0.1
- 🟡 in scope, deferred to v0.2 (or noted phase)
- 🔵 in scope, deferred to v1.x (Komino / major)
- 🚫 explicit non-goal
- 🤔 open / undecided

## Realm settings → General

| Feature | Status | Where |
|---|---|---|
| Realm enabled toggle | ✅ | `Realm.enabled` |
| Realm display name | ✅ | `Realm.display_name` + `display_name_html` |
| Frontend URL | ✅ | `Realm.frontend_url` |
| Require SSL | ✅ | `Realm.ssl_required` |
| ACR-to-LoA mapping | ✅ | `Realm.acr_policy` ([`12-security-crypto.md`](./12-security-crypto.md)) |
| User-managed access allowed | 🚫 | UMA is a non-goal in v0.1 |

## Realm settings → Login

| Feature | Status | Where |
|---|---|---|
| User registration | ✅ | `LoginSettings.user_registration_allowed` |
| Forgot password | ✅ | `LoginSettings.forgot_password_allowed` |
| Remember me | ✅ | `LoginSettings.remember_me_allowed` |
| Login with email | ✅ | `LoginSettings.login_with_email_allowed` |
| Email as username | ✅ | `LoginSettings.email_as_username` |
| Duplicate emails | ✅ | `LoginSettings.duplicate_emails_allowed` |
| Verify email required | ✅ | `LoginSettings.verify_email_required` |
| Edit username | ✅ | `LoginSettings.edit_username_allowed` |
| Passwordless login (WebAuthn) | 🟡 | `LoginSettings.passwordless_login_allowed`; first-class WebAuthn lifecycle v0.2 |
| User-managed access | 🚫 | UMA non-goal |

## Realm settings → Email

| Feature | Status | Where |
|---|---|---|
| SMTP host/port | ✅ | `Realm.smtp.host`, `port` |
| From address + display name | ✅ | `Realm.smtp.from`, `from_display_name` |
| Reply-to | ✅ | `Realm.smtp.reply_to` |
| Envelope from | ✅ | `Realm.smtp.envelope_from` |
| Enable SSL / StartTLS | ✅ | `Realm.smtp.ssl`, `starttls` |
| SMTP authentication | ✅ | `Realm.smtp.auth` (Secret<String>) |

## Realm settings → Themes

| Feature | Status | Where |
|---|---|---|
| Login theme | ✅ | `Realm.theme_binding.login` |
| Account theme | ✅ | `Realm.theme_binding.account` |
| Admin theme | ✅ | `Realm.theme_binding.admin` |
| Email theme | ✅ | `Realm.theme_binding.email` |
| Theme overlay (file-based) | ✅ | [`08-admin-ui.md`](./08-admin-ui.md) |
| Component override (Leptos) | ✅ | [`08-admin-ui.md`](./08-admin-ui.md) — slot trait |

## Realm settings → Localization

| Feature | Status | Where |
|---|---|---|
| Internationalization enabled | ✅ | `Realm.localization.internationalization_enabled` |
| Supported locales | ✅ | `Realm.localization.supported_locales` |
| Default locale | ✅ | `Realm.localization.default_locale` |
| Per-theme translation bundles | ✅ | [`08-admin-ui.md`](./08-admin-ui.md) — FTL files |

## Realm settings → Keys (cryptography)

| Feature | Status | Where |
|---|---|---|
| Active / rotated / disabled keys | ✅ | `KeyMaterial.state` |
| Multiple algorithms (RS / ES / EdDSA) | ✅ | `KeyMaterial.alg` |
| HMAC keys for client_secret_jwt | ✅ | KeyMaterial w/ usage=Sig + HS alg |
| HMAC for cookies / refresh hashing | ✅ | [`12-security-crypto.md`](./12-security-crypto.md) |
| External KMS (Vault Transit) | 🟡 | v0.2; trait already there |
| AWS KMS / GCP KMS / Pkcs11 | 🟡 / 🟡 / 🔵 | v0.2.x / v0.2.x / v0.3 |
| BYOK upload | 🤔 | needs spec; v0.2 candidate |

## Realm settings → Sessions

| Feature | Status | Where |
|---|---|---|
| SSO Session Idle / Max | ✅ | `SessionPolicy.sso_session_*` |
| Remember-Me Idle / Max | ✅ | `SessionPolicy.sso_session_*_remember` |
| Offline Session Idle / Max | ✅ | `SessionPolicy.offline_session_*` |
| Login Timeout | ✅ | `SessionPolicy.login_timeout` |
| Login Action Timeout | ✅ | `SessionPolicy.login_action_timeout` |
| Revoke refresh on logout | ✅ | `TokenPolicy.revoke_refresh_token_on_logout` |

## Realm settings → Tokens

| Feature | Status | Where |
|---|---|---|
| Default Signature Algorithm | ✅ | `TokenPolicy.access_token_signing_alg` / `id_token_signing_alg` |
| Userinfo Signed Response Algorithm | ✅ | `TokenPolicy.userinfo_signing_alg` |
| Refresh Token Rotation | ✅ | `TokenPolicy.refresh_token_rotation` |
| Access Token Lifespan | ✅ | `TokenPolicy.access_token_lifespan` |
| Authorization Code Lifespan | ✅ | `TokenPolicy.authorization_code_lifespan` |
| Action Token Lifespans (admin- and user-initiated) | ✅ | `SessionPolicy.action_token_lifespan*` |
| OAuth 2.0 device polling interval | 🤔 | hard-coded to 5 s in v0.1; configurable in v0.2 |

## Realm settings → Security defenses

| Feature | Status | Where |
|---|---|---|
| Browser security headers (X-Frame, CSP, HSTS, ...) | ✅ | `Realm.security_headers` |
| Brute force detection | ✅ | `Realm.brute_force` |
| Permanent lockout | ✅ | `BruteForcePolicy.permanent_lockout` |
| Quick login check window | ✅ | `BruteForcePolicy.quick_login_check_window` |
| Failure reset window | ✅ | `BruteForcePolicy.failure_reset_window` |

## Realm settings → Authentication policies

| Feature | Status | Where |
|---|---|---|
| Password policy DSL | ✅ | `Realm.password_policy.rules` (`PasswordRule` enum) |
| OTP policy (TOTP / HOTP, digits, period) | ✅ | `Realm.otp_policy` |
| WebAuthn policy | ✅ | `Realm.webauthn_policy`, `webauthn_passwordless_policy` |
| CIBA policy | 🚫 | DEFERRED |

## Realm settings → Events

| Feature | Status | Where |
|---|---|---|
| Login events enabled | ✅ | `EventConfig.login_events_enabled` |
| Admin events enabled | ✅ | `EventConfig.admin_events_enabled` |
| Saved event types filter | ✅ | `EventConfig.login_event_types` / `admin_event_types` |
| Event listeners (sinks) | ✅ | `EventSink` rows; built-in: Postgres, Webhook |
| Kafka / cloud sinks | 🟡 | v0.2 |
| Retention | ✅ | `EventConfig.retention_days` |
| Include representation in admin events | ✅ | `EventConfig.admin_events_include_representation` |

## Realm settings → Localization

(See above.)

## Realm settings → User profile

| Feature | Status | Where |
|---|---|---|
| Declarative user-profile schema | ✅ | [`16-user-profile.md`](./16-user-profile.md) |
| Built-in attributes (username, email, firstName, lastName) | ✅ | Default schema |
| Custom attribute validators | ✅ | `AttributeValidator` enum + WASM `Custom` |
| Attribute groups | ✅ | `UserAttributeGroup` |
| Permissions per attribute | ✅ | `AttributePermissions` |
| Unmanaged attribute policy | ✅ | `Reject` / `Allow` / `Hidden` |

## Clients

| Feature | Status | Where |
|---|---|---|
| Client ID / Name / Description | ✅ | `Client.client_id`, `name`, `description` |
| Client kind (public/confidential/bearer-only/service-account) | ✅ | `Client.kind` |
| Standard / Implicit / Direct / Service-accounts / Device / CIBA grant toggles | ✅ / 🚫 / ✅ / ✅ / ✅ / 🚫 | `Client.grants` |
| Redirect URIs | ✅ | `Client.redirect_uris` |
| Post-logout URIs | ✅ | `Client.post_logout_uris` |
| Web origins (CORS) | ✅ | `Client.web_origins` |
| Root / Base / Admin URL | ✅ | `Client.root_url`, `base_url`, `admin_url` |
| Logo / Policy / Terms URIs | ✅ | `Client.logo_uri`, `policy_uri`, `tos_uri` |
| Client authentication method | ✅ | `Client.auth_method` |
| Front-channel logout | ✅ | `Client.front_channel_logout_*` |
| Back-channel logout | ✅ | `Client.backchannel_logout_*` |
| Backchannel revoke offline sessions | ✅ | `Client.backchannel_logout_revoke_offline_sessions` |
| Authorization Services / UMA | 🚫 | non-goal v0.1 |
| Client scopes (default + optional) | ✅ | `Client.default_scopes` / `optional_scopes` |
| Client roles | ✅ | `Role.scope = ClientRole(client_id)` |
| Service account user | ✅ | `Client.service_account_user_id` |
| Pairwise sub algorithm | ✅ | `Client.pairwise_sub_algorithm` |
| Access token type (JWT/opaque) | ✅ | `Client.access_token_type` |
| Include AMR / session id in token | ✅ | `Client.include_authn_amr_in_id_token`, `include_session_id_in_token` |
| Token signing alg overrides | ✅ | `Client.access_token_signing_alg`, `id_token_signing_alg` |
| Sender-constraint (DPoP/mTLS) | 🟡 | `Client.sender_constraint`; impl v0.2 |
| FAPI level | 🟡 | `Client.fapi_level`; profile enforcement v0.2 |
| Display in console toggles | ✅ | `Client.display_in_console`, `always_display_in_console` |
| Refresh-token behavior | ✅ | `Client.use_refresh_tokens`, `use_refresh_tokens_for_client_credentials` |
| Client policies (registration policies) | 🟡 | v0.2; modeled as WASM `policy` SPI |
| Token / userinfo / id-token mappers | ✅ | Built-in mapper set + WASM `mapper` SPI |
| Pairwise client scope | ✅ | via `pairwise_sub_algorithm` |

## Roles

| Feature | Status | Where |
|---|---|---|
| Realm-level roles | ✅ | `Role.scope = RealmRole` |
| Client-level roles | ✅ | `Role.scope = ClientRole(...)` |
| Composite roles | ✅ | `Role.composites` |
| Default roles | ✅ | `Realm.default_roles` |
| Role attributes | 🤔 | not in v0.1 type; consider for v0.2 |

## Groups

| Feature | Status | Where |
|---|---|---|
| Hierarchical groups | ✅ | `Group.parent_id` + `path` |
| Group attributes | ✅ | `Group.attributes` |
| Group-assigned roles | ✅ | `Group.assigned_roles` |
| Default groups | ✅ | `Realm.default_groups` |
| Group memberships through LDAP | ✅ | [`04-federation-ldap.md`](./04-federation-ldap.md) Group sync |

## Users

| Feature | Status | Where |
|---|---|---|
| Username, email, name | ✅ | `User.username`, `email`, `name` |
| Email verified flag | ✅ | `User.email_verified` |
| Free-form attributes | ✅ | `User.attributes` |
| Declarative attribute schema | ✅ | [`16-user-profile.md`](./16-user-profile.md) |
| Required actions | ✅ | `User.required_actions` |
| Forced flow | ✅ | `User.required_flow` |
| User credentials (password / OTP / WebAuthn / recovery) | ✅ | `Credential` rows |
| Federation linkage | ✅ | `User.federation: Option<FederationLink>` |
| Federated identity (broker links) | ✅ | broker link rows; one per IdP per user |
| Sessions list | ✅ | `Session` rows |
| Consents list | ✅ | persisted consent records |
| Impersonation (admin signs in as user) | 🟡 | v0.2; explicit audit + restricted role |
| Sub-user / parent-user hierarchy | 🚫 | not a standard IAM concept |

## Identity providers (broker)

| Feature | Status | Where |
|---|---|---|
| OIDC IdPs (generic) | ✅ | core OIDC adapter |
| SAML 2.0 IdPs (we as SP) | ✅ | core SAML adapter |
| Vendor-specific quirks (Google, GitHub, Apple, Microsoft) | ✅ | first-party SPI plugins `spi-google`/`spi-github`/`spi-apple`/`spi-microsoft` |
| Mapper bindings (claim → attribute, role mapping, ...) | ✅ | `MapperBinding`; built-in + WASM |
| First-broker-login flow | ✅ | per-IdP `first_login_flow` |
| Post-login flow | ✅ | per-IdP `post_login_flow` |
| Account linking | ✅ | broker-link rows; flow-driven |
| Sync mode (Import vs ForceFetch) | ✅ | `IdentityProvider.sync_mode` |
| Issuer overrides / hosted domain | ✅ | per `OidcIdpConfig` |
| WS-Federation / CAS | 🚫 | non-goal |
| As-IdP for SAML SPs | 🟡 | v0.2 |

## User federation

| Feature | Status | Where |
|---|---|---|
| LDAP / AD federation | ✅ | [`04-federation-ldap.md`](./04-federation-ldap.md) |
| Pass-through bind / mirror / sync modes | ✅ | `FederationSource.write_policy`, `sync_policy` |
| AD-specific (tombstone, sAMAccountName, objectGUID) | ✅ | spec'd |
| Group sync | ✅ | `GroupSyncConfig` |
| Kerberos / SPNEGO | 🟡 | v0.2 via `spi-kerberos` |
| Custom federation source | ✅ | WASM `geonosis:federation@0.1.0` |

## Authentication flows

| Feature | Status | Where |
|---|---|---|
| Browser flow | ✅ | [`06-auth-flows.md`](./06-auth-flows.md) |
| Direct grant flow | ✅ | built-in `direct-grant` |
| Registration flow | ✅ | built-in `registration` |
| Reset credentials flow | ✅ | built-in `reset-credentials` |
| First broker login flow | ✅ | built-in `first-broker-login` |
| Client authentication flow | ✅ | built-in `client-authentication` |
| Step-up authentication | ✅ | `step-up` flow kind, `acr_policy`-driven |
| Custom authenticators | ✅ | built-in + WASM `geonosis:authn` |
| Required actions | ✅ | `User.required_actions` + built-in subflows |
| Visual editor | ✅ | [`06-auth-flows.md`](./06-auth-flows.md) + [`08-admin-ui.md`](./08-admin-ui.md) |
| Conditional execution (guard) | ✅ | tiny pure-evaluation language on edges |

## Organizations (B2B SaaS sub-realm grouping)

| Feature | Status | Where |
|---|---|---|
| Organization entity | ✅ | [`15-organizations.md`](./15-organizations.md) |
| Members / invitations | ✅ | `OrgMembership`, `OrgInvitation` |
| Domain claim + verification | ✅ | `OrgDomain` |
| Per-org IdP binding | ✅ | URL `/orgs/{alias}/idps` |
| Per-org roles | ✅ | `OrgRole` |
| Branding (logo, color, banner) | ✅ | `OrganizationBranding` |
| Token `org` claim | ✅ | claim shape spec'd |
| Auto-join on verified domain | ✅ | `OrganizationPolicy.auto_join_on_domain_match` |

## Sessions

| Feature | Status | Where |
|---|---|---|
| Browser SSO sessions | ✅ | `Session` |
| Offline sessions (refresh tokens) | ✅ | `RefreshToken` + `family_id` |
| Session list per user | ✅ | admin API |
| Revoke single session | ✅ | admin API + audit |
| Revoke all sessions of a user | ✅ | admin API |

## Events

| Feature | Status | Where |
|---|---|---|
| Login event log | ✅ | `audit_event` |
| Admin event log | ✅ | `audit_event` (admin actor kinds) |
| Event filters | ✅ | `EventConfig.login_event_types` / `admin_event_types` |
| Built-in webhook sink | ✅ | `EventSink kind=Webhook` |
| Kafka / cloud sinks | 🟡 | v0.2 |
| Event-driven trigger (SPI) | ✅ | WASM `geonosis:event` |

## Extensibility (SPI)

| Reference SPI category | Geonosis WIT | v0.1 |
|---|---|---|
| User-storage / federation provider | `geonosis:user-storage@0.1.0` | ✅ |
| Authenticator | `geonosis:authn@0.1.0` | ✅ |
| Event listener | `geonosis:event@0.1.0` | ✅ |
| OIDC / SAML protocol mapper | `geonosis:mapper@0.1.0` | ✅ |
| Policy provider | `geonosis:policy@0.1.0` | ✅ |
| Identity-provider vendor adapter | `geonosis:broker-adapter@0.1.0` | ✅ |
| Key provider (BYOK) | trait `KeyManagementService` | ✅ (Software in v0.1; Vault v0.2) |
| User-profile attribute validator | `geonosis:user-profile-validator@0.1.0` | ✅ |
| Override mode (replace / decorate / chain built-ins) | provider registry — see [`07-spi-wasm.md`](./07-spi-wasm.md) | ✅ |
| Authoring language | Rust v0.1, Go + JS v0.2, Python deferred |

## Admin REST API

| Feature | Status | Where |
|---|---|---|
| `/admin/v1/realms` CRUD | ✅ | [`08-admin-ui.md`](./08-admin-ui.md) |
| Users / Clients / Roles / Groups / Sessions / Events | ✅ | same |
| Organizations | ✅ | [`15-organizations.md`](./15-organizations.md) |
| Bulk import / export | 🟡 | v0.2 (`geoctl realm export/import`) |
| Incumbent-IAM import (realm export → Geonosis) | 🟡 | wishlist v0.2 / not committed |

## Account console (end-user portal)

| Feature | Status | Where |
|---|---|---|
| View profile | 🟡 | v0.2 |
| Edit profile (declared attributes) | 🟡 | v0.2 |
| List active sessions | 🟡 | v0.2 |
| Revoke own sessions | 🟡 | v0.2 |
| Add/remove WebAuthn credentials | 🟡 | v0.2 |
| Linked accounts (broker) | 🟡 | v0.2 |
| Org memberships management | 🟡 | v0.2 |
| GDPR data export / delete | 🤔 | v0.3 candidate |

## Tooling & operational features

| Feature | Status | Notes |
|---|---|---|
| Realm export / import | 🟡 | v0.2 via `geoctl` |
| Authentication Flow import / export | ✅ | v0.1 via `geoctl` (YAML) |
| Theme on disk | ✅ | files under `/themes/...`, watcher; templating engine is ours, not FreeMarker |
| Templates: register, login, otp, idp, email | ✅ | naming follows common IAM conventions |
| Operator CLI | ✅ | `geoctl` |
| Realm import from incumbent IAMs | 🤔 | nice-to-have, not committed |
| Master realm bootstrap | ✅ | inherent |
| Mobile-friendly login | ✅ | responsive themes by default |
| Database upgrade tool | ✅ | `geoctl migrate`, expand-contract |
| HA cache layer | ✅ → 🔵 | Redis in v0.1; Komino replacing Redis in v1.x ([`09-cache-invalidation.md`](./09-cache-invalidation.md)) |
| Multi-site (cross-DC replication) | 🚫 | non-goal v0.1 |
| Backchannel push notification | 🟡 | v0.2 via OIDC back-channel logout + event sinks |

## Where we deliberately differ

| Geonosis | vs. incumbent IAMs | Why |
|---|---|---|
| Rust single binary | Java app servers | Smaller image, faster boot, predictable memory |
| WIT/WASM SPI | Java Service Loader-style SPI | Sandboxing + language-agnostic + hot reload |
| Leptos SSR admin UI | React/Patternfly SPA | Tighter binary, slot-based override, one toolchain |
| Postgres-only storage | many DBs supported | Simplicity; one well-tested target |
| Graph-DSL flows | flat list with `REQUIRED/ALTERNATIVE` | Branching + parallel options without semantic gymnastics |
| Theme = filesystem + WASM | template engine only | Hot reload + Rust-friendly without losing simple overrides |
| `LISTEN`/`NOTIFY` invalidation as alternative | Java-cluster replication | Lighter footprint when no shared cache needed |
| Komino (planned) | embedded JVM caches | Native Rust, gossip-clustered, no JVM |

## How to find your way

If you came here looking for a specific feature from another IAM
and don't see it in the table, check:

1. The **glossary** ([`glossary.md`](./glossary.md)) — some
   features live under slightly different names.
2. The **data model** ([`02-data-model.md`](./02-data-model.md))
   for any field on `Realm` / `Client` / `User` not enumerated above.
3. The **roadmap** ([`14-roadmap.md`](./14-roadmap.md)) for the
   deferred items.

If still nothing, open an issue: it's a missing entry, not a missing
feature decision.
