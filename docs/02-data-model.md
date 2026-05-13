# 02 — Data Model

The Geonosis domain. Entities and their persisted shape. The Rust types
listed here are **normative**: code MUST match these spellings.

## Tenancy

We adopt the **Realm = tenant** model: one server hosts many realms;
each realm is an isolated identity universe.

- A **Realm** owns its users, clients, groups, roles, keys, flows,
  themes, and SPI bindings.
- Cross-realm references are forbidden. The `master` realm exists as
  an administrative bootstrap with users that can administer other
  realms.
- A `realm_id` column exists on **every** tenanted table and is part
  of every primary lookup index. Multi-tenant isolation is enforced
  by query, by RLS policy, and by repository trait boundary.

## Entity catalog

```
┌─────────┐    1   N  ┌────────┐
│  Realm  │──────────►│  User  │
└─────────┘           └────────┘
     │                    │  N         M  ┌────────┐
     │                    └──────────────►│  Role  │
     │                    │  N         M  └────────┘
     │                    └─────────────► ┌────────┐
     │                    │  N         M  │ Group  │
     │                    └─────────────► └────────┘
     │                                    ┌──────────────┐
     │                    └─────────────► │ Organization │
     │                                    └──────────────┘
     │   1     N  ┌─────────┐
     ├───────────►│ Client  │
     │            └─────────┘
     │   1     N  ┌──────────────┐
     ├───────────►│ Organization │
     │            └──────┬───────┘
     │                   │  1   N  ┌──────────────────┐
     │                   ├────────►│ OrgDomain        │
     │                   │         └──────────────────┘
     │                   │  N   M  ┌──────────────────┐
     │                   └────────►│ OrgMembership    │
     │                             └──────────────────┘
     │   1     N  ┌──────────────┐
     ├───────────►│ Identity-    │
     │            │ Provider     │
     │            │ (broker)     │
     │            └──────────────┘
     │   1     N  ┌──────────────┐
     ├───────────►│ Federation   │
     │            │ Source (LDAP)│
     │            └──────────────┘
     │   1     N  ┌──────────────┐
     ├───────────►│ AuthFlow     │
     │            └──────────────┘
     │   1     N  ┌──────────────┐
     ├───────────►│ KeyMaterial  │
     │            └──────────────┘
     │   1     N  ┌──────────────┐
     ├───────────►│ Theme        │
     │            └──────────────┘
     │   1     1  ┌──────────────┐
     ├───────────►│ UserProfile  │   (one schema per realm)
     │            └──────────────┘
     │   1     N  ┌──────────────┐
     ├───────────►│ SmtpServer   │
     │            └──────────────┘
     │   1     N  ┌──────────────┐
     ├───────────►│ EventSink    │
     │            └──────────────┘
     └───────────►│ SpiBinding   │
                  └──────────────┘
```

## Core types (Rust)

```rust
pub struct Realm {
    pub id: RealmId,                    // ULID
    pub slug: String,                   // url path segment, [a-z0-9-]
    pub display_name: String,
    pub display_name_html: Option<String>,  // HTML-permitted form for chrome
    pub frontend_url: Option<Url>,      // public-facing base URL (issuer)
    pub admin_frontend_url: Option<Url>,// reverse-proxied admin URL
    pub enabled: bool,
    pub ssl_required: SslRequirement,   // None | ExternalRequests | All

    // — feature toggles (realm login surface) —
    pub login: LoginSettings,           // see below
    pub registration: RegistrationPolicy,
    pub session_policy: SessionPolicy,
    pub token_policy: TokenPolicy,
    pub security_headers: SecurityHeaders,
    pub brute_force: BruteForcePolicy,
    pub password_policy: PasswordPolicy,
    pub otp_policy: OtpPolicy,
    pub webauthn_policy: WebauthnPolicy,
    pub webauthn_passwordless_policy: WebauthnPolicy,

    // — branding / i18n —
    pub theme_binding: ThemeBinding,    // login / account / admin / email theme names
    pub localization: LocalizationPolicy,

    // — operational —
    pub smtp: Option<SmtpServer>,       // for verify-email, reset-password, invitations
    pub events: EventConfig,            // which actions to record + sinks
    pub default_groups: Vec<GroupId>,   // new users auto-added
    pub default_roles: DefaultRoles,    // realm + client default role bindings

    // — protocol —
    pub acr_policy: AcrPolicy,          // see 12-security-crypto.md
    pub sender_constraint_default: SenderConstraint, // none | dpop | mtls (v0.2)

    // — organizations —
    pub organizations_enabled: bool,
    pub organization_policy: Option<OrganizationPolicy>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// All the on/off switches an operator sees under "Realm settings → Login".
pub struct LoginSettings {
    pub user_registration_allowed: bool,
    pub forgot_password_allowed: bool,
    pub remember_me_allowed: bool,
    pub email_as_username: bool,            // username field is filled from email
    pub login_with_email_allowed: bool,     // allow logging in via email
    pub duplicate_emails_allowed: bool,
    pub verify_email_required: bool,
    pub edit_username_allowed: bool,
    pub passwordless_login_allowed: bool,
    pub user_managed_access_allowed: bool,  // UMA 2.0 toggle (off in v0.1)
}

pub struct RegistrationPolicy {
    pub flow: FlowAlias,                    // default "registration"
    pub require_captcha: bool,
    pub require_email_verification: bool,
    pub required_actions: Vec<RequiredAction>, // default required actions for new users
    pub default_locale: Option<Locale>,
    pub allowed_email_domains: Option<Vec<String>>, // wildcard ok
    pub blocked_email_domains: Option<Vec<String>>,
}

pub struct SessionPolicy {
    pub sso_session_idle:           Duration,   // default 30 min
    pub sso_session_max:            Duration,   // default 10 h
    pub sso_session_idle_remember:  Duration,   // default 30 d
    pub sso_session_max_remember:   Duration,   // default 365 d
    pub offline_session_idle:       Duration,   // default 30 d
    pub offline_session_max:        Duration,   // default 60 d
    pub login_timeout:              Duration,   // default 30 m  (UI flow wall clock)
    pub login_action_timeout:       Duration,   // default 5 m   (per-step inactivity)
    pub action_token_lifespan:      Duration,   // default 5 m   (admin-initiated)
    pub action_token_lifespan_user: Duration,   // default 5 m   (user-initiated)
    pub revoke_on_password_change:  bool,
}

pub struct TokenPolicy {
    pub access_token_lifespan:           Duration,  // default 5 m
    pub access_token_lifespan_implicit:  Duration,  // default 15 m (deprecated; off in v0.1)
    pub authorization_code_lifespan:     Duration,  // default 1 m  (RFC bound)
    pub id_token_signing_alg:            JwsAlgorithm,
    pub access_token_signing_alg:        JwsAlgorithm,
    pub userinfo_signing_alg:            Option<JwsAlgorithm>,
    pub refresh_token_rotation:          RefreshRotationPolicy, // RotateOnEachUse | Static
    pub refresh_token_max_reuse:         u32,                   // 0 = strict
    pub revoke_refresh_token_on_logout:  bool,
    pub include_authn_amr:               bool,
    pub include_authn_acr:               bool,
    pub include_session_id_claim:        bool,
    pub include_session_state_iframe:    bool,
}

pub struct BruteForcePolicy {
    pub enabled: bool,
    pub permanent_lockout: bool,
    pub max_login_failures: u32,                // 30
    pub wait_increment: Duration,               // 60s
    pub max_wait: Duration,                     // 15 min
    pub quick_login_check_window: Duration,     // 1 min
    pub minimum_quick_login_wait: Duration,     // 60s
    pub failure_reset_window: Duration,         // 12 h
}

pub struct PasswordPolicy {
    pub rules: Vec<PasswordRule>,               // ordered, all must pass
}

pub enum PasswordRule {
    MinLength(u32),
    MaxLength(u32),
    MinDigits(u32),
    MinSpecialChars(u32),
    MinUpperCase(u32),
    MinLowerCase(u32),
    NotUsername,
    NotEmail,
    NoTopKCommon(u32),                          // breach-list deny
    HistoryDistinct(u32),                       // last K
    MaxAge(Duration),                           // forces rotation
    Argon2idCost(Argon2idParams),
    HashAlgorithm(HashAlg),                     // argon2id is the only allowed in v0.1
    PasswordBlacklist(BlacklistRef),
    RegexMatch(String),
    RegexForbid(String),
}

pub struct OtpPolicy {
    pub mode: OtpMode,                          // Totp | Hotp
    pub algorithm: OtpAlgorithm,                // SHA1 | SHA256 | SHA512
    pub digits: u8,                             // 6 | 8
    pub period_seconds: u32,                    // TOTP only, default 30
    pub initial_counter: u64,                   // HOTP only
    pub look_ahead_window: u32,                 // 1 (counter drift)
    pub reusable_codes: bool,                   // discouraged
    pub supported_apps: Vec<String>,            // shown to user in setup
}

pub struct WebauthnPolicy {
    pub rp_id: Option<String>,                  // defaults to realm hostname
    pub rp_display_name: String,
    pub signature_algorithms: Vec<CoseAlgorithm>,
    pub attestation_conveyance: Attestation,    // None | Indirect | Direct | Enterprise
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub require_resident_key: ResidentKey,      // Preferred | Required | Discouraged
    pub user_verification: UserVerification,
    pub timeout: Duration,                      // default 60s
    pub avoid_same_authenticator_registration: bool,
    pub allowed_aaguids: Option<Vec<Aaguid>>,   // enterprise allow-list
}

pub struct SecurityHeaders {
    pub frame_options: XFrameOption,            // Deny | SameOrigin
    pub content_security_policy: String,
    pub content_security_policy_report_only: Option<String>,
    pub strict_transport_security: String,
    pub x_content_type_options: String,         // "nosniff"
    pub referrer_policy: String,
    pub permissions_policy: String,
    pub robots_tag: String,                     // "none"
}

pub struct LocalizationPolicy {
    pub internationalization_enabled: bool,
    pub supported_locales: Vec<Locale>,         // e.g. ["en", "tr", "de"]
    pub default_locale: Locale,
}

pub struct SmtpServer {
    pub host: String,
    pub port: u16,
    pub from: String,
    pub from_display_name: Option<String>,
    pub reply_to: Option<String>,
    pub envelope_from: Option<String>,
    pub starttls: bool,
    pub ssl: bool,
    pub auth: Option<SmtpAuth>,                 // user + Secret<String>
}

pub struct EventConfig {
    pub login_events_enabled: bool,
    pub admin_events_enabled: bool,
    pub admin_events_include_representation: bool,
    pub login_event_types: Vec<String>,         // empty = all
    pub admin_event_types: Vec<String>,
    pub sinks: Vec<EventSinkRef>,               // see 13-observability.md
    pub retention_days: u32,                    // 90 default
}

pub struct DefaultRoles {
    pub realm_roles: Vec<RoleId>,               // assigned to new users
    pub client_roles: BTreeMap<ClientId, Vec<RoleId>>,
}

pub struct OrganizationPolicy {
    pub default_membership_invitation_expiry: Duration,
    pub auto_join_on_domain_match: bool,
    pub require_invitation_acceptance: bool,
}

/// Per-realm rules that derive `acr` from authentication outcome (AMR / sender-constraint).
/// Used to satisfy `acr_values` requests and to drive the `step-up` flow kind.
pub struct AcrPolicy {
    pub levels: Vec<AcrLevel>,          // ordered, ascending
}

pub struct AcrLevel {
    pub value: String,                  // e.g. "0", "1", "2", "urn:mace:incommon:iap:silver"
    pub display_name: String,
    pub require: AcrRequirement,
}

/// Boolean expression over AMRs + sender-constraint.
pub enum AcrRequirement {
    Any,                                // any successful authn
    AmrContains(Vec<Amr>),              // e.g. [pwd] for level 1, [pwd, otp] for level 2
    AllOf(Vec<AcrRequirement>),
    AnyOf(Vec<AcrRequirement>),
    SenderConstrained(SenderConstraint),// dpop | mtls
}

pub struct User {
    pub id: UserId,
    pub realm_id: RealmId,
    pub username: String,               // unique per realm, case-folded
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<PersonName>,
    pub credentials: Vec<CredentialRef>,// references; secret material in credentials table
    pub federation: Option<FederationLink>, // Some(...) when user is mirrored from LDAP/IdP
    pub attributes: BTreeMap<String, AttributeValue>,
    pub required_actions: Vec<RequiredAction>, // verify-email, update-password, ...
    pub required_flow: Option<FlowAlias>,      // forces this flow on the next login (admin-set)
    pub organizations: Vec<OrganizationId>,    // memberships denormalized for the hot path
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct Client {
    pub id: ClientId,
    pub realm_id: RealmId,
    pub client_id: String,              // OAuth client_id, unique per realm
    pub name: Option<String>,
    pub description: Option<String>,
    pub kind: ClientKind,               // Confidential | Public | BearerOnly | ServiceAccount

    // — URIs & origins —
    pub root_url: Option<Url>,
    pub base_url: Option<Url>,
    pub admin_url: Option<Url>,         // app-side admin/backchannel URL
    pub redirect_uris: Vec<UriPattern>,
    pub post_logout_uris: Vec<UriPattern>,
    pub web_origins: Vec<Origin>,       // CORS allowlist
    pub logo_uri: Option<Url>,
    pub policy_uri: Option<Url>,
    pub tos_uri: Option<Url>,

    // — protocols & grants —
    pub grants: GrantPolicy,            // see below
    pub auth_method: ClientAuthMethod,  // client_secret_basic, private_key_jwt, none (PKCE)
    pub flow_binding: FlowBinding,      // browser / direct-grant / reset / registration / step-up
    pub default_scopes: Vec<ScopeName>,
    pub optional_scopes: Vec<ScopeName>,
    pub consent: ConsentPolicy,         // see below

    // — token & session policy overrides (null = inherit from realm) —
    pub access_token_lifespan: Option<Duration>,
    pub refresh_token_lifespan: Option<Duration>,
    pub sso_session_idle: Option<Duration>,
    pub sso_session_max: Option<Duration>,
    pub access_token_signing_alg: Option<JwsAlgorithm>,
    pub id_token_signing_alg: Option<JwsAlgorithm>,
    pub access_token_type: AccessTokenType,    // Jwt | Opaque
    pub include_session_id_in_token: bool,
    pub include_session_state_iframe: bool,    // browser-state OIDC iframe
    pub pairwise_sub_algorithm: Option<PairwiseSubAlg>,
    pub sender_constraint: Option<SenderConstraint>, // null = realm default

    // — logout —
    pub front_channel_logout_enabled: bool,
    pub front_channel_logout_url: Option<Url>,
    pub backchannel_logout_url: Option<Url>,
    pub backchannel_logout_session_required: bool,
    pub backchannel_logout_revoke_offline_sessions: bool,

    // — admin UI presentation —
    pub display_in_console: bool,        // shown in account console application list
    pub always_display_in_console: bool,

    // — service account & specific options —
    pub service_account_user_id: Option<UserId>, // when kind == ServiceAccount
    pub include_authn_amr_in_id_token: bool,
    pub use_refresh_tokens: bool,
    pub use_refresh_tokens_for_client_credentials: bool,
    pub fapi_level: FapiLevel,          // None | Baseline | Advanced (v0.2)

    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct GrantPolicy {
    pub authorization_code: bool,        // "Standard flow"
    pub implicit: bool,                  // DEPRECATED; off by default
    pub direct_access_grants: bool,      // password grant
    pub client_credentials: bool,
    pub device_authorization: bool,      // RFC 8628
    pub token_exchange: bool,            // RFC 8693, v0.2
    pub ciba: bool,                      // OIDC CIBA, DEFERRED
    pub service_accounts_enabled: bool,
}

pub struct ConsentPolicy {
    pub consent_required: bool,
    pub display_on_consent_screen: bool, // show client info even when consent_required=false
    pub consent_screen_text: Option<String>,
}

pub struct Role {
    pub id: RoleId,
    pub realm_id: RealmId,
    pub scope: RoleScope,               // RealmRole | ClientRole(ClientId)
    pub name: String,                   // unique within scope
    pub description: Option<String>,
    pub composites: Vec<RoleId>,        // composite (parent → child) roles
    pub attributes: BTreeMap<String, AttributeValue>, // role metadata, mapper-readable
}

pub struct Group {
    pub id: GroupId,
    pub realm_id: RealmId,
    pub parent_id: Option<GroupId>,
    pub name: String,
    pub path: String,                   // materialized path "/eng/backend"
    pub attributes: BTreeMap<String, AttributeValue>,
    pub assigned_roles: Vec<RoleId>,
}

pub struct AuthFlow {
    pub id: FlowId,
    pub realm_id: RealmId,
    pub alias: String,                  // "browser", "direct-grant", custom
    pub description: Option<String>,
    pub graph: FlowGraph,               // see 06-auth-flows.md
    pub version: i32,                   // monotonic; old versions kept for in-flight
    pub built_in: bool,
}

pub struct Organization {
    pub id: OrganizationId,
    pub realm_id: RealmId,
    pub alias: String,                   // url-safe handle, unique per realm
    pub display_name: String,
    pub description: Option<String>,
    pub attributes: BTreeMap<String, AttributeValue>,
    pub branding: OrganizationBranding,  // logo, color, banner
    pub default_idp_alias: Option<String>, // SSO target for org members
    pub redirect_url: Option<Url>,       // post-login redirect override
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct OrganizationBranding {
    pub logo_uri: Option<Url>,
    pub primary_color: Option<String>,
    pub banner_text: Option<String>,
}

/// A claimed DNS domain. Users whose verified-email domain matches
/// may auto-join (if policy allows).
pub struct OrgDomain {
    pub id: OrgDomainId,
    pub organization_id: OrganizationId,
    pub realm_id: RealmId,
    pub domain: String,                  // "acme.com"
    pub verified: bool,                  // verified via DNS TXT or email-loop
    pub verification_token: Option<String>,
    pub verified_at: Option<DateTime<Utc>>,
}

pub struct OrgMembership {
    pub organization_id: OrganizationId,
    pub realm_id: RealmId,
    pub user_id: UserId,
    pub roles: Vec<OrgRoleId>,           // org-scoped roles
    pub joined_at: DateTime<Utc>,
    pub invited_by: Option<UserId>,
    pub state: MembershipState,          // Active | Invited | Suspended
}

pub struct OrgInvitation {
    pub id: OrgInvitationId,
    pub organization_id: OrganizationId,
    pub realm_id: RealmId,
    pub email: String,
    pub roles: Vec<OrgRoleId>,
    pub invited_by: UserId,
    pub token: Secret<String>,           // single-use, hashed in storage
    pub expires_at: DateTime<Utc>,
    pub accepted_at: Option<DateTime<Utc>>,
}

/// Roles scoped to an Organization (independent of realm roles).
pub struct OrgRole {
    pub id: OrgRoleId,
    pub organization_id: OrganizationId,
    pub realm_id: RealmId,
    pub name: String,                    // "owner", "admin", "billing", ...
    pub description: Option<String>,
}

/// Declarative schema for user attributes within a realm. One per realm.
/// Drives admin forms, registration form, account-console form, and
/// API write validation.
pub struct UserProfile {
    pub realm_id: RealmId,
    pub attributes: Vec<UserAttributeDecl>,
    pub groups: Vec<UserAttributeGroup>,  // display groupings
    pub unmanaged_attribute_policy: UnmanagedAttributePolicy, // Reject | Allow | Hidden
    pub updated_at: DateTime<Utc>,
}

pub struct UserAttributeDecl {
    pub name: String,                    // attribute key (e.g. "department")
    pub display_name: String,
    pub group: Option<String>,           // groups attributes in UI
    pub display_order: i32,
    pub multivalued: bool,
    pub required: AttributeRequirement,  // Always | OnRegistration | Never | Conditional
    pub permissions: AttributePermissions,
    pub validators: Vec<AttributeValidator>,
    pub annotations: BTreeMap<String, serde_json::Value>, // free-form UI hints
}

pub enum AttributeValidator {
    Length { min: Option<u32>, max: Option<u32> },
    Email,
    Url,
    Regex(String),
    LocalDate,
    Integer { min: Option<i64>, max: Option<i64> },
    Double { min: Option<f64>, max: Option<f64> },
    Options(Vec<String>),                // discrete enum
    PersonNameProhibitedCharacters,
    UsernameProhibitedCharacters,
    UriPattern,
    Custom { module: WasmModuleId, config: serde_json::Value },
}

pub struct AttributePermissions {
    pub view: Vec<AttributeAudience>,    // who can see this attribute
    pub edit: Vec<AttributeAudience>,    // who can write
}

pub enum AttributeAudience {
    User,           // the owning user (account console)
    Admin,          // realm admin via API or admin UI
    Anyone,         // public — appears in id_token / userinfo
}

pub struct UserAttributeGroup {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub display_order: i32,
}

pub struct IdentityProvider {
    pub id: IdpId,
    pub realm_id: RealmId,
    pub alias: String,                  // "google", "corp-okta"
    pub kind: IdpKind,                  // Oidc | Saml
    pub config: IdpConfig,              // protocol-specific fields
    pub trust: IdpTrust,                // signing keys / metadata URL
    pub mapper_bindings: Vec<MapperBinding>, // SPI mappers run on the broker assertion
    pub first_login_flow: FlowId,
    pub post_login_flow: Option<FlowId>,
    pub enabled: bool,
}

pub struct FederationSource {
    pub id: FederationId,
    pub realm_id: RealmId,
    pub alias: String,                  // "corp-ad"
    pub kind: FederationKind,           // Ldap | Spi(WasmModuleId)
    pub config: FederationConfig,       // bind DN, base DN, attr map, page size, tls
    pub priority: i32,                  // resolution order
    pub sync_policy: SyncPolicy,        // pull schedule + full/incremental
    pub enabled: bool,
}

pub struct KeyMaterial {
    pub id: KeyId,
    pub realm_id: RealmId,
    pub usage: KeyUsage,                // Sig | Enc
    pub alg: KeyAlgorithm,              // RS256, ES256, EdDSA, ...
    pub state: KeyState,                // Active | PreviousActive | Disabled
    pub public_jwk: serde_json::Value,
    pub private_ref: PrivateKeyRef,     // Local(opaque ciphertext) | Kms(uri)
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
}

pub struct Session {
    pub id: SessionId,                  // 32-byte random, opaque
    pub realm_id: RealmId,
    pub user_id: UserId,
    pub authn_level: AuthnLevel,
    pub idp_alias: Option<String>,
    pub started_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub remote_ip: IpAddr,
    pub user_agent: String,
    pub clients: Vec<ClientSessionRef>, // child client sessions (per-app SSO)
}

pub struct CodeGrant {
    pub code: CodeId,                   // 32-byte random, opaque
    pub realm_id: RealmId,
    pub client_id: ClientId,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub scope: Vec<ScopeName>,
    pub redirect_uri: Url,
    pub code_challenge: Option<CodeChallenge>, // PKCE
    pub nonce: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,      // 60s
}

pub struct RefreshToken {
    pub id: RefreshTokenId,             // hashed in storage
    pub family_id: TokenFamilyId,       // for rotation reuse detection
    pub realm_id: RealmId,
    pub client_id: ClientId,
    pub user_id: UserId,
    pub session_id: SessionId,
    pub scope: Vec<ScopeName>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
}

pub struct SpiBinding {
    pub id: SpiBindingId,
    pub realm_id: RealmId,
    pub interface: WitInterfaceName,    // "geonosis:user-storage@0.1.0", "geonosis:authn@0.1.0", ...
    pub provider_urn: String,           // stable id — "builtin:..." or "wasm:..."
    pub origin: ProviderOrigin,         // Builtin | Wasm { module_id, alias }
    pub config: serde_json::Value,      // typed by interface contract
    pub priority: i32,                  // smaller = earlier (FirstMatch / Chain)
    pub enabled: bool,
    pub replaces: Option<String>,       // when set, forcibly disables target provider URN
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub enum ProviderOrigin {
    Builtin,                            // implementation lives in-process (Rust)
    Wasm { module_id: WasmModuleId, alias: String },
}

pub struct EventSink {
    pub id: EventSinkId,
    pub realm_id: RealmId,
    pub alias: String,
    pub kind: EventSinkKind,             // Webhook | Kafka(v0.2) | Cloud(v0.2)
    pub config: serde_json::Value,
    pub events_filter: Vec<String>,      // empty = all
    pub enabled: bool,
}

pub struct WasmModule {
    pub id: WasmModuleId,
    pub realm_id: RealmId,
    pub sha256: [u8; 32],
    pub bytecode_url: Url,              // or inline if small
    pub wit_world: String,              // declared world (e.g. "geonosis:authn@0.1.0")
    pub uploaded_by: UserId,
    pub uploaded_at: DateTime<Utc>,
}
```

## Identifier strategy

- All ids are **ULID** rendered as `Crockford base32`. Lexicographic
  sort matches time order; useful for paginating audit logs.
- Storage column type: `text` with a `CHECK` constraint and a
  `BTREE` index. Postgres `uuid` was considered and rejected to keep
  audit logs readable in raw SQL.

## Postgres schema (sketch)

This is the v0.1 baseline. Real DDL lives in
`crates/geonosis-migrate/migrations/`.

```sql
CREATE TABLE realm (
    id              TEXT PRIMARY KEY,
    slug            TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    registration    JSONB NOT NULL,
    session_policy  JSONB NOT NULL,
    token_policy    JSONB NOT NULL,
    theme_binding   JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE app_user (
    id              TEXT PRIMARY KEY,
    realm_id        TEXT NOT NULL REFERENCES realm(id),
    username_lc     TEXT NOT NULL,
    email_lc        TEXT,
    email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
    name            JSONB,
    federation      JSONB,
    attributes      JSONB NOT NULL DEFAULT '{}'::jsonb,
    required_actions TEXT[] NOT NULL DEFAULT '{}',
    required_flow   TEXT,                  -- forces this flow alias on next login
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    -- Generated full-text search vector over username/email/name; see note below.
    search_vector   tsvector GENERATED ALWAYS AS (
        setweight(to_tsvector('simple', coalesce(username_lc, '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(email_lc, '')),    'B') ||
        setweight(to_tsvector('simple', coalesce(name->>'given',  '')), 'C') ||
        setweight(to_tsvector('simple', coalesce(name->>'family', '')), 'C')
    ) STORED,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (realm_id, username_lc)
);
CREATE INDEX ON app_user (realm_id, email_lc);
CREATE INDEX app_user_search_vector_idx ON app_user USING GIN (realm_id, search_vector);

CREATE TABLE credential (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES app_user(id),
    realm_id        TEXT NOT NULL,
    kind            TEXT NOT NULL,        -- 'password' | 'otp' | 'webauthn' | 'recovery'
    secret_data     BYTEA NOT NULL,       -- algorithm-specific encoded form
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON credential (user_id, kind);

-- ... clients, roles, groups, user_role, user_group, group_role,
-- identity_provider, federation_source, auth_flow, key_material,
-- session, code_grant, refresh_token, spi_binding, wasm_module,
-- organization, org_domain, org_membership, org_invitation, org_role,
-- user_profile, smtp_server, event_sink ...

-- Append-only audit log; partitioned by month.
CREATE TABLE audit_event (
    id              TEXT PRIMARY KEY,
    realm_id        TEXT NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL,
    actor           JSONB NOT NULL,        -- {kind:'user'|'client'|'system', id, ip}
    action          TEXT NOT NULL,         -- e.g. 'login.success'
    target          JSONB,
    detail          JSONB
) PARTITION BY RANGE (occurred_at);
```

### Row-Level Security

For defense in depth, every tenanted table has an RLS policy of the
form:

```sql
ALTER TABLE app_user ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON app_user
    USING (realm_id = current_setting('geonosis.realm_id', true));
```

The server sets `SET LOCAL geonosis.realm_id = '...'` at the start of
each transaction for tenanted handlers. Administrative handlers use a
distinct DB role that bypasses RLS, audited separately.

This is **belt and suspenders** — application code still constructs
queries with `WHERE realm_id = $1` — but RLS catches forgotten
predicates.

## Validation rules (selected)

- `realm.slug` MUST match `^[a-z][a-z0-9-]{1,63}$` and is reserved
  case-insensitively across all realms; `admin`, `master`, `well-known`
  are reserved.
- `user.username` is **case-folded** with NFKC + ICU lowercase to
  produce `username_lc`. The original casing is kept in attributes.
- `client.client_id` MUST match `^[A-Za-z0-9_.-]{1,128}$`.
- `redirect_uri` patterns support exact match and one `*` wildcard
  only at path tail; no scheme wildcards; no `localhost` special case.
- `attribute` keys MUST be ≤ 64 chars; values either string ≤ 2 KiB
  or array of strings with total ≤ 8 KiB.
- All timestamps are stored UTC.

## Non-goals

- **Custom column extensions** — schema is fixed; tenants extend via
  `attributes` JSONB or SPI mappers.
- **Polymorphic actor tables** — no Inheritance, no STI; each entity
  is its own table.
- **Soft delete by default** — only audit events are append-only;
  user delete is hard delete unless `retention_policy` says otherwise.

## Decisions and open items

- **User search**: full-text via Postgres `tsvector` over
  `username_lc`, `email_lc`, and `name` parts, generated as a
  `STORED` column with weight per field. GIN index keyed by
  `(realm_id, search_vector)`. The dictionary is `simple` by default
  for language-independence; realms with majority-language users can
  override to a specific dictionary (e.g. `english`, `turkish`) via
  a per-realm config knob in v0.2.
- **Attribute search**: not part of the base full-text vector; an
  optional GIN index on `attributes` JSONB is added in v0.2 with a
  per-realm allow-list of indexed keys.
- **Audit retention**: 90 days default in Postgres, configurable per
  realm; minimum 30 days. Cold storage off-host (S3 with
  Object Lock) is v0.2.
- **Schema for SAML-as-IdP** (Geonosis issuing SAML assertions):
  deferred to v0.2.
