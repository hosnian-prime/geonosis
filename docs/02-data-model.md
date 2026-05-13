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
    UrlPattern,                          // RFC 6570 URI template match
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
    pub display_name: String,
    pub kind: IdpKind,                  // Oidc | Saml — non-OIDC OAuth2 (e.g. GitHub) is
                                        // wrapped by a broker-adapter plugin presenting OIDC-shaped
                                        // assertions to the core. See 05-identity-broker.md.
    pub config: IdpConfig,              // protocol-specific fields
    pub trust: IdpTrust,                // signing keys / metadata URL
    pub mapper_bindings: Vec<MapperBinding>, // SPI mappers run on the broker assertion
    pub first_login_flow: FlowId,
    pub post_login_flow: Option<FlowId>,
    pub sync_mode: SyncMode,            // Import | ForceFetch
    pub link_only: bool,                // never auto-create users; only link to existing
    pub adapter_urn: Option<String>,    // optional broker-adapter SPI plugin URN
                                        // (Some(...) for vendor-quirky providers like GitHub/Apple/Microsoft)
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

## Appendix — Common type vocabulary

Types referenced by the entities above and across the other docs.
This list is **normative**: code MUST match these spellings. Where
a variant set is small, the variants are enumerated; where it's
large, the canonical doc is cited.

### Identifier newtypes

All ids are `pub struct XxxId(pub Ulid)` (Crockford base32-rendered)
unless stated otherwise. Newtypes prevent accidental mixing at
compile time.

```rust
pub struct RealmId(pub Ulid);
pub struct UserId(pub Ulid);
pub struct ClientId(pub Ulid);             // INTERNAL ULID. Distinct from Client.client_id (public OAuth client_id string).
pub struct RoleId(pub Ulid);
pub struct GroupId(pub Ulid);
pub struct OrganizationId(pub Ulid);
pub struct OrgDomainId(pub Ulid);
pub struct OrgRoleId(pub Ulid);
pub struct OrgInvitationId(pub Ulid);
pub struct FlowId(pub Ulid);
pub struct NodeId(pub Ulid);               // within a flow graph
pub struct KeyId(pub Ulid);
pub struct CredentialId(pub Ulid);
pub struct IdpId(pub Ulid);
pub struct SpiBindingId(pub Ulid);
pub struct WasmModuleId(pub Ulid);
pub struct EventSinkId(pub Ulid);
pub struct EventId(pub Ulid);
pub struct TokenFamilyId(pub Ulid);
pub struct AgentId(pub Ulid);              // see 18-agent-identity.md

/// Opaque base32-encoded 32-byte random; stored hashed where appropriate.
pub struct SessionId(pub String);
pub struct CodeId(pub String);
pub struct RefreshTokenId(pub String);     // stored hash; never plaintext
```

`Client.client_id: String` is the **public** OAuth client_id (a
human-readable string). `ClientId(pub Ulid)` is the **internal**
primary key. Cross-table references use the ULID; the wire surface
uses the public string.

### Attribute and profile types

```rust
pub enum AttributeValue {
    String(String),
    StringArray(Vec<String>),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Date(NaiveDate),
    DateTime(DateTime<Utc>),
}

pub struct PersonName {
    pub given: Option<String>,
    pub family: Option<String>,
    pub middle: Option<String>,
    pub honorific: Option<String>,
    pub display: Option<String>,           // explicit override; else computed
}

/// BCP 47 language tag (e.g. "en", "tr", "az", "de-CH").
pub struct Locale(pub String);

pub enum RequiredAction {
    VerifyEmail,
    UpdatePassword,
    ConfigureOtp,
    ConfigureWebauthn,
    AcceptTerms { version: String },
    UpdateProfile,
    Custom(String),                        // "acme:complete-onboarding" etc.
}

pub enum AttributeRequirement {
    Always,
    OnRegistration,
    Never,
    Conditional(GuardExpr),
}

/// Tiny pure-evaluation expression language; same grammar used by flow edges.
/// AST-parsed at save time, no embedded scripting.
pub struct GuardExpr(pub String);

pub struct AttributePermissions {
    pub view: Vec<AttributeAudience>,
    pub edit: Vec<AttributeAudience>,
}

pub enum AttributeAudience { User, Admin, Anyone }
pub enum UnmanagedAttributePolicy { Reject, Allow, Hidden }
pub struct ScopeName(pub String);          // OAuth scope identifier
```

### Credential types

```rust
pub struct CredentialRef {
    pub id: CredentialId,
    pub kind: CredentialKind,
    pub label: Option<String>,             // "iPhone YubiKey"
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

pub enum CredentialKind {
    Password,
    Totp,
    Hotp,
    WebauthnPlatform,                      // built-in / synced authenticator
    WebauthnRoaming,                       // security key
    RecoveryCode,
    MagicLink,
    PhoneOtp,
}

pub struct Credential {
    pub kind: CredentialKind,
    pub secret_data: Vec<u8>,              // algorithm-specific encoded form
    pub config: serde_json::Value,         // per-kind tuning (e.g. argon2id params)
}

pub struct CredentialInfo {
    pub id: CredentialId,
    pub kind: CredentialKind,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

pub enum ValidationResult {
    Valid { amr: Vec<Amr> },
    InvalidCredential,
    UserDisabled,
    UserLocked { unlock_at: Option<DateTime<Utc>> },
    Unsupported,
}

pub enum Amr {
    Pwd, Otp, Wbn,                         // password / TOTP|HOTP / WebAuthn
    Sms, Email,                            // phone OTP / magic link
    Mfa,                                   // synthetic when two factors satisfied
    Pop,                                   // proof-of-possession (DPoP / mTLS)
    Custom(String),
}
```

### Subject (flow result)

```rust
pub enum Subject {
    Local(UserId),
    External {
        idp_alias: String,
        broker_assertion: BrokerAssertion,
        candidate_user: Option<UserId>,    // present when matched
    },
    ServiceAccount(ClientId),
    Agent {                                // see 18-agent-identity.md
        agent_id: AgentId,
        parent_subject: Box<Subject>,      // delegating principal
        scopes: Vec<ScopeName>,
    },
}
```

### Federation / broker / IdP types

```rust
pub struct FederationLink {
    pub source_urn: String,                // "builtin:user-storage:ldap:corp-ad" or "wasm:..."
    pub external_id: String,
    pub external_dn: Option<String>,       // LDAP only
    pub last_synced_at: DateTime<Utc>,
}

pub enum IdpKind { Oidc, Saml }
pub struct IdpConfig(pub serde_json::Value);
pub struct IdpTrust {
    pub jwks: Option<serde_json::Value>,
    pub jwks_uri: Option<Url>,
    pub saml_signing_certs: Vec<X509Certificate>,
    pub metadata_url: Option<Url>,
    pub metadata_refresh_interval: Duration,
}
pub enum SyncMode { Import, ForceFetch }
pub enum MembershipState { Active, Invited, Suspended }

pub struct MapperBinding {
    pub mapper_urn: String,
    pub config: serde_json::Value,
    pub priority: i32,
}

pub struct BrokerAssertion {
    pub idp_alias: String,
    pub external_id: String,
    pub issuer: String,
    pub raw: Vec<u8>,
    pub claims: BTreeMap<String, AttributeValue>,
    pub tokens: Option<OAuth2TokenSet>,
    pub received_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

pub struct OAuth2TokenSet {
    pub access_token: Secret<String>,
    pub refresh_token: Option<Secret<String>>,
    pub id_token: Option<Secret<String>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scope: Vec<String>,
}

pub struct OidcIdpConfig { /* per 05-identity-broker.md */ }
pub struct SamlIdpConfig { /* per 05-identity-broker.md */ }
```

### Cryptographic / protocol types

```rust
pub enum JwsAlgorithm {
    RS256, RS384, RS512,
    PS256, PS384, PS512,
    ES256, ES384, ES512,
    EdDSA,                                 // Ed25519
    HS256, HS384, HS512,                   // client_secret_jwt only
}

pub enum KeyAlgorithm { Rs(u16), Es(u16), Ed25519 }
pub enum KeyUsage { Sig, Enc }
pub enum KeyState { Active, PreviousActive, Disabled }

pub enum HashAlg { Argon2id }              // v0.1 only allowed
pub struct Argon2idParams { pub memory_kib: u32, pub iterations: u32, pub parallelism: u32 }

pub enum ClientAuthMethod {
    ClientSecretBasic, ClientSecretPost, ClientSecretJwt,
    PrivateKeyJwt, None,                   // None = PKCE-only public clients
    TlsClientAuth,                         // v0.2
}

pub enum PkceMode { Required, IfSupported, Off }
pub enum SenderConstraint { None, Dpop, Mtls }
pub enum AccessTokenType { Jwt, Opaque }
pub enum PairwiseSubAlg { None, Sha256Salted }
pub enum FapiLevel { None, Baseline, Advanced }

pub struct X509Certificate(pub Vec<u8>);   // DER-encoded
pub enum NameIdFormat { Unspecified, EmailAddress, Persistent, Transient, X509SubjectName }
pub enum SamlBinding { HttpRedirect, HttpPost, Artifact }

pub struct BlacklistRef {
    pub source: BlacklistSource,
    pub last_refreshed: DateTime<Utc>,
}
pub enum BlacklistSource { HaveIBeenPwned, LocalFile { path: PathBuf } }
```

### Provider / SPI types

```rust
pub enum LookupOutcome<T> {
    NotFound,                              // delegate to next provider in chain
    Found(T),
}

pub struct ProviderCapabilities {
    pub supports_create: bool,
    pub supports_update: bool,
    pub supports_delete: bool,
    pub supports_credential_validation: bool,
    pub supports_search: bool,
    pub readonly_attributes: Vec<String>,
}

pub struct ProviderContext {
    pub request_id: String,
    pub realm_id: RealmId,
    pub remote_ip: Option<IpAddr>,
    pub trace_carrier: BTreeMap<String, String>,
}

pub enum ProviderError {
    NotFound, Unsupported,
    ResourceExceeded { kind: ResourceKind },
    Conflict(String), InvalidConfig(String),
    NetworkError(String), Timeout,
    Disabled, Quarantined,
    Internal(String),
}
pub enum ResourceKind { Fuel, Memory, WallClock }

pub enum ProviderOrigin {
    Builtin,
    Wasm { module_id: WasmModuleId, alias: String },
}

pub struct ExternalUser {
    pub external_id: String,
    pub username: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<PersonName>,
    pub attributes: BTreeMap<String, AttributeValue>,
    pub credentials: Vec<CredentialRef>,
    pub enabled: bool,
    pub source_urn: String,                // provider URN that emitted this
}

pub struct UserDraft {
    pub username: String,
    pub email: Option<String>,
    pub name: Option<PersonName>,
    pub attributes: BTreeMap<String, AttributeValue>,
    pub initial_credential: Option<Credential>,
}

pub struct UserPatch {
    pub email: Option<Option<String>>,     // outer = "field present", inner = set/unset
    pub name: Option<Option<PersonName>>,
    pub attributes: Option<BTreeMap<String, AttributeValue>>,
    pub enabled: Option<bool>,
}

pub struct SearchQuery {
    pub q: Option<String>,                 // tsvector free-text
    pub username: Option<String>,
    pub email: Option<String>,
    pub attributes: BTreeMap<String, String>,
    pub group_id: Option<GroupId>,
    pub organization_id: Option<OrganizationId>,
    pub limit: u32,
    pub offset: u32,
}

pub struct SearchPage {
    pub items: Vec<ExternalUser>,
    pub total: Option<u64>,                // None when source can't count
}

pub struct WitInterfaceName(pub String);   // "geonosis:user-storage@0.1.0"
```

### Auth flow execution types

```rust
pub struct FlowContext { /* see 06-auth-flows.md */ }
pub struct CompiledFlow { /* indexed graph + parsed guards */ }
pub enum StepInput { Submit(FormBody), Resume, IdpCallback(RawCallback) }
pub enum StepOutput {
    Render(RenderInstruction),
    Redirect(Url),
    Done(Subject),
    Failed(FlowFailure),
}
pub struct RenderInstruction {
    pub template: String,
    pub locals: BTreeMap<String, serde_json::Value>,
    pub csrf: CsrfToken,
}
pub struct CsrfToken(pub String);
pub enum FlowFailure {
    InvalidCredential,
    UserDisabled,
    UserNotFound,
    ConsentDenied,
    BrokerError(String),
    SpiError(ProviderError),
}
```

### Cache types

```rust
pub struct CacheKey { pub realm: RealmId, pub class: CacheClass, pub id: String }
pub struct CacheKeyPrefix { pub realm: RealmId, pub class: CacheClass }
pub enum CacheClass {
    Realm, Client, Flow, Theme, Spi, Jwks, Idp, Federation,
    User, UserProfile, Organization, Negative,
}
pub struct Cached<T> {
    pub value: Arc<T>,
    pub fetched_at: Instant,
    pub ttl: Duration,
}
```

### WebAuthn-specific types

```rust
pub struct Aaguid(pub Uuid);
pub struct CoseAlgorithm(pub i32);
pub enum AuthenticatorAttachment { Platform, CrossPlatform }
pub enum ResidentKey { Preferred, Required, Discouraged }
pub enum UserVerification { Preferred, Required, Discouraged }
pub enum Attestation { None, Indirect, Direct, Enterprise }
```

### Miscellaneous

```rust
pub enum XFrameOption { Deny, SameOrigin }

pub struct SmtpAuth {
    pub user: String,
    pub password: Secret<String>,
    pub mechanism: SmtpMechanism,
}
pub enum SmtpMechanism { Plain, Login, CramMd5 }

pub enum AuthnLevel { Anonymous, Single, Mfa, HardwareBound }

pub struct EventSinkRef(pub EventSinkId);
pub enum EventSinkKind { Postgres, Webhook, Kafka, Cloud }

/// HTTP origin per RFC 6454 (e.g. "https://app.acme.com").
/// Distinct from `ProviderOrigin` (built-in vs. WASM provenance);
/// the two never appear in the same module's name resolution.
pub struct Origin(pub String);
```

> **Naming notes** (from doc audit):
>
> - `Origin` is **HTTP origin**; `ProviderOrigin` is provider provenance.
> - `Client.client_id: String` is the **public** OAuth identifier;
>   `ClientId(Ulid)` is the **internal** primary key. They differ
>   intentionally; cross-references use the ULID.
> - `UrlPattern` (a `UserAttributeValidator` variant) is unrelated to
>   the `UriPattern` of `Client.redirect_uris`. The latter is a
>   redirect-URI matcher; the former is an RFC 6570 template validator.

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
