//! Storage trait.

use async_trait::async_trait;

use geonosis_broker::{BrokerAuthnState, BrokerLink, IdentityProvider};
use geonosis_core::{
    Agent, Client, ClientId, CodeGrant, CodeId, Group, GroupId, OrgConsentPolicy, OrgInvitation,
    OrgMembership, OrgRole, Organization, OrganizationId, Realm, RealmId, RefreshToken,
    RefreshTokenId, Role, RoleId, Session, SessionId, TokenFamilyId, User, UserId, UserProfile,
};
use geonosis_core::id::{AgentId, OrgInvitationId, OrgRoleId};
use geonosis_federation_ldap::LdapFederationConfig;

use crate::error::StorageError;

/// Storage seam — every concrete backend implements this. v0.1 has one
/// in-memory backend; the Postgres backend lives behind the same trait.
#[async_trait]
pub trait Storage: Send + Sync {
    /// Backend liveness probe. SHOULD complete in <100ms and never
    /// retry; the readiness handler calls this on every `/-/ready`
    /// poll. MemoryStorage returns Ok unconditionally; PostgresStorage
    /// runs `SELECT 1` against the pool.
    async fn ping(&self) -> Result<(), StorageError>;

    // ---- Realm ----
    async fn create_realm(&self, realm: Realm) -> Result<(), StorageError>;
    async fn get_realm(&self, id: RealmId) -> Result<Realm, StorageError>;
    async fn get_realm_by_slug(&self, slug: &str) -> Result<Realm, StorageError>;
    async fn update_realm(&self, realm: Realm) -> Result<(), StorageError>;
    async fn delete_realm(&self, id: RealmId) -> Result<(), StorageError>;
    async fn list_realms(&self) -> Result<Vec<Realm>, StorageError>;

    // ---- User ----
    async fn create_user(&self, user: User) -> Result<(), StorageError>;
    async fn get_user(&self, realm: RealmId, id: UserId) -> Result<User, StorageError>;
    async fn get_user_by_username(
        &self,
        realm: RealmId,
        username: &str,
    ) -> Result<User, StorageError>;
    async fn get_user_by_email(&self, realm: RealmId, email: &str) -> Result<User, StorageError>;
    async fn update_user(&self, user: User) -> Result<(), StorageError>;
    async fn delete_user(&self, realm: RealmId, id: UserId) -> Result<(), StorageError>;
    /// List users in a realm, capped at `limit`. v0.1 returns the
    /// first `limit` rows in insertion order; pagination lands in
    /// v0.1.x once an explicit `(offset, limit, sort)` cursor type is
    /// added to the trait.
    async fn list_users(
        &self,
        realm: RealmId,
        limit: usize,
    ) -> Result<Vec<User>, StorageError>;

    /// Credentials carry secrets — separate accessor so we can audit access.
    async fn store_password_hash(
        &self,
        realm: RealmId,
        user_id: UserId,
        phc_hash: String,
    ) -> Result<(), StorageError>;
    async fn get_password_hash(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<String, StorageError>;

    // ---- Client ----
    async fn create_client(&self, client: Client) -> Result<(), StorageError>;
    async fn get_client(&self, realm: RealmId, id: ClientId) -> Result<Client, StorageError>;
    async fn get_client_by_client_id(
        &self,
        realm: RealmId,
        client_id: &str,
    ) -> Result<Client, StorageError>;
    async fn update_client(&self, client: Client) -> Result<(), StorageError>;
    async fn delete_client(&self, realm: RealmId, id: ClientId) -> Result<(), StorageError>;
    async fn list_clients(&self, realm: RealmId) -> Result<Vec<Client>, StorageError>;

    /// Confidential clients store a hashed secret (BLAKE3-keyed). v0.1
    /// stores the realm-keyed hash; the plaintext secret is shown to admin
    /// at creation and never persisted.
    async fn store_client_secret_hash(
        &self,
        realm: RealmId,
        client_id: ClientId,
        secret_hash: String,
    ) -> Result<(), StorageError>;
    async fn get_client_secret_hash(
        &self,
        realm: RealmId,
        client_id: ClientId,
    ) -> Result<String, StorageError>;

    // ---- Session ----
    async fn create_session(&self, session: Session) -> Result<(), StorageError>;
    async fn get_session(&self, id: &SessionId) -> Result<Session, StorageError>;
    async fn update_session(&self, session: Session) -> Result<(), StorageError>;
    async fn delete_session(&self, id: &SessionId) -> Result<(), StorageError>;

    // ---- Code grant (single-use, 60s TTL) ----
    async fn save_code_grant(&self, grant: CodeGrant) -> Result<(), StorageError>;
    /// Atomically consume a code (deletes the row in the same query). Used
    /// at `/token` to enforce single-use semantics across pods.
    async fn consume_code(&self, code: &CodeId) -> Result<CodeGrant, StorageError>;

    // ---- Refresh token (rotation + family) ----
    async fn save_refresh_token(&self, token: RefreshToken) -> Result<(), StorageError>;
    async fn get_refresh_token(
        &self,
        id: &RefreshTokenId,
    ) -> Result<RefreshToken, StorageError>;
    async fn mark_refresh_used(&self, id: &RefreshTokenId) -> Result<(), StorageError>;
    /// Invalidate every token in a family — invoked when a previously-used
    /// refresh token is presented again (reuse detection).
    async fn revoke_token_family(&self, family: TokenFamilyId) -> Result<(), StorageError>;

    // ---- PAR (RFC 9126) ----
    async fn save_par_request(&self, par: ParRequest) -> Result<(), StorageError>;
    async fn consume_par_request(&self, request_uri: &str) -> Result<ParRequest, StorageError>;

    // ---- Device flow (RFC 8628) ----
    async fn save_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError>;
    async fn get_device_grant_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<DeviceGrant, StorageError>;
    async fn get_device_grant_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<DeviceGrant, StorageError>;
    async fn update_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError>;
    async fn delete_device_grant(&self, device_code: &str) -> Result<(), StorageError>;

    // ---- Flow state ----
    async fn save_flow_state(&self, state: FlowStateRow) -> Result<(), StorageError>;
    async fn get_flow_state(&self, id: &geonosis_core::FlowStateId) -> Result<FlowStateRow, StorageError>;
    async fn delete_flow_state(&self, id: &geonosis_core::FlowStateId) -> Result<(), StorageError>;

    // ---- Auth flow definitions (per (realm, alias, version)) ----
    async fn save_auth_flow(
        &self,
        flow: geonosis_flow::FlowDefinition,
    ) -> Result<(), StorageError>;
    /// Return the highest-version flow row for `(realm, alias)`. The
    /// older versions stay in the table so in-flight `FlowState`
    /// objects can resolve against the version they were started on.
    async fn get_auth_flow_by_alias(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<geonosis_flow::FlowDefinition, StorageError>;
    async fn list_auth_flows(
        &self,
        realm: RealmId,
    ) -> Result<Vec<geonosis_flow::FlowDefinition>, StorageError>;
    async fn delete_auth_flow(
        &self,
        realm: RealmId,
        id: geonosis_core::FlowId,
    ) -> Result<(), StorageError>;

    // ---- Consent grants (OIDC consent screen) ----
    async fn save_consent_grant(&self, grant: ConsentGrant) -> Result<(), StorageError>;
    async fn get_consent_grant(
        &self,
        realm: RealmId,
        user_id: UserId,
        client_id: ClientId,
    ) -> Result<ConsentGrant, StorageError>;
    async fn delete_consent_grant(
        &self,
        realm: RealmId,
        user_id: UserId,
        client_id: ClientId,
    ) -> Result<(), StorageError>;

    // ---- Identity provider (broker) ----
    async fn create_idp(&self, idp: IdentityProvider) -> Result<(), StorageError>;
    async fn get_idp_by_alias(&self, realm: RealmId, alias: &str)
        -> Result<IdentityProvider, StorageError>;
    async fn list_idps(&self, realm: RealmId) -> Result<Vec<IdentityProvider>, StorageError>;
    async fn delete_idp(&self, realm: RealmId, alias: &str) -> Result<(), StorageError>;

    // ---- BrokerAuthnState (per-redirect CSRF bridge) ----
    async fn save_broker_state(&self, state: BrokerAuthnState) -> Result<(), StorageError>;
    /// Atomically consume a broker state row by the random `state` value.
    /// Single-use: the row is deleted at consume time so a replayed
    /// callback fails with `NotFound`.
    async fn consume_broker_state(
        &self,
        realm: RealmId,
        state: &str,
    ) -> Result<BrokerAuthnState, StorageError>;

    // ---- BrokerLink (user_id ↔ external_id) ----
    async fn upsert_broker_link(&self, link: BrokerLink) -> Result<(), StorageError>;
    async fn find_broker_link(
        &self,
        realm: RealmId,
        idp_alias: &str,
        external_id: &str,
    ) -> Result<Option<BrokerLink>, StorageError>;
    async fn list_broker_links(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<Vec<BrokerLink>, StorageError>;

    // ---- LDAP federation source ----
    async fn upsert_ldap_source(&self, source: LdapFederationConfig)
        -> Result<(), StorageError>;
    async fn get_ldap_source(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<LdapFederationConfig, StorageError>;
    async fn list_ldap_sources(
        &self,
        realm: RealmId,
    ) -> Result<Vec<LdapFederationConfig>, StorageError>;
    async fn delete_ldap_source(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<(), StorageError>;

    // ---- WASM SPI modules ----
    async fn upload_wasm_module(&self, module: WasmModule) -> Result<(), StorageError>;
    async fn get_wasm_module(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<WasmModule, StorageError>;
    async fn list_wasm_modules(
        &self,
        realm: RealmId,
    ) -> Result<Vec<WasmModuleHeader>, StorageError>;
    async fn delete_wasm_module(&self, realm: RealmId, alias: &str)
        -> Result<(), StorageError>;

    // ---- SPI bindings ----
    async fn create_spi_binding(&self, binding: SpiBindingRow)
        -> Result<(), StorageError>;
    async fn list_spi_bindings(
        &self,
        realm: RealmId,
        interface: &str,
    ) -> Result<Vec<SpiBindingRow>, StorageError>;
    async fn update_spi_binding(&self, binding: SpiBindingRow)
        -> Result<(), StorageError>;
    async fn delete_spi_binding(
        &self,
        realm: RealmId,
        binding_id: geonosis_core::id::SpiBindingId,
    ) -> Result<(), StorageError>;

    // ---- Role (realm + client-scoped) ----
    async fn create_role(&self, role: Role) -> Result<(), StorageError>;
    async fn get_role(&self, realm: RealmId, id: RoleId) -> Result<Role, StorageError>;
    async fn get_role_by_name(
        &self,
        realm: RealmId,
        client_id: Option<ClientId>,
        name: &str,
    ) -> Result<Role, StorageError>;
    async fn list_roles(
        &self,
        realm: RealmId,
        client_id: Option<ClientId>,
    ) -> Result<Vec<Role>, StorageError>;
    async fn update_role(&self, role: Role) -> Result<(), StorageError>;
    async fn delete_role(&self, realm: RealmId, id: RoleId) -> Result<(), StorageError>;

    async fn assign_user_role(
        &self,
        realm: RealmId,
        user_id: UserId,
        role_id: RoleId,
    ) -> Result<(), StorageError>;
    async fn unassign_user_role(
        &self,
        realm: RealmId,
        user_id: UserId,
        role_id: RoleId,
    ) -> Result<(), StorageError>;
    async fn list_user_roles(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<Vec<Role>, StorageError>;

    // ---- Group (hierarchical) ----
    async fn create_group(&self, group: Group) -> Result<(), StorageError>;
    async fn get_group(&self, realm: RealmId, id: GroupId) -> Result<Group, StorageError>;
    async fn get_group_by_path(
        &self,
        realm: RealmId,
        path: &str,
    ) -> Result<Group, StorageError>;
    async fn list_groups(&self, realm: RealmId) -> Result<Vec<Group>, StorageError>;
    async fn update_group(&self, group: Group) -> Result<(), StorageError>;
    async fn delete_group(&self, realm: RealmId, id: GroupId) -> Result<(), StorageError>;

    async fn assign_user_group(
        &self,
        realm: RealmId,
        user_id: UserId,
        group_id: GroupId,
    ) -> Result<(), StorageError>;
    async fn unassign_user_group(
        &self,
        realm: RealmId,
        user_id: UserId,
        group_id: GroupId,
    ) -> Result<(), StorageError>;
    async fn list_user_groups(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<Vec<Group>, StorageError>;

    async fn assign_group_role(
        &self,
        realm: RealmId,
        group_id: GroupId,
        role_id: RoleId,
    ) -> Result<(), StorageError>;
    async fn unassign_group_role(
        &self,
        realm: RealmId,
        group_id: GroupId,
        role_id: RoleId,
    ) -> Result<(), StorageError>;
    async fn list_group_roles(
        &self,
        realm: RealmId,
        group_id: GroupId,
    ) -> Result<Vec<Role>, StorageError>;

    // ---- User Profile schema (per realm) ----
    async fn get_user_profile_schema(
        &self,
        realm: RealmId,
    ) -> Result<UserProfile, StorageError>;
    async fn save_user_profile_schema(
        &self,
        profile: UserProfile,
    ) -> Result<(), StorageError>;

    // ---- Agent identity ----
    async fn create_agent(&self, agent: Agent) -> Result<(), StorageError>;
    async fn get_agent(&self, realm: RealmId, id: AgentId) -> Result<Agent, StorageError>;
    async fn get_agent_by_alias(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<Agent, StorageError>;
    async fn list_agents(&self, realm: RealmId) -> Result<Vec<Agent>, StorageError>;
    async fn update_agent(&self, agent: Agent) -> Result<(), StorageError>;
    async fn revoke_agent(&self, realm: RealmId, id: AgentId) -> Result<(), StorageError>;

    // ---- Organization ----
    async fn create_organization(&self, org: Organization) -> Result<(), StorageError>;
    async fn get_organization(
        &self,
        realm: RealmId,
        id: OrganizationId,
    ) -> Result<Organization, StorageError>;
    async fn get_organization_by_alias(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<Organization, StorageError>;
    async fn list_organizations(
        &self,
        realm: RealmId,
    ) -> Result<Vec<Organization>, StorageError>;
    async fn update_organization(&self, org: Organization) -> Result<(), StorageError>;
    async fn delete_organization(
        &self,
        realm: RealmId,
        id: OrganizationId,
    ) -> Result<(), StorageError>;

    async fn upsert_org_domain(
        &self,
        domain: geonosis_core::OrgDomain,
    ) -> Result<(), StorageError>;
    async fn list_org_domains(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<geonosis_core::OrgDomain>, StorageError>;
    async fn delete_org_domain(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
        domain: &str,
    ) -> Result<(), StorageError>;
    async fn find_org_by_verified_domain(
        &self,
        realm: RealmId,
        domain: &str,
    ) -> Result<Option<Organization>, StorageError>;

    async fn upsert_org_membership(
        &self,
        membership: OrgMembership,
    ) -> Result<(), StorageError>;
    async fn get_org_membership(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
        user_id: UserId,
    ) -> Result<OrgMembership, StorageError>;
    async fn list_org_memberships(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgMembership>, StorageError>;
    async fn list_user_orgs(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<Vec<OrgMembership>, StorageError>;
    async fn delete_org_membership(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
        user_id: UserId,
    ) -> Result<(), StorageError>;

    async fn create_org_role(&self, role: OrgRole) -> Result<(), StorageError>;
    async fn get_org_role(
        &self,
        realm: RealmId,
        id: OrgRoleId,
    ) -> Result<OrgRole, StorageError>;
    async fn list_org_roles(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgRole>, StorageError>;
    async fn update_org_role(&self, role: OrgRole) -> Result<(), StorageError>;
    async fn delete_org_role(
        &self,
        realm: RealmId,
        id: OrgRoleId,
    ) -> Result<(), StorageError>;

    async fn create_org_invitation(
        &self,
        invitation: OrgInvitation,
    ) -> Result<(), StorageError>;
    async fn get_org_invitation_by_token(
        &self,
        token: &str,
    ) -> Result<OrgInvitation, StorageError>;
    async fn list_org_invitations(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgInvitation>, StorageError>;
    async fn mark_org_invitation_accepted(
        &self,
        id: OrgInvitationId,
    ) -> Result<(), StorageError>;
    async fn delete_org_invitation(
        &self,
        id: OrgInvitationId,
    ) -> Result<(), StorageError>;

    async fn upsert_org_consent_policy(
        &self,
        policy: OrgConsentPolicy,
    ) -> Result<(), StorageError>;
    async fn get_org_consent_policy(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
        client_id: ClientId,
    ) -> Result<Option<OrgConsentPolicy>, StorageError>;
    async fn list_org_consent_policies(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgConsentPolicy>, StorageError>;
    async fn delete_org_consent_policy(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
        client_id: ClientId,
    ) -> Result<(), StorageError>;

    async fn upsert_org_idp_binding(
        &self,
        binding: OrgIdpBinding,
    ) -> Result<(), StorageError>;
    async fn list_org_idp_bindings(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgIdpBinding>, StorageError>;
    async fn delete_org_idp_binding(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
        idp_alias: &str,
    ) -> Result<(), StorageError>;

    // ---- Audit event query ----

    /// List audit events for a realm with optional filters. Ordered
    /// by `occurred_at DESC`. Per docs/13-observability.md the table
    /// is partitioned by month + indexed on `(realm_id, occurred_at)`
    /// + `(realm_id, action, occurred_at)`, so this query stays
    /// bounded under heavy ingest.
    ///
    /// The actor filter does a substring match against the JSONB
    /// `actor::text` so callers can filter by kind (`user`, `client`,
    /// `system`) or by ULID without needing a structured query.
    async fn list_audit_events(
        &self,
        realm: RealmId,
        filter: &AuditEventFilter<'_>,
        limit: usize,
    ) -> Result<Vec<AuditEventRow>, StorageError>;

    /// List sessions for a realm, ordered by `last_seen_at DESC`. Hard
    /// cap on the limit lives at the call site; the schema's
    /// `session_realm_user_idx` keeps the query bounded.
    async fn list_sessions(
        &self,
        realm: RealmId,
        limit: usize,
    ) -> Result<Vec<Session>, StorageError>;

    // ---- SAML persistent NameID (per (realm, user, SP)) ----

    /// Look up the persistent NameID we previously minted for this
    /// `(realm, user, sp_entity_id)` tuple. Per
    /// `docs/20-saml-idp.md` §"NameID strategies": same user +
    /// same SP MUST resolve to the same NameID across sessions.
    /// Returns `None` if no row exists yet — the caller mints one
    /// and persists it via [`save_saml_persistent_id`].
    async fn get_saml_persistent_id(
        &self,
        realm: RealmId,
        user_id: UserId,
        sp_entity_id: &str,
    ) -> Result<Option<SamlPersistentIdRow>, StorageError>;

    /// Persist a freshly-minted persistent NameID. Idempotent: if a
    /// row already exists for the tuple it is left untouched so a
    /// concurrent SSO request from the same SP can't shift the
    /// downstream identity.
    async fn save_saml_persistent_id(
        &self,
        row: SamlPersistentIdRow,
    ) -> Result<(), StorageError>;
}

/// Per-(realm, user, SP) persistent SAML NameID row. The
/// `name_id` is an opaque ULID-based identifier that never reveals
/// the user_id to the SP. Schema matches the `saml_persistent_id`
/// table in the v0.1.x migration; `created_at` is the audit handle
/// for "when did Geonosis first identify this user to this SP".
#[derive(Debug, Clone, PartialEq)]
pub struct SamlPersistentIdRow {
    pub realm_id: RealmId,
    pub user_id: UserId,
    pub sp_entity_id: String,
    pub name_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Filter inputs for `list_audit_events`. Every field is optional; an
/// empty filter returns the most recent N rows.
#[derive(Debug, Clone, Default)]
pub struct AuditEventFilter<'a> {
    pub action: Option<&'a str>,
    pub actor: Option<&'a str>,
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    pub until: Option<chrono::DateTime<chrono::Utc>>,
}

/// Storage-shaped projection of one `audit_event` row. Mirrors the
/// REST response shape under `/admin/v1/realms/:slug/events`. We
/// keep `actor` + `target` as raw JSON values so the schema stays in
/// sync with the audit-sink writer without a typed Actor/Target
/// dependency from `geonosis-storage` onto `geonosis-audit`.
#[derive(Debug, Clone)]
pub struct AuditEventRow {
    pub id: String,
    pub realm_id: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub actor: serde_json::Value,
    pub action: String,
    pub target: Option<serde_json::Value>,
    pub detail: serde_json::Value,
}

/// Per-org binding to one of the realm's identity providers.
#[derive(Debug, Clone)]
pub struct OrgIdpBinding {
    pub organization_id: OrganizationId,
    pub realm_id: RealmId,
    pub idp_alias: String,
    pub priority: i32,
    pub enabled: bool,
}

/// Stored WASM module — bytecode + metadata for the per-pod loader.
#[derive(Debug, Clone)]
pub struct WasmModule {
    pub id: geonosis_core::id::WasmModuleId,
    pub realm_id: RealmId,
    pub alias: String,
    pub interface: String,
    pub sha256_hex: String,
    pub size_bytes: i64,
    pub bytecode: Vec<u8>,
    pub uploaded_by: Option<UserId>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// `WasmModule` without the bytecode — used by listing endpoints.
#[derive(Debug, Clone)]
pub struct WasmModuleHeader {
    pub id: geonosis_core::id::WasmModuleId,
    pub realm_id: RealmId,
    pub alias: String,
    pub interface: String,
    pub sha256_hex: String,
    pub size_bytes: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Persisted SPI binding row. Mirrors the doc `SpiBinding` shape.
#[derive(Debug, Clone)]
pub struct SpiBindingRow {
    pub id: geonosis_core::id::SpiBindingId,
    pub realm_id: RealmId,
    pub interface: String,
    pub provider_urn: String,
    pub priority: i32,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub replaces: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Persisted user-level consent grant for a `(user, client)` pair.
/// Holds the union of scopes the user has approved over previous logins.
#[derive(Debug, Clone)]
pub struct ConsentGrant {
    pub id: geonosis_core::ConsentGrantId,
    pub realm_id: RealmId,
    pub user_id: UserId,
    pub client_id: ClientId,
    pub scopes: Vec<geonosis_core::ScopeName>,
    pub granted_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Pushed authorization request row (RFC 9126).
#[derive(Debug, Clone)]
pub struct ParRequest {
    pub request_uri: String,
    pub realm_id: RealmId,
    pub client_id: ClientId,
    pub params: std::collections::BTreeMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Device authorization grant row (RFC 8628).
#[derive(Debug, Clone)]
pub struct DeviceGrant {
    pub device_code: String,
    pub user_code: String,
    pub realm_id: RealmId,
    pub client_id: ClientId,
    pub scope: Vec<geonosis_core::ScopeName>,
    pub interval_seconds: u32,
    pub status: DeviceGrantStatus,
    pub user_id: Option<UserId>,
    pub session_id: Option<SessionId>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Last poll timestamp — used to enforce `slow_down`.
    pub last_polled_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceGrantStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// Persisted flow state row.
#[derive(Debug, Clone)]
pub struct FlowStateRow {
    pub state: geonosis_flow::FlowState,
    /// Captured authorization-request params so we can mint the code on success.
    pub authorize_params: std::collections::BTreeMap<String, String>,
}
