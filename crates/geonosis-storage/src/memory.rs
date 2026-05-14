//! In-memory storage. Default for tests and the 5-minute quickstart.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;

use geonosis_broker::{BrokerAuthnState, BrokerLink, IdentityProvider};
use geonosis_core::{
    Agent, Client, ClientId, CodeGrant, CodeId, FlowStateId, Group, GroupId, OrgConsentPolicy,
    OrgDomain, OrgInvitation, OrgMembership, OrgRole, Organization, OrganizationId, Realm, RealmId,
    RefreshToken, RefreshTokenId, Role, RoleId, Session, SessionId, TokenFamilyId, User, UserId,
    UserProfile,
};
use geonosis_core::id::{AgentId, OrgInvitationId, OrgRoleId};
use geonosis_federation_ldap::LdapFederationConfig;

use crate::error::StorageError;
use crate::traits::{
    ConsentGrant, DeviceGrant, FlowStateRow, OrgIdpBinding, ParRequest, SpiBindingRow, Storage,
    WasmModule, WasmModuleHeader,
};

#[derive(Default)]
struct Tables {
    realms: HashMap<RealmId, Realm>,
    realm_by_slug: HashMap<String, RealmId>,
    users: HashMap<(RealmId, UserId), User>,
    users_by_username: HashMap<(RealmId, String), UserId>,
    users_by_email: HashMap<(RealmId, String), UserId>,
    password_hashes: HashMap<(RealmId, UserId), String>,
    clients: HashMap<(RealmId, ClientId), Client>,
    clients_by_client_id: HashMap<(RealmId, String), ClientId>,
    client_secret_hashes: HashMap<(RealmId, ClientId), String>,
    sessions: HashMap<SessionId, Session>,
    codes: HashMap<CodeId, CodeGrant>,
    refresh_tokens: HashMap<RefreshTokenId, RefreshToken>,
    /// family -> set of token ids
    families: HashMap<TokenFamilyId, Vec<RefreshTokenId>>,
    par_requests: HashMap<String, ParRequest>,
    device_by_device_code: HashMap<String, DeviceGrant>,
    device_by_user_code: HashMap<String, String>,
    flow_states: HashMap<FlowStateId, FlowStateRow>,
    consent_grants: HashMap<(RealmId, UserId, ClientId), ConsentGrant>,
    idps: HashMap<(RealmId, String), IdentityProvider>,
    broker_states: HashMap<(RealmId, String), BrokerAuthnState>,
    broker_links: HashMap<(RealmId, String, String), BrokerLink>,
    ldap_sources: HashMap<(RealmId, String), LdapFederationConfig>,
    wasm_modules: HashMap<(RealmId, String), WasmModule>,
    spi_bindings: HashMap<(RealmId, geonosis_core::id::SpiBindingId), SpiBindingRow>,
    auth_flows: HashMap<(RealmId, geonosis_core::FlowId), geonosis_flow::FlowDefinition>,
    roles: HashMap<(RealmId, RoleId), Role>,
    user_roles: HashMap<(RealmId, UserId), Vec<RoleId>>,
    groups: HashMap<(RealmId, GroupId), Group>,
    user_groups: HashMap<(RealmId, UserId), Vec<GroupId>>,
    group_roles: HashMap<(RealmId, GroupId), Vec<RoleId>>,
    user_profile_schemas: HashMap<RealmId, UserProfile>,
    agents: HashMap<(RealmId, AgentId), Agent>,
    organizations: HashMap<(RealmId, OrganizationId), Organization>,
    org_by_alias: HashMap<(RealmId, String), OrganizationId>,
    org_domains: HashMap<(OrganizationId, String), OrgDomain>,
    org_memberships: HashMap<(OrganizationId, UserId), OrgMembership>,
    org_roles: HashMap<(RealmId, OrgRoleId), OrgRole>,
    org_invitations: HashMap<OrgInvitationId, OrgInvitation>,
    org_invitations_by_token: HashMap<String, OrgInvitationId>,
    org_consent_policies: HashMap<(OrganizationId, ClientId), OrgConsentPolicy>,
    org_idp_bindings: HashMap<(OrganizationId, String), OrgIdpBinding>,
}

pub struct MemoryStorage {
    inner: Arc<RwLock<Tables>>,
}

impl Default for MemoryStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Tables::default())),
        }
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn ping(&self) -> Result<(), StorageError> {
        // In-process backend — health is implicit in the process being
        // alive. Returning Ok lets the readiness handler differentiate
        // "backend reachable" from "backend reachable BUT degraded";
        // the dev quickstart relies on this never erroring.
        Ok(())
    }

    // ---- Realm ----
    async fn create_realm(&self, realm: Realm) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        if t.realm_by_slug.contains_key(&realm.slug) {
            return Err(StorageError::Conflict(format!(
                "realm slug {} taken",
                realm.slug
            )));
        }
        t.realm_by_slug.insert(realm.slug.clone(), realm.id);
        t.realms.insert(realm.id, realm);
        Ok(())
    }

    async fn get_realm(&self, id: RealmId) -> Result<Realm, StorageError> {
        let t = self.inner.read();
        t.realms.get(&id).cloned().ok_or(StorageError::NotFound)
    }

    async fn get_realm_by_slug(&self, slug: &str) -> Result<Realm, StorageError> {
        let t = self.inner.read();
        let id = t.realm_by_slug.get(slug).ok_or(StorageError::NotFound)?;
        t.realms.get(id).cloned().ok_or(StorageError::NotFound)
    }

    async fn update_realm(&self, realm: Realm) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        if !t.realms.contains_key(&realm.id) {
            return Err(StorageError::NotFound);
        }
        t.realms.insert(realm.id, realm);
        Ok(())
    }

    async fn delete_realm(&self, id: RealmId) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let r = t.realms.remove(&id).ok_or(StorageError::NotFound)?;
        t.realm_by_slug.remove(&r.slug);
        Ok(())
    }

    async fn list_realms(&self) -> Result<Vec<Realm>, StorageError> {
        let t = self.inner.read();
        Ok(t.realms.values().cloned().collect())
    }

    // ---- User ----
    async fn create_user(&self, user: User) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let key = (user.realm_id, user.username.clone());
        if t.users_by_username.contains_key(&key) {
            return Err(StorageError::Conflict(format!(
                "username {} taken",
                user.username
            )));
        }
        if let Some(email) = &user.email {
            t.users_by_email
                .insert((user.realm_id, email.clone()), user.id);
        }
        t.users_by_username.insert(key, user.id);
        t.users.insert((user.realm_id, user.id), user);
        Ok(())
    }

    async fn get_user(&self, realm: RealmId, id: UserId) -> Result<User, StorageError> {
        let t = self.inner.read();
        t.users
            .get(&(realm, id))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn get_user_by_username(
        &self,
        realm: RealmId,
        username: &str,
    ) -> Result<User, StorageError> {
        let t = self.inner.read();
        let id = t
            .users_by_username
            .get(&(realm, username.to_string()))
            .ok_or(StorageError::NotFound)?;
        t.users
            .get(&(realm, *id))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn get_user_by_email(
        &self,
        realm: RealmId,
        email: &str,
    ) -> Result<User, StorageError> {
        let t = self.inner.read();
        let id = t
            .users_by_email
            .get(&(realm, email.to_string()))
            .ok_or(StorageError::NotFound)?;
        t.users
            .get(&(realm, *id))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn update_user(&self, user: User) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        if !t.users.contains_key(&(user.realm_id, user.id)) {
            return Err(StorageError::NotFound);
        }
        t.users.insert((user.realm_id, user.id), user);
        Ok(())
    }

    async fn list_users(
        &self,
        realm: RealmId,
        limit: usize,
    ) -> Result<Vec<User>, StorageError> {
        Ok(self
            .inner
            .read()
            .users
            .iter()
            .filter(|((r, _), _)| *r == realm)
            .take(limit)
            .map(|(_, u)| u.clone())
            .collect())
    }

    async fn delete_user(&self, realm: RealmId, id: UserId) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let u = t.users.remove(&(realm, id)).ok_or(StorageError::NotFound)?;
        t.users_by_username.remove(&(realm, u.username));
        if let Some(email) = u.email {
            t.users_by_email.remove(&(realm, email));
        }
        Ok(())
    }

    async fn store_password_hash(
        &self,
        realm: RealmId,
        user_id: UserId,
        phc_hash: String,
    ) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.password_hashes.insert((realm, user_id), phc_hash);
        Ok(())
    }

    async fn get_password_hash(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<String, StorageError> {
        let t = self.inner.read();
        t.password_hashes
            .get(&(realm, user_id))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    // ---- Client ----
    async fn create_client(&self, client: Client) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let key = (client.realm_id, client.client_id.clone());
        if t.clients_by_client_id.contains_key(&key) {
            return Err(StorageError::Conflict(format!(
                "client_id {} taken",
                client.client_id
            )));
        }
        t.clients_by_client_id.insert(key, client.id);
        t.clients.insert((client.realm_id, client.id), client);
        Ok(())
    }

    async fn get_client(&self, realm: RealmId, id: ClientId) -> Result<Client, StorageError> {
        let t = self.inner.read();
        t.clients
            .get(&(realm, id))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn get_client_by_client_id(
        &self,
        realm: RealmId,
        client_id: &str,
    ) -> Result<Client, StorageError> {
        let t = self.inner.read();
        let id = t
            .clients_by_client_id
            .get(&(realm, client_id.to_string()))
            .ok_or(StorageError::NotFound)?;
        t.clients
            .get(&(realm, *id))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn update_client(&self, client: Client) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        if !t.clients.contains_key(&(client.realm_id, client.id)) {
            return Err(StorageError::NotFound);
        }
        t.clients.insert((client.realm_id, client.id), client);
        Ok(())
    }

    async fn delete_client(&self, realm: RealmId, id: ClientId) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let c = t
            .clients
            .remove(&(realm, id))
            .ok_or(StorageError::NotFound)?;
        t.clients_by_client_id.remove(&(realm, c.client_id));
        Ok(())
    }

    async fn list_clients(&self, realm: RealmId) -> Result<Vec<Client>, StorageError> {
        let t = self.inner.read();
        Ok(t.clients
            .iter()
            .filter(|((r, _), _)| *r == realm)
            .map(|(_, c)| c.clone())
            .collect())
    }

    async fn store_client_secret_hash(
        &self,
        realm: RealmId,
        client_id: ClientId,
        secret_hash: String,
    ) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.client_secret_hashes
            .insert((realm, client_id), secret_hash);
        Ok(())
    }

    async fn get_client_secret_hash(
        &self,
        realm: RealmId,
        client_id: ClientId,
    ) -> Result<String, StorageError> {
        let t = self.inner.read();
        t.client_secret_hashes
            .get(&(realm, client_id))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    // ---- Session ----
    async fn create_session(&self, session: Session) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.sessions.insert(session.id.clone(), session);
        Ok(())
    }

    async fn get_session(&self, id: &SessionId) -> Result<Session, StorageError> {
        let t = self.inner.read();
        t.sessions.get(id).cloned().ok_or(StorageError::NotFound)
    }

    async fn update_session(&self, session: Session) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        if !t.sessions.contains_key(&session.id) {
            return Err(StorageError::NotFound);
        }
        t.sessions.insert(session.id.clone(), session);
        Ok(())
    }

    async fn delete_session(&self, id: &SessionId) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.sessions.remove(id).ok_or(StorageError::NotFound).map(|_| ())
    }

    // ---- Code grant ----
    async fn save_code_grant(&self, grant: CodeGrant) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.codes.insert(grant.code.clone(), grant);
        Ok(())
    }

    async fn consume_code(&self, code: &CodeId) -> Result<CodeGrant, StorageError> {
        let mut t = self.inner.write();
        t.codes.remove(code).ok_or(StorageError::NotFound)
    }

    // ---- Refresh token ----
    async fn save_refresh_token(&self, token: RefreshToken) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.families
            .entry(token.family_id)
            .or_default()
            .push(token.id.clone());
        t.refresh_tokens.insert(token.id.clone(), token);
        Ok(())
    }

    async fn get_refresh_token(
        &self,
        id: &RefreshTokenId,
    ) -> Result<RefreshToken, StorageError> {
        let t = self.inner.read();
        t.refresh_tokens
            .get(id)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn mark_refresh_used(&self, id: &RefreshTokenId) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let tok = t.refresh_tokens.get_mut(id).ok_or(StorageError::NotFound)?;
        tok.used = true;
        Ok(())
    }

    async fn revoke_token_family(&self, family: TokenFamilyId) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        if let Some(ids) = t.families.remove(&family) {
            for id in ids {
                t.refresh_tokens.remove(&id);
            }
        }
        Ok(())
    }

    // ---- PAR ----
    async fn save_par_request(&self, par: ParRequest) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.par_requests.insert(par.request_uri.clone(), par);
        Ok(())
    }

    async fn consume_par_request(&self, request_uri: &str) -> Result<ParRequest, StorageError> {
        let mut t = self.inner.write();
        t.par_requests
            .remove(request_uri)
            .ok_or(StorageError::NotFound)
    }

    // ---- Device flow ----
    async fn save_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.device_by_user_code
            .insert(grant.user_code.clone(), grant.device_code.clone());
        t.device_by_device_code
            .insert(grant.device_code.clone(), grant);
        Ok(())
    }

    async fn get_device_grant_by_device_code(
        &self,
        device_code: &str,
    ) -> Result<DeviceGrant, StorageError> {
        let t = self.inner.read();
        t.device_by_device_code
            .get(device_code)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn get_device_grant_by_user_code(
        &self,
        user_code: &str,
    ) -> Result<DeviceGrant, StorageError> {
        let t = self.inner.read();
        let dc = t
            .device_by_user_code
            .get(user_code)
            .cloned()
            .ok_or(StorageError::NotFound)?;
        t.device_by_device_code
            .get(&dc)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn update_device_grant(&self, grant: DeviceGrant) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        if !t.device_by_device_code.contains_key(&grant.device_code) {
            return Err(StorageError::NotFound);
        }
        t.device_by_device_code
            .insert(grant.device_code.clone(), grant);
        Ok(())
    }

    async fn delete_device_grant(&self, device_code: &str) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let g = t
            .device_by_device_code
            .remove(device_code)
            .ok_or(StorageError::NotFound)?;
        t.device_by_user_code.remove(&g.user_code);
        Ok(())
    }

    // ---- Flow state ----
    async fn save_flow_state(&self, state: FlowStateRow) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.flow_states.insert(state.state.id, state);
        Ok(())
    }

    async fn get_flow_state(&self, id: &FlowStateId) -> Result<FlowStateRow, StorageError> {
        let t = self.inner.read();
        t.flow_states.get(id).cloned().ok_or(StorageError::NotFound)
    }

    async fn delete_flow_state(&self, id: &FlowStateId) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.flow_states.remove(id).ok_or(StorageError::NotFound).map(|_| ())
    }

    async fn save_auth_flow(
        &self,
        flow: geonosis_flow::FlowDefinition,
    ) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        if t.auth_flows
            .values()
            .any(|f| f.realm_id == flow.realm_id && f.alias == flow.alias && f.version == flow.version)
            && !t.auth_flows.contains_key(&(flow.realm_id, flow.id))
        {
            return Err(StorageError::Conflict(format!(
                "auth_flow ({}, {}, v{}) already exists",
                flow.realm_id, flow.alias, flow.version
            )));
        }
        t.auth_flows.insert((flow.realm_id, flow.id), flow);
        Ok(())
    }

    async fn get_auth_flow_by_alias(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<geonosis_flow::FlowDefinition, StorageError> {
        self.inner
            .read()
            .auth_flows
            .values()
            .filter(|f| f.realm_id == realm && f.alias == alias)
            .max_by_key(|f| f.version)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn list_auth_flows(
        &self,
        realm: RealmId,
    ) -> Result<Vec<geonosis_flow::FlowDefinition>, StorageError> {
        use std::collections::BTreeMap as Map;
        let mut latest: Map<String, geonosis_flow::FlowDefinition> = Map::new();
        let t = self.inner.read();
        for f in t.auth_flows.values().filter(|f| f.realm_id == realm) {
            match latest.get(f.alias.as_str()) {
                Some(prev) if prev.version >= f.version => {}
                _ => {
                    latest.insert(f.alias.clone(), f.clone());
                }
            }
        }
        Ok(latest.into_values().collect())
    }

    async fn delete_auth_flow(
        &self,
        realm: RealmId,
        id: geonosis_core::FlowId,
    ) -> Result<(), StorageError> {
        self.inner
            .write()
            .auth_flows
            .remove(&(realm, id))
            .ok_or(StorageError::NotFound)
            .map(|_| ())
    }

    // ---- Consent grants ----
    async fn save_consent_grant(&self, grant: ConsentGrant) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.consent_grants
            .insert((grant.realm_id, grant.user_id, grant.client_id), grant);
        Ok(())
    }

    async fn get_consent_grant(
        &self,
        realm: RealmId,
        user_id: UserId,
        client_id: ClientId,
    ) -> Result<ConsentGrant, StorageError> {
        let t = self.inner.read();
        t.consent_grants
            .get(&(realm, user_id, client_id))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn delete_consent_grant(
        &self,
        realm: RealmId,
        user_id: UserId,
        client_id: ClientId,
    ) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.consent_grants
            .remove(&(realm, user_id, client_id))
            .ok_or(StorageError::NotFound)
            .map(|_| ())
    }

    // ---- IdP ----
    async fn create_idp(&self, idp: IdentityProvider) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let key = (idp.realm_id, idp.alias.clone());
        if t.idps.contains_key(&key) {
            return Err(StorageError::Conflict(format!(
                "idp alias {} taken",
                idp.alias
            )));
        }
        t.idps.insert(key, idp);
        Ok(())
    }

    async fn get_idp_by_alias(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<IdentityProvider, StorageError> {
        self.inner
            .read()
            .idps
            .get(&(realm, alias.to_string()))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn list_idps(&self, realm: RealmId) -> Result<Vec<IdentityProvider>, StorageError> {
        Ok(self
            .inner
            .read()
            .idps
            .iter()
            .filter(|((r, _), _)| *r == realm)
            .map(|(_, v)| v.clone())
            .collect())
    }

    async fn delete_idp(&self, realm: RealmId, alias: &str) -> Result<(), StorageError> {
        self.inner
            .write()
            .idps
            .remove(&(realm, alias.to_string()))
            .ok_or(StorageError::NotFound)
            .map(|_| ())
    }

    // ---- BrokerAuthnState ----
    async fn save_broker_state(&self, state: BrokerAuthnState) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.broker_states
            .insert((state.realm_id, state.state.clone()), state);
        Ok(())
    }

    async fn consume_broker_state(
        &self,
        realm: RealmId,
        state: &str,
    ) -> Result<BrokerAuthnState, StorageError> {
        self.inner
            .write()
            .broker_states
            .remove(&(realm, state.to_string()))
            .ok_or(StorageError::NotFound)
    }

    // ---- BrokerLink ----
    async fn upsert_broker_link(&self, link: BrokerLink) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.broker_links.insert(
            (
                link.realm_id,
                link.idp_alias.clone(),
                link.external_id.clone(),
            ),
            link,
        );
        Ok(())
    }

    async fn find_broker_link(
        &self,
        realm: RealmId,
        idp_alias: &str,
        external_id: &str,
    ) -> Result<Option<BrokerLink>, StorageError> {
        Ok(self
            .inner
            .read()
            .broker_links
            .get(&(realm, idp_alias.to_string(), external_id.to_string()))
            .cloned())
    }

    async fn list_broker_links(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<Vec<BrokerLink>, StorageError> {
        Ok(self
            .inner
            .read()
            .broker_links
            .iter()
            .filter(|((r, _, _), v)| *r == realm && v.user_id == user_id)
            .map(|(_, v)| v.clone())
            .collect())
    }

    // ---- LDAP federation source ----
    async fn upsert_ldap_source(
        &self,
        source: LdapFederationConfig,
    ) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.ldap_sources
            .insert((source.realm_id, source.alias.clone()), source);
        Ok(())
    }

    async fn get_ldap_source(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<LdapFederationConfig, StorageError> {
        self.inner
            .read()
            .ldap_sources
            .get(&(realm, alias.to_string()))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn list_ldap_sources(
        &self,
        realm: RealmId,
    ) -> Result<Vec<LdapFederationConfig>, StorageError> {
        Ok(self
            .inner
            .read()
            .ldap_sources
            .iter()
            .filter(|((r, _), _)| *r == realm)
            .map(|(_, v)| v.clone())
            .collect())
    }

    async fn delete_ldap_source(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<(), StorageError> {
        self.inner
            .write()
            .ldap_sources
            .remove(&(realm, alias.to_string()))
            .ok_or(StorageError::NotFound)
            .map(|_| ())
    }

    // ---- WASM modules ----
    async fn upload_wasm_module(&self, module: WasmModule) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.wasm_modules
            .insert((module.realm_id, module.alias.clone()), module);
        Ok(())
    }

    async fn get_wasm_module(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<WasmModule, StorageError> {
        self.inner
            .read()
            .wasm_modules
            .get(&(realm, alias.to_string()))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn list_wasm_modules(
        &self,
        realm: RealmId,
    ) -> Result<Vec<WasmModuleHeader>, StorageError> {
        Ok(self
            .inner
            .read()
            .wasm_modules
            .iter()
            .filter(|((r, _), _)| *r == realm)
            .map(|(_, m)| WasmModuleHeader {
                id: m.id,
                realm_id: m.realm_id,
                alias: m.alias.clone(),
                interface: m.interface.clone(),
                sha256_hex: m.sha256_hex.clone(),
                size_bytes: m.size_bytes,
                created_at: m.created_at,
            })
            .collect())
    }

    async fn delete_wasm_module(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<(), StorageError> {
        self.inner
            .write()
            .wasm_modules
            .remove(&(realm, alias.to_string()))
            .ok_or(StorageError::NotFound)
            .map(|_| ())
    }

    // ---- SPI bindings ----
    async fn create_spi_binding(
        &self,
        binding: SpiBindingRow,
    ) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.spi_bindings.insert((binding.realm_id, binding.id), binding);
        Ok(())
    }

    async fn list_spi_bindings(
        &self,
        realm: RealmId,
        interface: &str,
    ) -> Result<Vec<SpiBindingRow>, StorageError> {
        Ok(self
            .inner
            .read()
            .spi_bindings
            .iter()
            .filter(|((r, _), v)| *r == realm && v.interface == interface)
            .map(|(_, v)| v.clone())
            .collect())
    }

    async fn update_spi_binding(
        &self,
        binding: SpiBindingRow,
    ) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        if !t.spi_bindings.contains_key(&(binding.realm_id, binding.id)) {
            return Err(StorageError::NotFound);
        }
        t.spi_bindings.insert((binding.realm_id, binding.id), binding);
        Ok(())
    }

    async fn delete_spi_binding(
        &self,
        realm: RealmId,
        binding_id: geonosis_core::id::SpiBindingId,
    ) -> Result<(), StorageError> {
        self.inner
            .write()
            .spi_bindings
            .remove(&(realm, binding_id))
            .ok_or(StorageError::NotFound)
            .map(|_| ())
    }

    // ---- Role ----
    async fn create_role(&self, role: Role) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let key = (role.realm_id, role.id);
        if t.roles.contains_key(&key) {
            return Err(StorageError::Conflict("role exists".into()));
        }
        if t.roles
            .values()
            .any(|r| r.realm_id == role.realm_id && r.client_id == role.client_id && r.name == role.name)
        {
            return Err(StorageError::Conflict("role name taken".into()));
        }
        t.roles.insert(key, role);
        Ok(())
    }

    async fn get_role(&self, realm: RealmId, id: RoleId) -> Result<Role, StorageError> {
        self.inner
            .read()
            .roles
            .get(&(realm, id))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn get_role_by_name(
        &self,
        realm: RealmId,
        client_id: Option<ClientId>,
        name: &str,
    ) -> Result<Role, StorageError> {
        self.inner
            .read()
            .roles
            .values()
            .find(|r| r.realm_id == realm && r.client_id == client_id && r.name == name)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn list_roles(
        &self,
        realm: RealmId,
        client_id: Option<ClientId>,
    ) -> Result<Vec<Role>, StorageError> {
        Ok(self
            .inner
            .read()
            .roles
            .values()
            .filter(|r| r.realm_id == realm && r.client_id == client_id)
            .cloned()
            .collect())
    }

    async fn update_role(&self, role: Role) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let key = (role.realm_id, role.id);
        if !t.roles.contains_key(&key) {
            return Err(StorageError::NotFound);
        }
        t.roles.insert(key, role);
        Ok(())
    }

    async fn delete_role(&self, realm: RealmId, id: RoleId) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.roles
            .remove(&(realm, id))
            .ok_or(StorageError::NotFound)?;
        // Cascade unassign.
        for v in t.user_roles.values_mut() {
            v.retain(|r| *r != id);
        }
        for v in t.group_roles.values_mut() {
            v.retain(|r| *r != id);
        }
        Ok(())
    }

    async fn assign_user_role(
        &self,
        realm: RealmId,
        user_id: UserId,
        role_id: RoleId,
    ) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        if !t.roles.contains_key(&(realm, role_id)) {
            return Err(StorageError::NotFound);
        }
        let entry = t.user_roles.entry((realm, user_id)).or_default();
        if !entry.contains(&role_id) {
            entry.push(role_id);
        }
        Ok(())
    }

    async fn unassign_user_role(
        &self,
        realm: RealmId,
        user_id: UserId,
        role_id: RoleId,
    ) -> Result<(), StorageError> {
        if let Some(v) = self.inner.write().user_roles.get_mut(&(realm, user_id)) {
            v.retain(|r| *r != role_id);
        }
        Ok(())
    }

    async fn list_user_roles(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<Vec<Role>, StorageError> {
        let t = self.inner.read();
        let ids = t
            .user_roles
            .get(&(realm, user_id))
            .cloned()
            .unwrap_or_default();
        Ok(ids
            .into_iter()
            .filter_map(|id| t.roles.get(&(realm, id)).cloned())
            .collect())
    }

    // ---- Group ----
    async fn create_group(&self, group: Group) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let key = (group.realm_id, group.id);
        if t.groups.contains_key(&key) {
            return Err(StorageError::Conflict("group exists".into()));
        }
        if t.groups
            .values()
            .any(|g| g.realm_id == group.realm_id && g.path == group.path)
        {
            return Err(StorageError::Conflict("group path taken".into()));
        }
        t.groups.insert(key, group);
        Ok(())
    }

    async fn get_group(&self, realm: RealmId, id: GroupId) -> Result<Group, StorageError> {
        self.inner
            .read()
            .groups
            .get(&(realm, id))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn get_group_by_path(
        &self,
        realm: RealmId,
        path: &str,
    ) -> Result<Group, StorageError> {
        self.inner
            .read()
            .groups
            .values()
            .find(|g| g.realm_id == realm && g.path == path)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn list_groups(&self, realm: RealmId) -> Result<Vec<Group>, StorageError> {
        Ok(self
            .inner
            .read()
            .groups
            .values()
            .filter(|g| g.realm_id == realm)
            .cloned()
            .collect())
    }

    async fn update_group(&self, group: Group) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let key = (group.realm_id, group.id);
        if !t.groups.contains_key(&key) {
            return Err(StorageError::NotFound);
        }
        t.groups.insert(key, group);
        Ok(())
    }

    async fn delete_group(&self, realm: RealmId, id: GroupId) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        t.groups
            .remove(&(realm, id))
            .ok_or(StorageError::NotFound)?;
        for v in t.user_groups.values_mut() {
            v.retain(|g| *g != id);
        }
        t.group_roles.remove(&(realm, id));
        Ok(())
    }

    async fn assign_user_group(
        &self,
        realm: RealmId,
        user_id: UserId,
        group_id: GroupId,
    ) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        if !t.groups.contains_key(&(realm, group_id)) {
            return Err(StorageError::NotFound);
        }
        let entry = t.user_groups.entry((realm, user_id)).or_default();
        if !entry.contains(&group_id) {
            entry.push(group_id);
        }
        Ok(())
    }

    async fn unassign_user_group(
        &self,
        realm: RealmId,
        user_id: UserId,
        group_id: GroupId,
    ) -> Result<(), StorageError> {
        if let Some(v) = self.inner.write().user_groups.get_mut(&(realm, user_id)) {
            v.retain(|g| *g != group_id);
        }
        Ok(())
    }

    async fn list_user_groups(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<Vec<Group>, StorageError> {
        let t = self.inner.read();
        let ids = t
            .user_groups
            .get(&(realm, user_id))
            .cloned()
            .unwrap_or_default();
        Ok(ids
            .into_iter()
            .filter_map(|id| t.groups.get(&(realm, id)).cloned())
            .collect())
    }

    async fn assign_group_role(
        &self,
        realm: RealmId,
        group_id: GroupId,
        role_id: RoleId,
    ) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        if !t.groups.contains_key(&(realm, group_id)) {
            return Err(StorageError::NotFound);
        }
        if !t.roles.contains_key(&(realm, role_id)) {
            return Err(StorageError::NotFound);
        }
        let entry = t.group_roles.entry((realm, group_id)).or_default();
        if !entry.contains(&role_id) {
            entry.push(role_id);
        }
        Ok(())
    }

    async fn unassign_group_role(
        &self,
        realm: RealmId,
        group_id: GroupId,
        role_id: RoleId,
    ) -> Result<(), StorageError> {
        if let Some(v) = self.inner.write().group_roles.get_mut(&(realm, group_id)) {
            v.retain(|r| *r != role_id);
        }
        Ok(())
    }

    async fn list_group_roles(
        &self,
        realm: RealmId,
        group_id: GroupId,
    ) -> Result<Vec<Role>, StorageError> {
        let t = self.inner.read();
        let ids = t
            .group_roles
            .get(&(realm, group_id))
            .cloned()
            .unwrap_or_default();
        Ok(ids
            .into_iter()
            .filter_map(|id| t.roles.get(&(realm, id)).cloned())
            .collect())
    }

    // ---- User Profile schema ----
    async fn get_user_profile_schema(
        &self,
        realm: RealmId,
    ) -> Result<UserProfile, StorageError> {
        Ok(self
            .inner
            .read()
            .user_profile_schemas
            .get(&realm)
            .cloned()
            .unwrap_or_else(|| UserProfile::default_for(realm)))
    }

    async fn save_user_profile_schema(
        &self,
        profile: UserProfile,
    ) -> Result<(), StorageError> {
        self.inner
            .write()
            .user_profile_schemas
            .insert(profile.realm_id, profile);
        Ok(())
    }

    // ---- Agent ----
    async fn create_agent(&self, agent: Agent) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let key = (agent.realm_id, agent.id);
        if t.agents.contains_key(&key) {
            return Err(StorageError::Conflict("agent exists".into()));
        }
        if t.agents
            .values()
            .any(|a| a.realm_id == agent.realm_id && a.alias == agent.alias)
        {
            return Err(StorageError::Conflict("agent alias taken".into()));
        }
        t.agents.insert(key, agent);
        Ok(())
    }

    async fn get_agent(&self, realm: RealmId, id: AgentId) -> Result<Agent, StorageError> {
        self.inner
            .read()
            .agents
            .get(&(realm, id))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn get_agent_by_alias(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<Agent, StorageError> {
        self.inner
            .read()
            .agents
            .values()
            .find(|a| a.realm_id == realm && a.alias == alias)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn list_agents(&self, realm: RealmId) -> Result<Vec<Agent>, StorageError> {
        Ok(self
            .inner
            .read()
            .agents
            .values()
            .filter(|a| a.realm_id == realm)
            .cloned()
            .collect())
    }

    async fn update_agent(&self, agent: Agent) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let key = (agent.realm_id, agent.id);
        if !t.agents.contains_key(&key) {
            return Err(StorageError::NotFound);
        }
        t.agents.insert(key, agent);
        Ok(())
    }

    async fn revoke_agent(&self, realm: RealmId, id: AgentId) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let agent = t
            .agents
            .get_mut(&(realm, id))
            .ok_or(StorageError::NotFound)?;
        agent.revoked_at = Some(chrono::Utc::now());
        agent.enabled = false;
        Ok(())
    }

    // ---- Organization ----
    async fn create_organization(&self, org: Organization) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        if t.org_by_alias
            .contains_key(&(org.realm_id, org.alias.clone()))
        {
            return Err(StorageError::Conflict("org alias taken".into()));
        }
        t.org_by_alias
            .insert((org.realm_id, org.alias.clone()), org.id);
        t.organizations.insert((org.realm_id, org.id), org);
        Ok(())
    }

    async fn get_organization(
        &self,
        realm: RealmId,
        id: OrganizationId,
    ) -> Result<Organization, StorageError> {
        self.inner
            .read()
            .organizations
            .get(&(realm, id))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn get_organization_by_alias(
        &self,
        realm: RealmId,
        alias: &str,
    ) -> Result<Organization, StorageError> {
        let t = self.inner.read();
        let id = t
            .org_by_alias
            .get(&(realm, alias.to_string()))
            .ok_or(StorageError::NotFound)?;
        t.organizations
            .get(&(realm, *id))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn list_organizations(
        &self,
        realm: RealmId,
    ) -> Result<Vec<Organization>, StorageError> {
        Ok(self
            .inner
            .read()
            .organizations
            .values()
            .filter(|o| o.realm_id == realm)
            .cloned()
            .collect())
    }

    async fn update_organization(&self, org: Organization) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let key = (org.realm_id, org.id);
        if !t.organizations.contains_key(&key) {
            return Err(StorageError::NotFound);
        }
        // Keep alias index in sync.
        let old_alias = t.organizations.get(&key).map(|o| o.alias.clone());
        if let Some(a) = old_alias {
            if a != org.alias {
                t.org_by_alias.remove(&(org.realm_id, a));
                t.org_by_alias
                    .insert((org.realm_id, org.alias.clone()), org.id);
            }
        }
        t.organizations.insert(key, org);
        Ok(())
    }

    async fn delete_organization(
        &self,
        realm: RealmId,
        id: OrganizationId,
    ) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let o = t
            .organizations
            .remove(&(realm, id))
            .ok_or(StorageError::NotFound)?;
        t.org_by_alias.remove(&(realm, o.alias));
        t.org_domains.retain(|(oid, _), _| *oid != id);
        t.org_memberships.retain(|(oid, _), _| *oid != id);
        t.org_consent_policies.retain(|(oid, _), _| *oid != id);
        t.org_idp_bindings.retain(|(oid, _), _| *oid != id);
        Ok(())
    }

    async fn upsert_org_domain(&self, domain: OrgDomain) -> Result<(), StorageError> {
        self.inner
            .write()
            .org_domains
            .insert((domain.organization_id, domain.domain.clone()), domain);
        Ok(())
    }

    async fn list_org_domains(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgDomain>, StorageError> {
        Ok(self
            .inner
            .read()
            .org_domains
            .values()
            .filter(|d| d.organization_id == organization_id && d.realm_id == realm)
            .cloned()
            .collect())
    }

    async fn delete_org_domain(
        &self,
        _realm: RealmId,
        organization_id: OrganizationId,
        domain: &str,
    ) -> Result<(), StorageError> {
        self.inner
            .write()
            .org_domains
            .remove(&(organization_id, domain.to_string()))
            .ok_or(StorageError::NotFound)
            .map(|_| ())
    }

    async fn find_org_by_verified_domain(
        &self,
        realm: RealmId,
        domain: &str,
    ) -> Result<Option<Organization>, StorageError> {
        let t = self.inner.read();
        let Some(d) = t.org_domains.values().find(|d| {
            d.realm_id == realm && d.domain == domain && d.verified
        }) else {
            return Ok(None);
        };
        Ok(t.organizations
            .get(&(realm, d.organization_id))
            .cloned())
    }

    async fn upsert_org_membership(
        &self,
        membership: OrgMembership,
    ) -> Result<(), StorageError> {
        self.inner.write().org_memberships.insert(
            (membership.organization_id, membership.user_id),
            membership,
        );
        Ok(())
    }

    async fn get_org_membership(
        &self,
        _realm: RealmId,
        organization_id: OrganizationId,
        user_id: UserId,
    ) -> Result<OrgMembership, StorageError> {
        self.inner
            .read()
            .org_memberships
            .get(&(organization_id, user_id))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn list_org_memberships(
        &self,
        _realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgMembership>, StorageError> {
        Ok(self
            .inner
            .read()
            .org_memberships
            .values()
            .filter(|m| m.organization_id == organization_id)
            .cloned()
            .collect())
    }

    async fn list_user_orgs(
        &self,
        realm: RealmId,
        user_id: UserId,
    ) -> Result<Vec<OrgMembership>, StorageError> {
        Ok(self
            .inner
            .read()
            .org_memberships
            .values()
            .filter(|m| m.user_id == user_id && m.realm_id == realm)
            .cloned()
            .collect())
    }

    async fn delete_org_membership(
        &self,
        _realm: RealmId,
        organization_id: OrganizationId,
        user_id: UserId,
    ) -> Result<(), StorageError> {
        self.inner
            .write()
            .org_memberships
            .remove(&(organization_id, user_id))
            .ok_or(StorageError::NotFound)
            .map(|_| ())
    }

    async fn create_org_role(&self, role: OrgRole) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let key = (role.realm_id, role.id);
        if t.org_roles.contains_key(&key) {
            return Err(StorageError::Conflict("org role exists".into()));
        }
        t.org_roles.insert(key, role);
        Ok(())
    }

    async fn get_org_role(
        &self,
        realm: RealmId,
        id: OrgRoleId,
    ) -> Result<OrgRole, StorageError> {
        self.inner
            .read()
            .org_roles
            .get(&(realm, id))
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn list_org_roles(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgRole>, StorageError> {
        Ok(self
            .inner
            .read()
            .org_roles
            .values()
            .filter(|r| r.realm_id == realm && r.organization_id == organization_id)
            .cloned()
            .collect())
    }

    async fn update_org_role(&self, role: OrgRole) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let key = (role.realm_id, role.id);
        if !t.org_roles.contains_key(&key) {
            return Err(StorageError::NotFound);
        }
        t.org_roles.insert(key, role);
        Ok(())
    }

    async fn delete_org_role(
        &self,
        realm: RealmId,
        id: OrgRoleId,
    ) -> Result<(), StorageError> {
        self.inner
            .write()
            .org_roles
            .remove(&(realm, id))
            .ok_or(StorageError::NotFound)
            .map(|_| ())
    }

    async fn create_org_invitation(
        &self,
        invitation: OrgInvitation,
    ) -> Result<(), StorageError> {
        use geonosis_core::Secret;
        let mut t = self.inner.write();
        // Take the token plaintext for the lookup index. Secret<String> stays
        // boxed elsewhere; we only need its bytes for the by-token lookup.
        let token_value: &Secret<String> = &invitation.token;
        let token = token_value.expose().to_string();
        if t.org_invitations_by_token.contains_key(&token) {
            return Err(StorageError::Conflict("invitation token reuse".into()));
        }
        t.org_invitations_by_token.insert(token, invitation.id);
        t.org_invitations.insert(invitation.id, invitation);
        Ok(())
    }

    async fn get_org_invitation_by_token(
        &self,
        token: &str,
    ) -> Result<OrgInvitation, StorageError> {
        let t = self.inner.read();
        let id = t
            .org_invitations_by_token
            .get(token)
            .ok_or(StorageError::NotFound)?;
        t.org_invitations
            .get(id)
            .cloned()
            .ok_or(StorageError::NotFound)
    }

    async fn list_org_invitations(
        &self,
        realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgInvitation>, StorageError> {
        Ok(self
            .inner
            .read()
            .org_invitations
            .values()
            .filter(|i| i.realm_id == realm && i.organization_id == organization_id)
            .cloned()
            .collect())
    }

    async fn mark_org_invitation_accepted(
        &self,
        id: OrgInvitationId,
    ) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let i = t
            .org_invitations
            .get_mut(&id)
            .ok_or(StorageError::NotFound)?;
        i.accepted_at = Some(chrono::Utc::now());
        Ok(())
    }

    async fn delete_org_invitation(
        &self,
        id: OrgInvitationId,
    ) -> Result<(), StorageError> {
        let mut t = self.inner.write();
        let i = t
            .org_invitations
            .remove(&id)
            .ok_or(StorageError::NotFound)?;
        t.org_invitations_by_token.remove(i.token.expose());
        Ok(())
    }

    async fn upsert_org_consent_policy(
        &self,
        policy: OrgConsentPolicy,
    ) -> Result<(), StorageError> {
        self.inner
            .write()
            .org_consent_policies
            .insert((policy.organization_id, policy.client_id), policy);
        Ok(())
    }

    async fn get_org_consent_policy(
        &self,
        _realm: RealmId,
        organization_id: OrganizationId,
        client_id: ClientId,
    ) -> Result<Option<OrgConsentPolicy>, StorageError> {
        Ok(self
            .inner
            .read()
            .org_consent_policies
            .get(&(organization_id, client_id))
            .cloned())
    }

    async fn list_org_consent_policies(
        &self,
        _realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgConsentPolicy>, StorageError> {
        Ok(self
            .inner
            .read()
            .org_consent_policies
            .values()
            .filter(|p| p.organization_id == organization_id)
            .cloned()
            .collect())
    }

    async fn delete_org_consent_policy(
        &self,
        _realm: RealmId,
        organization_id: OrganizationId,
        client_id: ClientId,
    ) -> Result<(), StorageError> {
        self.inner
            .write()
            .org_consent_policies
            .remove(&(organization_id, client_id))
            .ok_or(StorageError::NotFound)
            .map(|_| ())
    }

    async fn upsert_org_idp_binding(
        &self,
        binding: OrgIdpBinding,
    ) -> Result<(), StorageError> {
        self.inner
            .write()
            .org_idp_bindings
            .insert(
                (binding.organization_id, binding.idp_alias.clone()),
                binding,
            );
        Ok(())
    }

    async fn list_org_idp_bindings(
        &self,
        _realm: RealmId,
        organization_id: OrganizationId,
    ) -> Result<Vec<OrgIdpBinding>, StorageError> {
        Ok(self
            .inner
            .read()
            .org_idp_bindings
            .values()
            .filter(|b| b.organization_id == organization_id)
            .cloned()
            .collect())
    }

    async fn delete_org_idp_binding(
        &self,
        _realm: RealmId,
        organization_id: OrganizationId,
        idp_alias: &str,
    ) -> Result<(), StorageError> {
        self.inner
            .write()
            .org_idp_bindings
            .remove(&(organization_id, idp_alias.to_string()))
            .ok_or(StorageError::NotFound)
            .map(|_| ())
    }

    async fn list_audit_events(
        &self,
        _realm: RealmId,
        _filter: &crate::traits::AuditEventFilter<'_>,
        _limit: usize,
    ) -> Result<Vec<crate::traits::AuditEventRow>, StorageError> {
        // The in-memory backend is for quickstart / unit tests where
        // audit ingest goes to a no-op sink. Per docs/13 the audit
        // table is Postgres-backed in production; reads only return
        // data when the Postgres storage backend is active.
        Ok(Vec::new())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use geonosis_core::{
        LoginSettings, OtpPolicy, PasswordPolicy, Realm, RegistrationPolicy, SenderConstraint,
        SessionPolicy, SslRequirement, ThemeBinding, TokenPolicy, WebauthnPolicy,
    };

    fn fixture_realm() -> Realm {
        Realm {
            id: RealmId::new(),
            slug: "t".into(),
            display_name: "T".into(),
            frontend_url: None,
            admin_frontend_url: None,
            enabled: true,
            ssl_required: SslRequirement::ExternalRequests,
            login: LoginSettings::default(),
            registration: RegistrationPolicy::default(),
            session_policy: SessionPolicy::default(),
            token_policy: TokenPolicy::default(),
            brute_force: geonosis_core::BruteForcePolicy::default(),
            password_policy: PasswordPolicy::default(),
            otp_policy: OtpPolicy::default(),
            webauthn_policy: WebauthnPolicy::default(),
            acr_policy: geonosis_core::AcrPolicy::default(),
            sender_constraint_default: SenderConstraint::None,
            theme_binding: ThemeBinding::default(),
            localization: geonosis_core::LocalizationPolicy::default(),
            events: geonosis_core::EventConfig::default(),
            default_groups: vec![],
            default_roles: geonosis_core::realm::DefaultRoles::default(),
            organizations_enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn realm_crud() {
        let s = MemoryStorage::new();
        let r = fixture_realm();
        let id = r.id;
        s.create_realm(r.clone()).await.unwrap();
        assert_eq!(s.get_realm(id).await.unwrap().slug, "t");
        assert_eq!(s.get_realm_by_slug("t").await.unwrap().id, id);
        let mut r2 = r.clone();
        r2.display_name = "T2".into();
        s.update_realm(r2).await.unwrap();
        assert_eq!(s.get_realm(id).await.unwrap().display_name, "T2");
        s.delete_realm(id).await.unwrap();
        assert!(s.get_realm(id).await.is_err());
    }

    #[tokio::test]
    async fn unique_slug_enforced() {
        let s = MemoryStorage::new();
        let a = fixture_realm();
        let mut b = fixture_realm();
        b.slug = a.slug.clone();
        s.create_realm(a).await.unwrap();
        assert!(s.create_realm(b).await.is_err());
    }

    #[tokio::test]
    async fn code_consume_is_one_shot() {
        use geonosis_core::token::{CodeChallenge, CodeChallengeMethod};
        use url::Url;

        let s = MemoryStorage::new();
        let realm = RealmId::new();
        let client = ClientId::new();
        let user = UserId::new();
        let session = SessionId::new_random();
        let code = CodeId::new_random();
        let grant = CodeGrant {
            code: code.clone(),
            realm_id: realm,
            client_id: client,
            user_id: user,
            session_id: session,
            scope: vec![],
            redirect_uri: Url::parse("https://example.com/cb").unwrap(),
            code_challenge: Some(CodeChallenge {
                method: CodeChallengeMethod::S256,
                challenge: "abc".into(),
            }),
            nonce: None,
            state: None,
            amr: vec![],
            auth_time: Utc::now(),
            created_at: Utc::now(),
            expires_at: Utc::now(),
        };
        s.save_code_grant(grant).await.unwrap();
        let consumed = s.consume_code(&code).await.unwrap();
        assert_eq!(consumed.code, code);
        // Second consume must fail.
        assert!(s.consume_code(&code).await.is_err());
    }

    #[tokio::test]
    async fn refresh_family_revoke_invalidates_all() {
        let s = MemoryStorage::new();
        let family = TokenFamilyId::new();
        let realm = RealmId::new();
        for _ in 0..3 {
            let t = RefreshToken {
                id: RefreshTokenId("h".to_string() + &uniq()),
                family_id: family,
                realm_id: realm,
                client_id: ClientId::new(),
                user_id: UserId::new(),
                session_id: SessionId::new_random(),
                scope: vec![],
                issued_at: Utc::now(),
                expires_at: Utc::now(),
                used: false,
            };
            s.save_refresh_token(t).await.unwrap();
        }
        s.revoke_token_family(family).await.unwrap();
        // None of the tokens in the family should be retrievable.
        let t = s.inner.read();
        assert!(t.refresh_tokens.is_empty());
    }

    fn uniq() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        C.fetch_add(1, Ordering::Relaxed).to_string()
    }

}
