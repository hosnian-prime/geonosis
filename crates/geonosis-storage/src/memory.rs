//! In-memory storage. Default for tests and the 5-minute quickstart.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;

use geonosis_core::{
    Client, ClientId, CodeGrant, CodeId, FlowStateId, Realm, RealmId, RefreshToken, RefreshTokenId,
    Session, SessionId, TokenFamilyId, User, UserId,
};

use crate::error::StorageError;
use crate::traits::{
    ConsentGrant, DeviceGrant, FlowStateRow, ParRequest, SpiBindingRow, Storage, WasmModule,
    WasmModuleHeader,
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
    wasm_modules: HashMap<(RealmId, String), WasmModule>,
    spi_bindings: HashMap<(RealmId, geonosis_core::id::SpiBindingId), SpiBindingRow>,
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
