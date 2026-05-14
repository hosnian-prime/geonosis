//! Grant-type engines.
//!
//! Each grant produces an `IssuedTokens` package. The OIDC layer composes
//! these into the `/token` response.

use std::sync::Arc;

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use geonosis_core::{
    Client, ClientKind, CodeChallenge, CodeChallengeMethod, CodeGrant, CodeId, GrantType, Realm,
    RealmId, RefreshToken, RefreshTokenId, ScopeName, SessionId, Subject, UserId,
};
use geonosis_crypto::{refresh_token_hash, RefreshTokenSecret};
use geonosis_storage::Storage;

use crate::error::{OAuthError, OAuthErrorCode};
use crate::pkce::verify_code_verifier_against_challenge;
use crate::refresh::new_family;

/// Output of any grant — the OIDC handler wraps this for the HTTP response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedTokens {
    /// Bearer access token (JWT or opaque per client config).
    pub access_token: String,
    pub access_token_expires_in: i64,
    /// Identity token — only present when `openid` scope was requested.
    pub id_token: Option<String>,
    /// Refresh token plaintext (returned once; we persist only the hash).
    pub refresh_token: Option<String>,
    /// Scope echoed back per RFC 6749 §5.1.
    pub scope: String,
    pub token_type: TokenType,
    pub session_id: SessionId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TokenType {
    Bearer,
    /// DPoP-bound (RFC 9449). v0.2 wires this; v0.1 fixture only.
    Dpop,
}

/// Authorization-code grant engine.
#[derive(Debug)]
pub struct AuthorizationCodeGrant {
    pub code: CodeId,
    pub code_verifier: Option<String>,
    pub redirect_uri: Url,
    pub client_id: String,
}

#[derive(Debug, Error)]
pub enum GrantError {
    #[error(transparent)]
    OAuth(#[from] OAuthError),
    #[error("storage: {0}")]
    Storage(String),
    #[error("pkce: {0}")]
    Pkce(#[from] crate::pkce::PkceError),
    #[error("internal: {0}")]
    Internal(String),
}

/// Trait implemented by the OIDC layer to mint access / ID tokens. The
/// grant engines stay storage-aware but JWT-blind.
#[async_trait::async_trait]
pub trait TokenIssuer: Send + Sync {
    async fn mint_access_token(
        &self,
        realm: &Realm,
        client: &Client,
        subject: &Subject,
        session_id: &SessionId,
        scope: &[ScopeName],
    ) -> Result<(String, i64), GrantError>;

    async fn mint_id_token(
        &self,
        realm: &Realm,
        client: &Client,
        subject: &Subject,
        session_id: &SessionId,
        scope: &[ScopeName],
        nonce: Option<&str>,
    ) -> Result<String, GrantError>;

    /// Per-realm BLAKE3 hashing key for refresh-token storage.
    fn refresh_hash_key(&self, realm: RealmId) -> [u8; 32];
}

impl AuthorizationCodeGrant {
    pub async fn exchange(
        self,
        storage: &Arc<dyn Storage>,
        issuer: &dyn TokenIssuer,
        client: &Client,
        realm: &Realm,
    ) -> Result<IssuedTokens, GrantError> {
        // 1) Consume the code atomically.
        let code: CodeGrant = storage
            .consume_code(&self.code)
            .await
            .map_err(|_| OAuthError::invalid_grant("code unknown or already used"))?;

        // 2) TTL check (defense in depth; storage SHOULD have already enforced).
        if code.expires_at < Utc::now() {
            return Err(OAuthError::invalid_grant("code expired").into());
        }

        // 3) Match client_id from request to bound code.
        if client.client_id != self.client_id {
            return Err(OAuthError::invalid_grant("client_id mismatch").into());
        }

        // 4) Match redirect_uri exactly (RFC 6749 §10.6).
        if code.redirect_uri != self.redirect_uri {
            return Err(OAuthError::invalid_grant("redirect_uri mismatch").into());
        }

        // 5) PKCE: required for public clients; rejected with `plain`.
        if let Some(challenge) = &code.code_challenge {
            let v = self
                .code_verifier
                .as_deref()
                .ok_or_else(|| OAuthError::invalid_grant("code_verifier required"))?;
            verify_code_verifier_against_challenge(challenge.method.as_str(), v, &challenge.challenge)?;
        } else if client.kind == ClientKind::Public {
            return Err(OAuthError::invalid_grant("PKCE required for public clients").into());
        }

        // 6) Mint tokens.
        let subject = Subject::Local {
            user_id: code.user_id,
        };
        let (access, exp) = issuer
            .mint_access_token(realm, client, &subject, &code.session_id, &code.scope)
            .await?;
        let id_token = if code.scope.iter().any(|s| s.as_str() == "openid") {
            Some(
                issuer
                    .mint_id_token(realm, client, &subject, &code.session_id, &code.scope, code.nonce.as_deref())
                    .await?,
            )
        } else {
            None
        };

        // 7) Refresh token (rotated every use).
        let refresh = if client.kind != ClientKind::Public
            || code.scope.iter().any(|s| s.as_str() == "offline_access")
        {
            let secret = RefreshTokenSecret::generate();
            let key = issuer.refresh_hash_key(realm.id);
            let token = RefreshToken {
                id: RefreshTokenId(refresh_token_hash(secret.as_str(), &key)),
                family_id: new_family(),
                realm_id: realm.id,
                client_id: client.id,
                user_id: code.user_id,
                session_id: code.session_id.clone(),
                scope: code.scope.clone(),
                issued_at: Utc::now(),
                expires_at: Utc::now() + Duration::from_std(realm.token_policy.refresh_token_lifespan).unwrap_or_default(),
                used: false,
            };
            storage
                .save_refresh_token(token)
                .await
                .map_err(|e| GrantError::Storage(e.to_string()))?;
            Some(secret.as_str().to_string())
        } else {
            None
        };

        Ok(IssuedTokens {
            access_token: access,
            access_token_expires_in: exp,
            id_token,
            refresh_token: refresh,
            scope: code
                .scope
                .iter()
                .map(geonosis_core::ScopeName::as_str)
                .collect::<Vec<_>>()
                .join(" "),
            token_type: TokenType::Bearer,
            session_id: code.session_id,
        })
    }
}

/// Client-credentials grant engine.
#[derive(Debug)]
pub struct ClientCredentialsGrant {
    pub scope: Vec<ScopeName>,
}

impl ClientCredentialsGrant {
    pub async fn exchange(
        self,
        _storage: &Arc<dyn Storage>,
        issuer: &dyn TokenIssuer,
        client: &Client,
        realm: &Realm,
    ) -> Result<IssuedTokens, GrantError> {
        if !client.grants.client_credentials {
            return Err(OAuthError::unauthorized_client("client_credentials disabled").into());
        }
        let subject = Subject::ServiceAccount {
            client_id: client.id,
        };
        let session = SessionId::new_random();
        let (access, exp) = issuer
            .mint_access_token(realm, client, &subject, &session, &self.scope)
            .await?;
        Ok(IssuedTokens {
            access_token: access,
            access_token_expires_in: exp,
            id_token: None,
            refresh_token: None,
            scope: self
                .scope
                .iter()
                .map(geonosis_core::ScopeName::as_str)
                .collect::<Vec<_>>()
                .join(" "),
            token_type: TokenType::Bearer,
            session_id: session,
        })
    }
}

/// Token-exchange grant (RFC 8693) — v0.1 supports the Agent identity
/// path (`subject_token_type = access_token`, actor_token optional).
#[derive(Debug)]
pub struct TokenExchangeGrant {
    pub subject_token: String,
    pub subject_token_type: TokenExchangeSubjectTokenType,
    pub actor_token: Option<String>,
    pub requested_audience: Vec<String>,
    pub requested_scope: Vec<ScopeName>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenExchangeSubjectTokenType {
    AccessToken,
    RefreshToken,
    IdToken,
    SamlAssertion,
    JwtBearer,
}

impl TokenExchangeSubjectTokenType {
    pub fn as_uri(self) -> &'static str {
        match self {
            Self::AccessToken => "urn:ietf:params:oauth:token-type:access_token",
            Self::RefreshToken => "urn:ietf:params:oauth:token-type:refresh_token",
            Self::IdToken => "urn:ietf:params:oauth:token-type:id_token",
            Self::SamlAssertion => "urn:ietf:params:oauth:token-type:saml2",
            Self::JwtBearer => "urn:ietf:params:oauth:token-type:jwt",
        }
    }

    pub fn from_uri(s: &str) -> Option<Self> {
        Some(match s {
            "urn:ietf:params:oauth:token-type:access_token" => Self::AccessToken,
            "urn:ietf:params:oauth:token-type:refresh_token" => Self::RefreshToken,
            "urn:ietf:params:oauth:token-type:id_token" => Self::IdToken,
            "urn:ietf:params:oauth:token-type:saml2" => Self::SamlAssertion,
            "urn:ietf:params:oauth:token-type:jwt" => Self::JwtBearer,
            _ => return None,
        })
    }
}

/// PKCE-bound `CodeChallenge` helper: derive a challenge from a verifier
/// for code-issuance unit tests.
#[allow(dead_code)]
pub(crate) fn challenge_from_verifier(verifier: &str) -> CodeChallenge {
    CodeChallenge {
        method: CodeChallengeMethod::S256,
        challenge: crate::pkce::derive_challenge_s256(verifier).unwrap(),
    }
}

/// Confirm a `GrantType` is in the client's `grants` policy.
pub fn assert_grant_permitted(client: &Client, grant: GrantType) -> Result<(), OAuthError> {
    let ok = match grant {
        GrantType::AuthorizationCode => client.grants.authorization_code,
        GrantType::RefreshToken => client.grants.refresh_token,
        GrantType::ClientCredentials => client.grants.client_credentials,
        GrantType::Password => client.grants.password,
        GrantType::DeviceCode => client.grants.device_code,
        GrantType::TokenExchange => client.grants.token_exchange,
    };
    if ok {
        Ok(())
    } else {
        Err(OAuthError::new(
            OAuthErrorCode::UnauthorizedClient,
            format!("grant_type {} disabled for client", grant.as_token_param()),
        ))
    }
}

/// Helper exposed for use by handler code: the `UserId` extraction path
/// for refresh-token reuse audit events.
pub fn user_id_from_subject(s: &Subject) -> Option<UserId> {
    match s {
        Subject::Local { user_id } => Some(*user_id),
        Subject::Agent { parent, .. } => user_id_from_subject(parent),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use geonosis_core::{
        AccessTokenType, ClientAuthMethod, ConsentPolicy, FlowBinding, GrantPolicy,
    };
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    fn realm() -> Realm {
        Realm {
            id: RealmId::new(),
            slug: "t".into(),
            display_name: "T".into(),
            frontend_url: None,
            admin_frontend_url: None,
            enabled: true,
            ssl_required: geonosis_core::SslRequirement::ExternalRequests,
            login: Default::default(),
            registration: Default::default(),
            session_policy: Default::default(),
            token_policy: Default::default(),
            brute_force: Default::default(),
            password_policy: Default::default(),
            otp_policy: Default::default(),
            webauthn_policy: Default::default(),
            acr_policy: Default::default(),
            sender_constraint_default: geonosis_core::SenderConstraint::None,
            theme_binding: Default::default(),
            localization: Default::default(),
            events: Default::default(),
            default_groups: vec![],
            default_roles: Default::default(),
            organizations_enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn client() -> Client {
        Client {
            id: geonosis_core::ClientId::new(),
            realm_id: RealmId::new(),
            client_id: "spa".into(),
            display_name: None,
            kind: ClientKind::Public,
            grants: GrantPolicy::public_app(),
            auth_method: ClientAuthMethod::None,
            flow_binding: FlowBinding::default(),
            default_scopes: vec![],
            optional_scopes: vec![],
            redirect_uris: vec![],
            post_logout_redirect_uris: vec![],
            web_origins: vec![],
            access_token_type: AccessTokenType::Jwt,
            consent: ConsentPolicy::default(),
            access_token_lifespan: None,
            refresh_token_lifespan: None,
            access_token_signing_alg: None,
            front_channel_logout_enabled: false,
            backchannel_logout_url: None,
            client_authentication_keys: vec![],
            pairwise_sub_algorithm: None,
            saml_sp_config: None,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    struct TestIssuer {
        log: Mutex<HashMap<String, String>>,
    }

    #[async_trait::async_trait]
    impl TokenIssuer for TestIssuer {
        async fn mint_access_token(
            &self,
            _realm: &Realm,
            _client: &Client,
            _subject: &Subject,
            _session_id: &SessionId,
            _scope: &[ScopeName],
        ) -> Result<(String, i64), GrantError> {
            Ok(("access-token-jwt".into(), 300))
        }
        async fn mint_id_token(
            &self,
            _realm: &Realm,
            _client: &Client,
            _subject: &Subject,
            _session_id: &SessionId,
            _scope: &[ScopeName],
            nonce: Option<&str>,
        ) -> Result<String, GrantError> {
            self.log
                .lock()
                .await
                .insert("nonce".into(), nonce.unwrap_or("").to_string());
            Ok("id-token-jwt".into())
        }
        fn refresh_hash_key(&self, _realm: RealmId) -> [u8; 32] {
            [42u8; 32]
        }
    }

    #[tokio::test]
    async fn public_client_without_pkce_is_rejected() {
        let storage: Arc<dyn Storage> = Arc::new(geonosis_storage::MemoryStorage::new());
        let issuer = TestIssuer {
            log: Mutex::new(HashMap::new()),
        };
        let realm = realm();
        let client = client();
        let code_id = CodeId::new_random();
        let grant = CodeGrant {
            code: code_id.clone(),
            realm_id: realm.id,
            client_id: client.id,
            user_id: UserId::new(),
            session_id: SessionId::new_random(),
            scope: vec![],
            redirect_uri: Url::parse("https://example.com/cb").unwrap(),
            // No challenge stored — must reject for public.
            code_challenge: None,
            nonce: None,
            state: None,
            amr: vec![],
            auth_time: Utc::now(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(60),
        };
        storage.save_code_grant(grant).await.unwrap();
        let g = AuthorizationCodeGrant {
            code: code_id,
            code_verifier: None,
            redirect_uri: Url::parse("https://example.com/cb").unwrap(),
            client_id: "spa".into(),
        };
        let err = g.exchange(&storage, &issuer, &client, &realm).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("PKCE required"), "got: {msg}");
    }

    #[tokio::test]
    async fn code_consume_is_atomic() {
        let storage: Arc<dyn Storage> = Arc::new(geonosis_storage::MemoryStorage::new());
        let issuer = TestIssuer {
            log: Mutex::new(HashMap::new()),
        };
        let realm = realm();
        let client = client();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = challenge_from_verifier(verifier);

        let code_id = CodeId::new_random();
        let grant = CodeGrant {
            code: code_id.clone(),
            realm_id: realm.id,
            client_id: client.id,
            user_id: UserId::new(),
            session_id: SessionId::new_random(),
            scope: vec![ScopeName::new("openid").unwrap()],
            redirect_uri: Url::parse("https://example.com/cb").unwrap(),
            code_challenge: Some(challenge),
            nonce: Some("n1".into()),
            state: None,
            amr: vec![],
            auth_time: Utc::now(),
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(60),
        };
        storage.save_code_grant(grant).await.unwrap();

        let g = AuthorizationCodeGrant {
            code: code_id.clone(),
            code_verifier: Some(verifier.to_string()),
            redirect_uri: Url::parse("https://example.com/cb").unwrap(),
            client_id: "spa".into(),
        };
        let issued = g.exchange(&storage, &issuer, &client, &realm).await.unwrap();
        assert_eq!(issued.access_token, "access-token-jwt");
        assert!(issued.id_token.is_some());

        // Second exchange must fail — code already consumed.
        let g2 = AuthorizationCodeGrant {
            code: code_id,
            code_verifier: Some(verifier.to_string()),
            redirect_uri: Url::parse("https://example.com/cb").unwrap(),
            client_id: "spa".into(),
        };
        assert!(g2.exchange(&storage, &issuer, &client, &realm).await.is_err());
    }

    #[tokio::test]
    async fn token_exchange_uri_roundtrip() {
        let t = TokenExchangeSubjectTokenType::AccessToken;
        assert_eq!(
            TokenExchangeSubjectTokenType::from_uri(t.as_uri()),
            Some(t)
        );
    }
}
