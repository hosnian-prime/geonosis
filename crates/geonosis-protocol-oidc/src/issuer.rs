//! `TokenIssuer` implementation backed by `KeyManagementService`.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use thiserror::Error;

use geonosis_core::{
    AccessTokenClaims, Client, IdTokenClaims, Realm, RealmId, ScopeName, SessionId, Subject,
};
use geonosis_crypto::jwt::{sign_jwt, JwsHeader, PrivateMaterial};
use geonosis_crypto::KeyManagementService;
use geonosis_protocol_oauth::grants::GrantError;
use geonosis_protocol_oauth::TokenIssuer;

/// Errors emitted when issuing fails before the OAuth grant layer surfaces
/// them as `invalid_request` / `server_error`.
#[derive(Debug, Error)]
pub enum OidcIssuerError {
    #[error("kms: {0}")]
    Kms(#[from] geonosis_crypto::KmsError),
    #[error("signing: {0}")]
    Sign(String),
    #[error("internal: {0}")]
    Internal(String),
}

/// OIDC-aware token issuer. Holds a reference to the realm-scoped KMS and
/// the refresh-token hash key. v0.1 uses a single deployment-wide hash key
/// (per-realm derivation lands in v0.1.x once master-key derivation is
/// wired through the server).
pub struct OidcIssuer<K: KeyManagementService + ?Sized + 'static> {
    pub kms: Arc<K>,
    pub refresh_hash_key: [u8; 32],
    pub issuer_base: url::Url,
}

#[async_trait]
impl<K: KeyManagementService + ?Sized + 'static> TokenIssuer for OidcIssuer<K> {
    async fn mint_access_token(
        &self,
        realm: &Realm,
        client: &Client,
        subject: &Subject,
        session_id: &SessionId,
        scope: &[ScopeName],
    ) -> Result<(String, i64), GrantError> {
        let alg = client
            .access_token_signing_alg
            .unwrap_or(realm.token_policy.default_signing_alg);
        let kid = self
            .kms
            .active_signing_kid(realm.id, alg)
            .await
            .map_err(|e| GrantError::Internal(e.to_string()))?;
        let private = self
            .kms
            .load_private(&kid)
            .await
            .map_err(|e| GrantError::Internal(e.to_string()))?;

        let now = Utc::now();
        let exp_secs = realm.token_policy.access_token_lifespan.as_secs() as i64;
        let claims = AccessTokenClaims {
            iss: issuer_url(&self.issuer_base, &realm.slug),
            sub: resolve_sub(subject, client),
            aud: vec![client.client_id.clone()],
            exp: now.timestamp() + exp_secs,
            iat: now.timestamp(),
            jti: geonosis_crypto::random::random_token(),
            scope: scope
                .iter()
                .map(geonosis_core::ScopeName::as_str)
                .collect::<Vec<_>>()
                .join(" "),
            azp: client.client_id.clone(),
            sid: Some(session_id.to_string()),
            realm_access: None,
            resource_access: Default::default(),
            groups: None,
            // `org` claim is populated by the token-mint helper in
            // `geonosis_admin_ui::org_flow::build_org_claim_default`
            // before this struct is signed. The issuer leaves it None
            // here because the broker/admin contexts may override it
            // via the `?org=` selector at authorize-time.
            org: None,
            // `act` chain is only set by the Token Exchange path; the
            // base `mint_access_token` call is for the user/client
            // grant flow which has no upstream actor.
            act: None,
            ext: Default::default(),
        };
        let header = JwsHeader::new(alg, kid.to_string(), "JWT");
        let jwt = sign_jwt_compat(&header, &claims, &private).map_err(GrantError::Internal)?;
        Ok((jwt, exp_secs))
    }

    async fn mint_id_token(
        &self,
        realm: &Realm,
        client: &Client,
        subject: &Subject,
        session_id: &SessionId,
        _scope: &[ScopeName],
        nonce: Option<&str>,
        acr: Option<&str>,
    ) -> Result<String, GrantError> {
        let alg = client
            .access_token_signing_alg
            .unwrap_or(realm.token_policy.default_signing_alg);
        let kid = self
            .kms
            .active_signing_kid(realm.id, alg)
            .await
            .map_err(|e| GrantError::Internal(e.to_string()))?;
        let private = self
            .kms
            .load_private(&kid)
            .await
            .map_err(|e| GrantError::Internal(e.to_string()))?;

        let now = Utc::now();
        let claims = IdTokenClaims {
            iss: issuer_url(&self.issuer_base, &realm.slug),
            sub: resolve_sub(subject, client),
            aud: vec![client.client_id.clone()],
            exp: now.timestamp() + realm.token_policy.access_token_lifespan.as_secs() as i64,
            iat: now.timestamp(),
            auth_time: now.timestamp(),
            nonce: nonce.map(str::to_string),
            azp: client.client_id.clone(),
            amr: None,
            acr: acr.map(str::to_string),
            sid: Some(session_id.to_string()),
            name: None,
            preferred_username: None,
            email: None,
            email_verified: None,
        };
        let header = JwsHeader::new(alg, kid.to_string(), "JWT");
        sign_jwt_compat(&header, &claims, &private).map_err(GrantError::Internal)
    }

    fn refresh_hash_key(&self, _realm: RealmId) -> [u8; 32] {
        self.refresh_hash_key
    }
}

/// Optional non-default fields that handlers (Token Exchange,
/// organization-scoped login) want injected into the signed access
/// token. Keeping it as a single struct avoids breaking
/// `TokenIssuer::mint_access_token` whenever a new claim joins.
#[derive(Debug, Default, Clone)]
pub struct AccessTokenExtras {
    pub org: Option<geonosis_core::OrgClaim>,
    pub act: Option<serde_json::Value>,
    pub audience: Option<Vec<String>>,
}

impl<K: KeyManagementService + ?Sized + 'static> OidcIssuer<K> {
    /// Mint an access token with caller-provided extras (`org`, `act`,
    /// explicit audience). Used by the Token Exchange handler and the
    /// org-aware authorize path. The base trait method keeps its
    /// simpler signature for the everyday flow.
    pub async fn mint_access_token_with_extras(
        &self,
        realm: &Realm,
        client: &Client,
        subject: &Subject,
        session_id: &SessionId,
        scope: &[ScopeName],
        extras: AccessTokenExtras,
    ) -> Result<(String, i64), GrantError> {
        let alg = client
            .access_token_signing_alg
            .unwrap_or(realm.token_policy.default_signing_alg);
        let kid = self
            .kms
            .active_signing_kid(realm.id, alg)
            .await
            .map_err(|e| GrantError::Internal(e.to_string()))?;
        let private = self
            .kms
            .load_private(&kid)
            .await
            .map_err(|e| GrantError::Internal(e.to_string()))?;

        let now = Utc::now();
        let exp_secs = realm.token_policy.access_token_lifespan.as_secs() as i64;
        let aud = extras
            .audience
            .unwrap_or_else(|| vec![client.client_id.clone()]);
        let claims = AccessTokenClaims {
            iss: issuer_url(&self.issuer_base, &realm.slug),
            sub: resolve_sub(subject, client),
            aud,
            exp: now.timestamp() + exp_secs,
            iat: now.timestamp(),
            jti: geonosis_crypto::random::random_token(),
            scope: scope
                .iter()
                .map(geonosis_core::ScopeName::as_str)
                .collect::<Vec<_>>()
                .join(" "),
            azp: client.client_id.clone(),
            sid: Some(session_id.to_string()),
            realm_access: None,
            resource_access: Default::default(),
            groups: None,
            org: extras.org,
            act: extras.act,
            ext: Default::default(),
        };
        let header = JwsHeader::new(alg, kid.to_string(), "JWT");
        let jwt = sign_jwt_compat(&header, &claims, &private).map_err(GrantError::Internal)?;
        Ok((jwt, exp_secs))
    }
}

/// Resolve the `sub` claim for a token. When the client is configured
/// with `pairwise_sub_algorithm`, hash the raw user id with the
/// client_id as sector to produce a per-client opaque identifier.
/// Otherwise return the public subject identifier.
fn resolve_sub(subject: &Subject, client: &Client) -> String {
    let raw = subject.token_sub();
    match client.pairwise_sub_algorithm.as_deref() {
        Some("sha256") => geonosis_crypto::pairwise_subject_hash(&client.client_id, &raw),
        Some(_) => {
            // Unknown algorithm — fall back to public sub with a log.
            tracing::warn!(
                client_id = %client.client_id,
                "unknown pairwise_sub_algorithm; falling back to public sub",
            );
            raw
        }
        None => raw,
    }
}

fn issuer_url(base: &url::Url, slug: &str) -> String {
    let mut u = base.clone();
    let path = format!(
        "{}/realms/{}",
        u.path()
            .trim_end_matches('/')
            .trim_end_matches("/realms")
            .trim_end_matches('/'),
        slug
    );
    u.set_path(&path);
    u.to_string()
}

fn sign_jwt_compat<T: serde::Serialize>(
    header: &JwsHeader,
    claims: &T,
    key: &PrivateMaterial,
) -> Result<String, String> {
    sign_jwt(header, claims, key).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_url_includes_realm() {
        let base = url::Url::parse("https://g.example").unwrap();
        let s = issuer_url(&base, "acme");
        assert!(s.starts_with("https://g.example"), "got {s}");
        assert!(s.ends_with("/realms/acme"), "got {s}");
    }
}
