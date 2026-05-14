//! Identity broker — Geonosis acting as an OIDC RP / SAML SP towards an
//! external IdP.
//!
//! Per `docs/05-identity-broker.md`:
//! - Generic OIDC + SAML adapters in the core binary; vendor quirks
//!   delegated to first-party `broker-adapter` SPI plugins.
//! - `BrokerAuthnState` row carries CSRF `state` + OIDC `nonce` across
//!   the outbound redirect + inbound callback round-trip (TTL 10 min).
//!
//! Crate layout:
//! - `types` — config + persisted records (no runtime deps)
//! - `oidc` — OIDC RP runtime: discovery, JWKS, code exchange, id_token verify
//! - `saml` — SAML SP runtime: AuthnRequest, ACS, signature verify
//! - `adapter` — vendor adapter trait + first-party impls (Google,
//!   GitHub, Apple, Microsoft)

pub mod mapper;
pub mod types;

pub use mapper::{apply_all as apply_mappers, DraftUser, MapperBinding, MapperKind};
pub use types::{
    BrokerAssertion, BrokerAuthnState, BrokerError, BrokerLink, ClientAuthMethod, IdentityProvider,
    IdpConfig, IdpKind, OidcIdpConfig, SamlIdpConfig,
};

#[cfg(feature = "broker-runtime")]
pub mod adapter;
#[cfg(feature = "broker-runtime")]
pub mod oidc;
#[cfg(feature = "broker-runtime")]
pub mod pkce;
#[cfg(feature = "broker-runtime")]
pub mod saml;

#[cfg(feature = "broker-runtime")]
pub use adapter::{BrokerAdapter, BuiltinAdapters, GenericOidcAdapter};
#[cfg(feature = "broker-runtime")]
pub use oidc::{exchange_code, fetch_discovery, fetch_jwks, OidcDiscovery, TokenResponse};
#[cfg(feature = "broker-runtime")]
pub use pkce::PkcePair;
#[cfg(feature = "broker-runtime")]
pub use saml::{build_authn_request, parse_response, verify_response_signature, SamlResponse};
