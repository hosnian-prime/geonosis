//! OIDC 1.0 endpoint logic (transport-agnostic).
//!
//! The actual axum routing lives in `geonosis-server`; this crate
//! contains the protocol decisions:
//! - `/authorize` request validation
//! - `/.well-known/openid-configuration` rendering
//! - `IdTokenClaims` / `AccessTokenClaims` construction
//! - Token issuance helpers (signs via `KeyManagementService`)

pub mod authorize;
pub mod discovery;
pub mod issuer;

pub use authorize::{AuthorizeRequest, AuthorizeRequestError, ResponseType};
pub use discovery::{discovery_document, DiscoveryDocument};
pub use issuer::{OidcIssuer, OidcIssuerError};
