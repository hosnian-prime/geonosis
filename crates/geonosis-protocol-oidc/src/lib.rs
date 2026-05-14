//! OIDC 1.0 endpoint logic (transport-agnostic).
//!
//! The actual axum routing lives in `geonosis-server`; this crate
//! contains the protocol decisions:
//! - `/authorize` request validation
//! - `/.well-known/openid-configuration` rendering
//! - `IdTokenClaims` / `AccessTokenClaims` construction
//! - Token issuance helpers (signs via `KeyManagementService`)

pub mod authorize;
pub mod backchannel_logout;
pub mod device;
pub mod discovery;
pub mod introspect;
pub mod issuer;
pub mod par;
pub mod userinfo;

pub use authorize::{AuthorizeRequest, AuthorizeRequestError, ResponseType};
pub use backchannel_logout::{
    LogoutTokenClaims, BACKCHANNEL_LOGOUT_EVENT, LOGOUT_TOKEN_TYP,
};
pub use device::{generate_user_code, DeviceAuthorizationResponse, DEVICE_CODE_DEFAULT_TTL_SECS, DEVICE_CODE_DEFAULT_INTERVAL_SECS};
pub use discovery::{discovery_document, DiscoveryDocument};
pub use introspect::{IntrospectionResponse, build_introspection};
pub use issuer::{AccessTokenExtras, OidcIssuer, OidcIssuerError};
pub use par::{ParResponse, generate_request_uri, PAR_DEFAULT_TTL_SECS};
pub use userinfo::{userinfo_for, UserinfoClaims};
