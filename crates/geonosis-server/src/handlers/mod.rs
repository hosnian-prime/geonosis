//! HTTP handlers for the Geonosis protocol surface.
//!
//! Per `docs/03-protocols-oidc.md` v0.1 ships:
//! - Health probes: `/-/started`, `/-/ready`, `/-/healthy`
//! - Discovery: `/realms/{slug}/.well-known/openid-configuration`
//! - JWKS: `/realms/{slug}/protocol/openid-connect/jwks`
//! - `/authorize` (GET + POST, including PAR `request_uri` resolution)
//! - `/token` (auth_code, refresh, client_credentials, password, device_code, token-exchange)
//! - `/userinfo` (GET + POST)
//! - `/logout` (front + back-channel)
//! - `/revoke` (RFC 7009)
//! - `/introspect` (RFC 7662)
//! - `/par` (RFC 9126)
//! - `/device/authorize` + `/device/token` (RFC 8628)
//! - `/login-actions/authenticate` (form-post auth used by the test login UI)

pub mod authorize;
pub mod broker;
pub mod client_auth;
pub mod device;
pub mod error;
pub mod health;
pub mod introspect;
pub mod login_actions;
pub mod logout;
pub mod oidc_meta;
pub mod par;
pub mod revoke;
pub mod saml;
pub mod token;
pub mod userinfo;

pub use authorize::{authorize_get, authorize_post};
pub use broker::{broker_endpoint_get, broker_endpoint_post, broker_login, broker_metadata};
pub use device::{device_authorize, device_token};
pub use health::{drain, healthy, ready, started};
pub use saml::{
    acs_auto_post_form as saml_acs_form, metadata as saml_metadata, slo_get as saml_slo_get,
    slo_post as saml_slo_post, sso_get as saml_sso_get, sso_post as saml_sso_post,
    unsolicited as saml_unsolicited,
};
pub use introspect::introspect;
pub use login_actions::authenticate_post;
pub use logout::{logout_get, logout_post};
pub use oidc_meta::{jwks, openid_configuration};
pub use par::par;
pub use revoke::revoke;
pub use token::token;
pub use userinfo::{userinfo_get, userinfo_post};
