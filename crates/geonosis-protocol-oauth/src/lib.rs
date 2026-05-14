//! OAuth 2.1 grant engines.
//!
//! Per `docs/03-protocols-oidc.md`:
//! - PKCE is mandatory for public clients; `plain` is always rejected.
//! - Authorization codes are single-use, 60-second TTL.
//! - Refresh tokens use `family_id` rotation; reuse burns the family.
//! - Supported grants: authorization_code, refresh_token, client_credentials,
//!   password (deprecated), device_code, token_exchange.

pub mod error;
pub mod grants;
pub mod pkce;
pub mod refresh;

pub use error::{OAuthError, OAuthErrorCode};
pub use grants::{
    AuthorizationCodeGrant, ClientCredentialsGrant, IssuedTokens, TokenExchangeGrant,
    TokenExchangeSubjectTokenType, TokenIssuer,
};
pub use pkce::{
    derive_challenge_s256, validate_code_verifier, verify_code_verifier_against_challenge,
    PkceError,
};
pub use refresh::{rotate_refresh_token, validate_refresh, RefreshOutcome, RefreshRotateError};
