//! Cryptographic primitives for Geonosis.
//!
//! - JWT signing (RS256, ES256, EdDSA)
//! - JWKS rendering
//! - Argon2id password hashing
//! - AES-256-GCM secret wrapping (master-key-derived)
//! - Constant-time token-hash comparison
//! - `KeyManagementService` trait (software impl included; HSM/Vault in v0.2)

pub mod base64url;
pub mod cert;
pub mod hash;
pub mod jwk;
pub mod jwt;
pub mod kms;
pub mod password;
pub mod random;
pub mod refresh_token;
pub mod wrap;

pub use hash::token_hash;
pub use jwk::{Jwk, JwkSet, PublicJwk};
pub use jwt::{sign_jwt, verify_jwt, JwsHeader, JwtError, JwtVerifyError};
pub use kms::{
    KeyManagementService, KeyMaterial, KeyState, KeyUsage, KmsError, PrivateKeyRef, SoftwareKms,
};
pub use password::{hash_password, verify_password, PasswordError};
pub use random::{random_bytes, random_token};
pub use refresh_token::{refresh_token_hash, RefreshTokenSecret};
pub use wrap::{MasterKey, WrapError, WrappedSecret};
