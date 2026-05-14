//! Built-in authenticator runtimes for Geonosis v0.1.
//!
//! Per `docs/06-auth-flows.md` §Built-in authenticators (v0.1):
//!
//! - `password` — Username + password against the local store
//! - `otp` — TOTP / HOTP (RFC 6238 + RFC 4226)
//! - `webauthn` — WebAuthn assertion (assertion-as-step in v0.1; full
//!   passkey lifecycle lands in v0.2)
//! - `recovery-code` — One-time recovery code
//! - `magic-link` — Single-use email token (gated by realm SMTP config)
//! - `phone-otp` — SMS one-time password (SMS dispatch via SPI plugin)
//! - `consent` — OAuth consent screen
//! - `cookie` — Re-use existing SSO cookie
//! - `idp-redirect` — Begin a broker-step
//! - `require-action` — Verify-email, update-password, etc.
//! - `risk-score` — Returns a discrete risk decision
//!
//! Every built-in is a `pub struct` implementing `Authenticator` and
//! registers under a stable `builtin:authn:<name>` URN. The flow
//! executor + WASM SPI dispatch through the same trait so plugins and
//! built-ins are interchangeable (per `docs/07-spi-wasm.md`).

pub mod brute_force;
pub mod consent;
pub mod context;
pub mod cookie;
pub mod idp_redirect;
pub mod magic_link;
pub mod otp;
pub mod password;
pub mod phone_otp;
pub mod recovery_code;
pub mod registry;
pub mod require_action;
pub mod risk_score;
pub mod traits;
pub mod webauthn;

pub use brute_force::{check_locked, record_failure, record_success, BruteForceError};
pub use consent::ConsentAuthenticator;
pub use context::AuthnContext;
pub use cookie::CookieAuthenticator;
pub use idp_redirect::IdpRedirectAuthenticator;
pub use magic_link::{MagicLinkAuthenticator, MagicLinkSender};
pub use otp::{generate_totp_at, OtpAuthenticator, OtpConfig};
pub use password::PasswordAuthenticator;
pub use phone_otp::{PhoneOtpAuthenticator, SmsSender};
pub use recovery_code::{generate_recovery_codes, RecoveryCodeAuthenticator};
pub use registry::{register_builtins, BuiltinUrn};
pub use require_action::RequireActionAuthenticator;
pub use risk_score::{RiskDecision, RiskScoreAuthenticator};
pub use traits::{
    Authenticator, AuthnError, AuthnInput, AuthnOutput, FailureKind, RenderInstruction,
};
pub use webauthn::WebauthnAuthenticator;
