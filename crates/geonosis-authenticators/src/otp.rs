//! Built-in `otp` authenticator — RFC 6238 (TOTP) over RFC 4226 (HOTP).
//!
//! v0.1 default: SHA-1, 6 digits, 30-second period — matches `OtpPolicy`
//! defaults in `geonosis-core` and the Google Authenticator family.
//! SHA-256 / SHA-512 + alternate digits are accepted via realm config.

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use thiserror::Error;

use geonosis_core::realm::{OtpAlgorithm, OtpKind, OtpPolicy};
use geonosis_core::{Amr, CredentialKind};

use crate::context::AuthnContext;
use crate::traits::{
    Authenticator, AuthnError, AuthnInput, AuthnOutput, FailureKind, RenderInstruction,
};

#[derive(Debug, Error)]
pub enum OtpError {
    #[error("digits must be in 6..=10, got {0}")]
    BadDigits(u32),
    #[error("hmac key length: {0}")]
    BadKey(String),
}

/// Per-authenticator runtime config (compiled from `OtpPolicy` + flow-node config).
#[derive(Debug, Clone)]
pub struct OtpConfig {
    pub kind: OtpKind,
    pub algorithm: OtpAlgorithm,
    pub digits: u32,
    pub period_seconds: u32,
    /// How many adjacent steps either side of "now" we accept (TOTP).
    /// Default 1 (i.e. previous + current + next window).
    pub look_ahead_window: u32,
}

impl Default for OtpConfig {
    fn default() -> Self {
        Self::from_policy(&OtpPolicy::default())
    }
}

impl OtpConfig {
    pub fn from_policy(p: &OtpPolicy) -> Self {
        Self {
            kind: p.kind,
            algorithm: p.algorithm,
            digits: p.digits,
            period_seconds: p.period_seconds,
            look_ahead_window: p.look_ahead_window,
        }
    }
}

/// `builtin:authn:otp` — verifies a 6-digit code presented by the user
/// against the secret stored in their `otp` credential row.
pub struct OtpAuthenticator {
    pub config: OtpConfig,
}

impl OtpAuthenticator {
    pub fn new(config: OtpConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Authenticator for OtpAuthenticator {
    fn provider_id(&self) -> &'static str {
        "builtin:authn:otp"
    }

    async fn process(
        &self,
        ctx: &mut AuthnContext,
        input: AuthnInput,
    ) -> Result<AuthnOutput, AuthnError> {
        let fields = match input {
            AuthnInput::Submit(m) => m,
            _ => {
                return Ok(AuthnOutput::Continue {
                    render: RenderInstruction::new("login/otp.html"),
                });
            }
        };

        let user_id = ctx
            .user_id
            .ok_or_else(|| AuthnError::Invalid("otp requires resolved user".into()))?;
        let code = fields
            .get("code")
            .cloned()
            .ok_or_else(|| AuthnError::Invalid("missing code".into()))?;

        // For v0.1 the OTP secret is read directly from the user record
        // — once the credentials table is wired (sqlx Postgres) the
        // lookup migrates to `Storage::get_credential` with a richer row.
        let user = ctx
            .storage
            .get_user(ctx.realm_id, user_id)
            .await
            .map_err(|e| AuthnError::Storage(e.to_string()))?;
        let secret_hex = user
            .attributes
            .get("otp:secret")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthnError::Invalid("user has no OTP secret enrolled".into()))?
            .to_string();
        let secret = hex::decode(&secret_hex)
            .map_err(|e| AuthnError::Invalid(format!("invalid OTP secret hex: {e}")))?;

        let candidate = code.trim();
        if !candidate.chars().all(|c| c.is_ascii_digit())
            || candidate.len() as u32 != self.config.digits
        {
            return Ok(AuthnOutput::Failure(FailureKind::InvalidCredential));
        }

        let now_secs = ctx.now.timestamp() as u64;
        let ok = verify_totp(&self.config, &secret, candidate, now_secs)
            .map_err(|e| AuthnError::Crypto(e.to_string()))?;
        if !ok {
            return Ok(AuthnOutput::Failure(FailureKind::InvalidCredential));
        }

        ctx.record_amr(Amr::Otp);
        Ok(AuthnOutput::Success {
            credentials_satisfied: vec![CredentialKind::Otp],
            amr: vec![Amr::Otp],
        })
    }
}

/// Verify a TOTP code against `secret` for the current step plus
/// `±look_ahead_window` steps to tolerate clock skew. Constant-time per
/// step.
pub fn verify_totp(
    config: &OtpConfig,
    secret: &[u8],
    candidate: &str,
    now_unix_secs: u64,
) -> Result<bool, OtpError> {
    if !(6..=10).contains(&config.digits) {
        return Err(OtpError::BadDigits(config.digits));
    }
    let step = now_unix_secs / u64::from(config.period_seconds);
    let window = i64::from(config.look_ahead_window);
    let mut accepted = false;
    for delta in -window..=window {
        let t = (step as i64 + delta).max(0) as u64;
        let expected = format!(
            "{:0width$}",
            hotp(config.algorithm, secret, t)? % 10u32.pow(config.digits),
            width = config.digits as usize
        );
        if expected.as_bytes().ct_eq(candidate.as_bytes()).into() {
            accepted = true;
        }
    }
    Ok(accepted)
}

/// Generate a TOTP for a fixed point in time — exposed for tests and the
/// enrollment helper.
pub fn generate_totp_at(
    config: &OtpConfig,
    secret: &[u8],
    now_unix_secs: u64,
) -> Result<String, OtpError> {
    let step = now_unix_secs / u64::from(config.period_seconds);
    let n = hotp(config.algorithm, secret, step)? % 10u32.pow(config.digits);
    Ok(format!("{:0width$}", n, width = config.digits as usize))
}

/// RFC 4226 HOTP — the core HMAC-truncate primitive both HOTP and TOTP use.
fn hotp(alg: OtpAlgorithm, secret: &[u8], counter: u64) -> Result<u32, OtpError> {
    let bytes = counter.to_be_bytes();
    let mac_bytes: Vec<u8> = match alg {
        OtpAlgorithm::Sha1 => {
            let mut mac = <Hmac<Sha1>>::new_from_slice(secret)
                .map_err(|e| OtpError::BadKey(e.to_string()))?;
            mac.update(&bytes);
            mac.finalize().into_bytes().to_vec()
        }
        OtpAlgorithm::Sha256 => {
            let mut mac = <Hmac<Sha256>>::new_from_slice(secret)
                .map_err(|e| OtpError::BadKey(e.to_string()))?;
            mac.update(&bytes);
            mac.finalize().into_bytes().to_vec()
        }
        OtpAlgorithm::Sha512 => {
            let mut mac = <Hmac<Sha512>>::new_from_slice(secret)
                .map_err(|e| OtpError::BadKey(e.to_string()))?;
            mac.update(&bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };
    let offset = (mac_bytes[mac_bytes.len() - 1] & 0x0f) as usize;
    let bin_code = (u32::from(mac_bytes[offset]) & 0x7f) << 24
        | (u32::from(mac_bytes[offset + 1]) & 0xff) << 16
        | (u32::from(mac_bytes[offset + 2]) & 0xff) << 8
        | (u32::from(mac_bytes[offset + 3]) & 0xff);
    Ok(bin_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4226 Appendix D test vectors — secret "12345678901234567890" (ASCII).
    const RFC4226_SECRET: &[u8] = b"12345678901234567890";
    const RFC4226_VECTORS: &[(u64, &str)] = &[
        (0, "755224"),
        (1, "287082"),
        (2, "359152"),
        (3, "969429"),
        (4, "338314"),
        (5, "254676"),
        (6, "287922"),
        (7, "162583"),
        (8, "399871"),
        (9, "520489"),
    ];

    fn cfg_sha1() -> OtpConfig {
        OtpConfig {
            kind: OtpKind::Hotp,
            algorithm: OtpAlgorithm::Sha1,
            digits: 6,
            period_seconds: 30,
            look_ahead_window: 0,
        }
    }

    #[test]
    fn rfc4226_hotp_vectors() {
        for (counter, expected) in RFC4226_VECTORS {
            let n = hotp(OtpAlgorithm::Sha1, RFC4226_SECRET, *counter).unwrap();
            let got = format!("{:06}", n % 1_000_000);
            assert_eq!(&got, expected, "counter={counter}");
        }
    }

    // RFC 6238 Appendix B Table 1 (subset) — secret "12345678901234567890" (ASCII), SHA-1, T=30, digits=8.
    #[test]
    fn rfc6238_totp_sha1_vectors() {
        let cfg = OtpConfig {
            kind: OtpKind::Totp,
            algorithm: OtpAlgorithm::Sha1,
            digits: 8,
            period_seconds: 30,
            look_ahead_window: 0,
        };
        let pairs: &[(u64, &str)] = &[
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
        ];
        for (t, expected) in pairs {
            let got = generate_totp_at(&cfg, RFC4226_SECRET, *t).unwrap();
            assert_eq!(&got, expected, "t={t}");
        }
    }

    #[test]
    fn verify_accepts_current_window() {
        let mut cfg = cfg_sha1();
        cfg.look_ahead_window = 0;
        let t = 1_234_567_890u64;
        let code = generate_totp_at(&cfg, RFC4226_SECRET, t).unwrap();
        assert!(verify_totp(&cfg, RFC4226_SECRET, &code, t).unwrap());
    }

    #[test]
    fn verify_accepts_within_look_ahead() {
        let mut cfg = cfg_sha1();
        cfg.look_ahead_window = 1;
        let t = 1_700_000_000u64;
        // Code from the previous step is accepted with window=1.
        let prev_code = generate_totp_at(&cfg, RFC4226_SECRET, t - 30).unwrap();
        assert!(verify_totp(&cfg, RFC4226_SECRET, &prev_code, t).unwrap());
        let next_code = generate_totp_at(&cfg, RFC4226_SECRET, t + 30).unwrap();
        assert!(verify_totp(&cfg, RFC4226_SECRET, &next_code, t).unwrap());
    }

    #[test]
    fn verify_rejects_outside_window() {
        let mut cfg = cfg_sha1();
        cfg.look_ahead_window = 0;
        let t = 1_700_000_000u64;
        let stale = generate_totp_at(&cfg, RFC4226_SECRET, t - 90).unwrap();
        assert!(!verify_totp(&cfg, RFC4226_SECRET, &stale, t).unwrap());
    }

    #[test]
    fn verify_rejects_garbage_code() {
        let cfg = cfg_sha1();
        assert!(!verify_totp(&cfg, RFC4226_SECRET, "000000", 0).unwrap());
        assert!(!verify_totp(&cfg, RFC4226_SECRET, "garbage", 0).unwrap());
    }

    #[test]
    fn digits_outside_range_rejected() {
        let mut cfg = cfg_sha1();
        cfg.digits = 4;
        let err = verify_totp(&cfg, RFC4226_SECRET, "1234", 0).unwrap_err();
        assert!(matches!(err, OtpError::BadDigits(4)));
    }
}
