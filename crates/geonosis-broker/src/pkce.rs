//! PKCE (RFC 7636) helper. The broker always emits S256; `plain` is
//! never sent so we don't even expose it as an option.

use base64::Engine;
use rand::Rng;
use sha2::Digest;

/// One PKCE round of `(code_verifier, code_challenge)`. Caller keeps
/// the verifier in `BrokerAuthnState`, sends the challenge with the
/// authorization request, and presents the verifier at the token
/// endpoint.
#[derive(Debug, Clone)]
pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

impl PkcePair {
    /// Random 43-char verifier (96-bit security at base64url, well under
    /// the 128-char ceiling).
    pub fn generate() -> Self {
        // 32 random bytes → 43 base64url chars.
        let mut buf = [0u8; 32];
        rand::thread_rng().fill(&mut buf[..]);
        let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf);
        let challenge = Self::challenge_for(&verifier);
        Self {
            verifier,
            challenge,
        }
    }

    pub fn challenge_for(verifier: &str) -> String {
        let digest = sha2::Sha256::digest(verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_s256_of_verifier() {
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let c = PkcePair::challenge_for(v);
        // Known-good per RFC 7636 §B.
        assert_eq!(c, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn generated_pair_round_trips() {
        let p = PkcePair::generate();
        assert_eq!(PkcePair::challenge_for(&p.verifier), p.challenge);
    }
}
