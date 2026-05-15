# 12 — Security & Cryptography

This document covers cryptographic key management, JWT signing
choices, secret handling, and the threat model assumed throughout
the architecture.

## Threat model (abridged)

Assumed **in scope**:

- Network attacker on the path between client and server.
- Compromise of a single Postgres backup (the master key is required
  to read sensitive ciphertext).
- Compromise of a single pod (memory snapshot).
- Malicious or buggy SPI plugin uploaded by an admin.
- Misconfigured client (wildcard redirect URI, leaked client secret).
- Brute-force login attempts.

Assumed **out of scope** for v0.1:

- Compromise of the master encryption key.
- Compromise of the host OS / Kubernetes control plane.
- Side-channel attacks on the host CPU.
- A malicious realm admin attacking other realms (the master realm
  can do anything; sub-realm admins are confined by RLS + handler
  checks, but a v0.1 install is not a "hostile multi-tenant" product).

## Keys we manage

| Key | Algorithm options | Purpose | Rotation cadence |
|---|---|---|---|
| **Realm signing key** | RS256, RS384, RS512, ES256, ES384, EdDSA (Ed25519) | Sign id tokens, access tokens (JWS), JWKS publish | 90 days default |
| **Realm encryption key** | RSA-OAEP, ECDH-ES | JWE for tokens/requests when used | 180 days |
| **Realm HMAC key** | HS256/HS384/HS512 | `client_secret_jwt` validation, internal MAC for cookies | 180 days |
| **Master encryption key** (server) | AES-256-GCM (envelope) | Wrap all per-realm keys at rest; wrap stored secrets | Operator-controlled (rare) |
| **Refresh-token MAC key** | BLAKE3 keyed | Tokenize refresh tokens for index without storing plaintext | per realm; rotated on master rotation |
| **Cookie session signing key** | HMAC-SHA256 | Sign cookie values (session id, CSRF) | 30 days, rotation transparent |

## KeyMaterial lifecycle

```
Created → Active → PreviousActive → Disabled → (deleted after retention)
```

- **Active** keys sign new tokens; included in JWKS.
- **PreviousActive** keys do NOT sign new tokens; still appear in
  JWKS so existing tokens verify until they expire.
- **Disabled** keys are removed from JWKS; verification fails for
  any `kid` matching disabled keys.
- Per realm there's **exactly one Active** signing key per algorithm
  family for OIDC. Exception: SAML IdP signing permits multiple Active
  keys for SP metadata caching tolerance (see
  [`20-saml-idp.md`](./20-saml-idp.md) §Signing key rotation).

Rotation is a single admin call:

```
POST /admin/v1/realms/{slug}/keys/{kid}/rotate
```

The handler:

1. Generates a new key with the same algorithm.
2. Inserts the new `KeyMaterial` with `state=Active`.
3. Moves the old one to `state=PreviousActive`.
4. `pg_notify` invalidates the cached JWKS.
5. New requests use the new key immediately; existing tokens still
   verify until the old key is later disabled (operator action, or
   scheduled by a policy).

No tokens are invalidated by rotation. Reissuing must be triggered
explicitly if the operator believes the key is compromised
(`/keys/{kid}/disable` + revoke-all-sessions).

## Private key storage

Per `PrivateKeyRef`:

```rust
enum PrivateKeyRef {
    Local(WrappedSecret),   // ciphertext under master key, plus tag
    Kms(KmsUri),            // pointer to external KMS
}
```

### Local mode (default)

Private key bytes are encrypted with AES-256-GCM using a derived data
encryption key (DEK). The DEK itself is wrapped under the master key
(envelope encryption). The master key is loaded from
`GEONOSIS_MASTER_KEY` (a base64-encoded 32-byte secret) on startup.

If the master key isn't present, the server refuses to start.

### Bring-your-own-key (BYOK)

Operators can supply pre-generated private keys instead of letting
Geonosis generate them. Two paths, both v0.2:

1. **UI upload, KMS-backed.** Admin pastes a PEM or JWK (or
   uploads a file) for a chosen algorithm; the server wraps the
   private material with the master key (or hands it off to the
   configured KMS — `vault transit import`, AWS `ImportKeyMaterial`,
   GCP `ImportJob`) and persists a `KeyMaterial` row with
   `state=Active`. Verification public part is also stored as a
   JWK.
2. **CLI upload.** `geoctl keys import --realm master --pem signing.pem
   --alg RS256` does the same thing without UI.

Important invariants enforced on import:

- Key type matches the declared algorithm.
- For RSA, modulus ≥ 2048 bits; for ECDSA, allowed curves only
  (P-256/P-384); EdDSA Ed25519.
- An import sets `state=Active` only if there is no existing
  Active key of the same algorithm. Otherwise the imported key
  lands as `PreviousActive` and the admin promotes it explicitly.

The wire format for upload accepts:

- PEM (PKCS#8 for RSA/EC/Ed25519)
- JWK (private)
- DER (PKCS#8)
- HSM handles via `pkcs11:` URI when the realm's KMS is PKCS#11

v0.1 ships only **server-generated** keys; the upload paths land
in v0.2 with the first external KMS backend (Vault Transit).

### External KMS

`Kms(KmsUri)` indicates: sign by calling out to an external HSM/KMS.
Geonosis supports the following backends behind a trait:

```rust
#[async_trait]
trait KeyManagementService: Send + Sync {
    async fn sign(&self, kid: &KeyId, algo: KeyAlgorithm, data: &[u8])
        -> Result<Vec<u8>, KmsError>;

    async fn unwrap(&self, kid: &KeyId, wrapped: &[u8])
        -> Result<Zeroizing<Vec<u8>>, KmsError>;

    async fn jwk(&self, kid: &KeyId) -> Result<PublicJwk, KmsError>;
}
```

Implementations:

- `SoftwareKms` (default, v0.1): local AES-GCM envelope under
  `GEONOSIS_MASTER_KEY`.
- **`VaultTransit` (v0.2, first external backend)**: HashiCorp Vault
  Transit engine. Asymmetric signing supported by Vault for the
  algorithms we use (RS256/384/512, ES256/384, EdDSA). Chosen first
  because Vault is the most commonly available self-hosted KMS and
  is portable across clouds.
- `AwsKmsBackend` (v0.2.x): AWS KMS asymmetric keys.
- `GcpKmsBackend` (v0.2.x): Google Cloud KMS asymmetric keys.
- `Pkcs11Backend` (v0.3): generic HSMs via PKCS#11.

Hot path performance: software signing is ~50 µs; KMS-backed signing
is ~5 ms (network) — the server caches verification public keys
locally so verification is always fast, signing-only takes the hit.

## Master key management

- **Provisioning**: operator generates a 32-byte random and stores in
  K8s Secret / external secret store. Loaded into the process as
  `GEONOSIS_MASTER_KEY` (base64-encoded). Geonosis does NOT generate
  the master key itself on first boot (avoid surprise key creation).
- **No passphrase derivation in the server.** A passphrase-based
  master key invites operators to use weak passphrases. The repo
  ships a documented *recipe* (HKDF-SHA-256 with mandatory salt and
  length) as comments in the `geoctl secrets generate-master-key`
  subcommand — operators derive the 32-byte key out-of-band and
  provide it as the env var like any other secret.
- **Rotation**: a `geoctl secrets rewrap --new-key <path>` command
  reads every wrapped secret in the DB, decrypts with the old master,
  re-encrypts with the new, swaps in a transaction. Runtime supports
  reading either-old-or-new during a transition window
  (`MASTER_KEY_PRIMARY` + `MASTER_KEY_SECONDARY` env vars).
- **Backup**: master key is the encryption boundary for the DB. Lose
  it, lose all stored signing keys. Operator runbook MUST cover this.

## ACR Policy (per realm)

Authentication Context Class Reference (`acr`) is a token claim
expressing **how strong** the authentication was. Each realm defines
its `AcrPolicy`: an ordered list of levels with rules that translate
authentication outcomes (AMR + sender-constraint) into a level
identifier.

### Why per-realm

- Different operators use different ACR conventions (numeric `1/2/3`,
  ISO/IEC 29115 LoA, custom URIs).
- Step-up requirements differ ("MFA" means OTP here, WebAuthn there).
- Brokered IdPs return their own ACR strings; per-realm mapping is
  the natural place to normalize them.

### Default policy

A new realm starts with three levels (operator can rename / extend
without limit):

```yaml
acr_policy:
  levels:
    - value: "0"
      display_name: "Unauthenticated context"
      require:
        any: true
    - value: "1"
      display_name: "Single-factor"
      require:
        amr_contains: ["pwd"]
    - value: "2"
      display_name: "Multi-factor"
      require:
        all_of:
          - amr_contains: ["pwd"]
          - any_of:
              - amr_contains: ["otp"]
              - amr_contains: ["wbn"]   # WebAuthn
    # Level 3 (Hardware-bound + sender-constrained) is available as a
    # v0.2 extension once DPoP / mTLS lands. Operators can add it then:
    #
    # - value: "3"
    #   display_name: "Hardware-bound"
    #   require:
    #     all_of:
    #       - amr_contains: ["wbn"]
    #       - sender_constrained: "dpop"
```

The executor picks the **highest** level whose `require` evaluates
true given the current session AMRs and the access token's
sender-constraint binding.

### `acr_values` interaction

When a client passes `acr_values="2 3"` on `/authorize`:

1. The executor evaluates the current session's ACR.
2. If neither 2 nor 3 is satisfied, the executor selects the
   realm's `step-up` flow bound to the *lowest acceptable* requested
   level (here, level 2).
3. After step-up, ACR is re-evaluated; if it now satisfies a
   requested level, the request proceeds and the `acr` claim
   reflects the satisfied level. If not, the response is
   `interaction_required` (or `login_required` per RFC).

### Brokered IdP ACR mapping

Per `IdentityProvider` config, operators may declare
`acr_remap: { "google:enterprise" -> "2", "okta:phr" -> "3" }`.
Mapping happens at the broker boundary; from there the local
`acr_policy` takes over.

## Password storage (local users)

- **Argon2id** with `m=64 MiB`, `t=3`, `p=4` parameters by default.
- Parameter values stored alongside hash so we can upgrade without
  rehashing. On successful login with old parameters, rehash and
  update on the fly.
- Pepper: optional, sourced from the master key (HKDF-Expand with
  context "password-pepper"). Off by default; on with
  `GEONOSIS_PASSWORD_PEPPER=on`.
- Failed attempts: per-user counter persisted; brute force protection
  triggers temporary lockout (configurable per realm).

## Cookies & CSRF

- Cookies signed with the cookie session signing key (HMAC), prefixed
  with a key id for rotation.
- `Secure; HttpOnly; SameSite=Lax` by default; `SameSite=None`
  permitted per-realm only with operator opt-in.
- CSRF: separate cookie + form field for all POST handlers that
  change state. Double-submit pattern. Constant-time comparison.

## Secrets in the database

Secret-typed fields (LDAP bind password, IdP client secret, KMS
credentials, OAuth client secret hashes) are stored as ciphertext
wrapped under the master key. Domain types:

```rust
#[derive(Clone)]
pub struct Secret<T> { /* wraps T with Zeroize on drop */ }

impl Serialize/Deserialize for Secret<String> {
    // serializes as wrapped ciphertext via the master key context
}
```

Plaintext secret values never leave the encryption boundary on
disk or in logs. Tracing filters strip `Secret<_>` debug output.

## Client secrets

- **Stored hashed** (`Argon2id` with mild parameters) — even if a
  realm operator clones the DB, they can't recover the secrets in
  plaintext.
- **Rotation**: admin generates a new secret, the old one stays
  valid for a configurable grace period (default 24 h). Both hashes
  stored during the grace window.
- **Public clients**: no secret; rely on PKCE.

## Refresh token security

- Token is opaque random 32-byte string (Base64URL-encoded).
- Stored as a BLAKE3 keyed hash; never plaintext.
- **Family tracking**: each refresh issued at code exchange creates a
  `family_id`; each rotation links new → old. Replay of a used token
  invalidates the entire family.
- Default family TTL: 30 days idle, 90 days absolute.

## TLS

- TLS 1.2+ required; TLS 1.3 preferred.
- Geonosis terminates TLS only when run without an ingress (single-
  binary deploy). In K8s, the ingress controller does TLS.
- HSTS header default: `max-age=31536000; includeSubDomains`.

## Logging hygiene

- We never log: passwords, refresh tokens, access tokens, id tokens,
  client secrets, master key, JWE ciphertexts.
- We DO log: token JTI, session id (opaque), client id, user id,
  request id, error codes.
- `tracing-subscriber` filter scrubs `Secret<_>` debug.
- Audit log is separate from operational log; see
  [`13-observability.md`](./13-observability.md).

## Rate limiting & brute force

- Per-pod token-bucket per `(remote_ip, realm, action)` for
  `/authorize`, `/token`, `/userinfo`.
- Per-user counter for failed authn → temporary lock with backoff.
- Distributed rate-limit (cluster-wide) is a v0.2 feature requiring
  Redis or DB counter; v0.1 is per-pod which is adequate behind a
  single ingress.

## Cryptographic libraries

- **JWS/JWE**: `josekit` for now (vetted, full cover), with vendoring
  to lock the algorithm allowlist; consider migration to a smaller
  `rustcrypto`-built crate after audit.
- **Hashing**: `argon2`, `blake3`.
- **Symmetric**: `aes-gcm`.
- **Asymmetric**: `rsa`, `p256`, `p384`, `ed25519-dalek`.
- **Random**: `rand` with `OsRng`; we never use `thread_rng()` for
  secret material.
- **WebAuthn**: `webauthn-rs`.

All crypto is centralized in the `geonosis-crypto` crate. No other
crate calls these libraries directly; the surface is reviewed.

## Non-goals

- **Post-quantum** algorithms — track, do not adopt v0.1.
- **Bring-your-own-cipher** policy — no.
- **Storing plaintext client secrets** for compatibility — no.

## Decisions and open items

- **First external KMS backend**: HashiCorp Vault Transit, v0.2.
- **Master key**: raw 32-byte env only; derivation recipe documented
  separately as an operator runbook.
- **ACR policy**: per-realm policy table in v0.1 (default policy
  provided above; operators may extend).
