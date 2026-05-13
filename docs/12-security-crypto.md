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
  family.

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

- `SoftwareKms` (default): local AES-GCM envelope.
- `VaultTransit` (v0.2): HashiCorp Vault Transit engine.
- `AwsKmsBackend` (v0.2): AWS KMS asymmetric keys.
- `GcpKmsBackend` (v0.2): Google Cloud KMS asymmetric keys.
- `Pkcs11Backend` (v0.3): generic HSMs via PKCS#11.

Hot path performance: software signing is ~50 µs; KMS-backed signing
is ~5 ms (network) — the server caches verification public keys
locally so verification is always fast, signing-only takes the hit.

## Master key management

- **Provisioning**: operator generates a 32-byte random and stores in
  K8s Secret / external secret store. Geonosis does NOT generate the
  master key itself on first boot (avoid surprise key creation).
- **Rotation**: a `geoctl secrets rewrap --new-key <path>` command
  reads every wrapped secret in the DB, decrypts with the old master,
  re-encrypts with the new, swaps in a transaction. Runtime supports
  reading either-old-or-new during a transition window
  (`MASTER_KEY_PRIMARY` + `MASTER_KEY_SECONDARY` env vars).
- **Backup**: master key is the encryption boundary for the DB. Lose
  it, lose all stored signing keys. Operator runbook MUST cover this.

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

## Open

- **HSM/KMS backends**: which one ships in v0.2 first? Vault Transit
  is leading because it's commonly available and supports the asym
  algorithms we use.
- **Master key derivation** from a passphrase — operationally nice
  but reduces strength; default to raw bytes, document derivation
  recipe.
- **`acr_values` mapping** to authn strength — needs a small policy
  table in v0.2.
