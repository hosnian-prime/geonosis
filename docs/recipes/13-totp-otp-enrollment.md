# 13 — Configure TOTP enrollment and MFA policy

## What you'll have at the end

New users in realm `master` are required to enroll a TOTP
authenticator on their first login. The realm's OTP policy uses
SHA-1 / 6 digits / 30-second period for maximum app compatibility,
with recovery codes as a fallback.

## Prerequisites

- A running realm `master`.
- Users with email verified (for recovery-code delivery).

## Steps

1. **Set the realm OTP policy.**

   ```sh
   geoctl realm patch --realm master --otp-policy '{
     "mode": "Totp",
     "algorithm": "SHA1",
     "digits": 6,
     "period_seconds": 30,
     "initial_counter": 0,
     "look_ahead_window": 1,
     "reusable_codes": false,
     "supported_apps": ["Google Authenticator", "Authy", "1Password", "Bitwarden"]
   }'
   ```

   **Why SHA-1?** SHA-256/512 are more secure in theory, but
   Google Authenticator (the most common app) only supports SHA-1
   reliably. The 30-second window with `look_ahead_window: 1`
   tolerates ±30 seconds of clock drift — sufficient for mobile
   devices with NTP.

2. **Add `ConfigureOtp` as a required action for new users.**

   ```sh
   geoctl realm patch --realm master --registration-policy '{
     "required_actions": ["VerifyEmail", "ConfigureOtp"]
   }'
   ```

   Existing users can be forced individually:

   ```sh
   geoctl users patch --realm master --user ada \
     --required-actions '["ConfigureOtp"]'
   ```

3. **Ensure the browser flow includes the OTP step.**

   The default `browser` flow already has an `otp` authenticator
   node gated by a `Switch` that checks `user.credentials contains
   otp`. Verify:

   ```sh
   geoctl flows get --realm master --alias browser | grep -A2 'otp'
   ```

   If your flow is custom, insert an `otp` authenticator node
   after the `password` node.

4. **Generate recovery codes (recommended).**

   Recovery codes are a fallback when the user loses their TOTP
   device. The default flow includes a `recovery-code`
   authenticator after `otp` in the `Switch` node.

   ```sh
   geoctl realm patch --realm master --registration-policy '{
     "required_actions": ["VerifyEmail", "ConfigureOtp"]
   }'
   ```

   When the user first enrolls OTP, the flow generates 10
   single-use recovery codes (8 characters each) and displays
   them once. The codes are hashed with BLAKE3 before storage.

## Verifying

```sh
# Login as ada — the flow will require OTP enrollment:
docker run --rm --network host \
  ghcr.io/hosnian-prime/geonosis-quickstart-helper \
  login --realm master --user ada --pw ada-pw
```

The helper will display a `otpauth://` URI (and QR code in
supported terminals). After scanning with an authenticator app and
submitting the 6-digit code:

```sh
geoctl users get --realm master --user ada | jq '.credentials[] | select(.kind=="otp")'
```

Shows the credential entry (secret is never exposed — only
metadata).

Subsequent logins require the TOTP code after password.

## Enforcing MFA realm-wide (for existing users)

```sh
geoctl users required-action-add \
  --realm master \
  --filter '{"credentials_missing":"otp"}' \
  --action ConfigureOtp
```

This batch command adds the required action only to users who
don't already have OTP enrolled.

## Troubleshooting

- **Code always rejected** — clock drift beyond ±30 s. The user's
  device may not have NTP synced. Increase `look_ahead_window` to
  2 (tolerates ±60 s) as a temporary measure.
- **QR code not scanning** — some apps reject `otpauth://` URIs
  with special characters in the issuer name. Keep
  `Realm.display_name` simple (alphanumeric + spaces).
- **Recovery code rejected** — codes are single-use and
  case-insensitive. The user may have already used it.
  `geoctl users credential-list --realm master --user ada --kind
  recovery` shows remaining codes.
- **User locked out (no device, no recovery codes)** — admin
  resets: `geoctl users credential-remove --realm master --user ada
  --kind otp` and re-adds `ConfigureOtp` required action.

## See also

- [`02-data-model.md`](../02-data-model.md) — `OtpPolicy`,
  `CredentialKind::Totp`.
- [`06-auth-flows.md`](../06-auth-flows.md) — Built-in `otp` and
  `recovery-code` authenticators.
- [Recipe 03 — Step-up MFA](./03-step-up-mfa.md) — Making MFA
  conditional on `acr_values`.
