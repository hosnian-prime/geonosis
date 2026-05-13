# 16 — Configure a production password policy

## What you'll have at the end

Realm `acme` enforces a password policy aligned with **NIST
800-63B** recommendations: minimum length, breach-list check, no
forced rotation, no arbitrary complexity rules.

## Prerequisites

- A running realm `acme`.

## Steps

1. **Set the password policy.**

   ```sh
   geoctl realm patch --realm acme --password-policy '{
     "rules": [
       {"MinLength": 8},
       {"MaxLength": 128},
       {"NotUsername": null},
       {"NotEmail": null},
       {"NoTopKCommon": 100000},
       {"HistoryDistinct": 3},
       {"Argon2idCost": {"memory_kib": 65536, "iterations": 3, "parallelism": 4}},
       {"HashAlgorithm": "Argon2id"}
     ]
   }'
   ```

   **What's here and why (NIST 800-63B):**

   | Rule | Rationale |
   |---|---|
   | `MinLength(8)` | NIST minimum; 12+ is better but 8 balances usability |
   | `MaxLength(128)` | Prevents DoS via huge inputs to Argon2id |
   | `NotUsername`, `NotEmail` | Obvious credential-stuffing targets |
   | `NoTopKCommon(100000)` | Checks against top 100K breached passwords (HaveIBeenPwned k-anonymity API). This is the single highest-ROI rule |
   | `HistoryDistinct(3)` | Prevents cycling back to recent passwords |
   | `Argon2idCost` | 64 MiB memory, 3 iterations, 4 threads — ~300 ms on a 4-core pod. Tuned to resist GPU/ASIC attacks while keeping login latency acceptable |

   **What's deliberately absent (and why):**

   | Omitted rule | Why |
   |---|---|
   | `MinDigits`, `MinSpecialChars`, `MinUpperCase` | NIST 800-63B §5.1.1.2 explicitly discourages composition rules — they reduce entropy by making passwords predictable ("Password1!") and frustrate users |
   | `MaxAge` (forced rotation) | NIST 800-63B §5.1.1.2: "Verifiers SHOULD NOT require memorized secrets to be changed arbitrarily." Rotation encourages weak incremental passwords |
   | `RegexMatch` | Same concern as composition rules; use sparingly and only for compliance mandates you can't avoid |

2. **(Optional) Add the HaveIBeenPwned online check.**

   The `NoTopKCommon` rule checks against a bundled static list.
   For real-time breach detection, enable the HIBP k-anonymity
   lookup:

   ```sh
   geoctl realm patch --realm acme --password-policy-add \
     '{"PasswordBlacklist": {"source": "HaveIBeenPwned"}}'
   ```

   This sends only the first 5 characters of the SHA-1 hash to
   the HIBP API (k-anonymity) — the full password never leaves
   the server.

3. **Tune Argon2id for your hardware.**

   The default `memory_kib: 65536` (64 MiB) assumes 4+ GiB pods.
   If you're running smaller:

   ```sh
   # For 2 GiB pods (e.g. edge deployment):
   geoctl realm patch --realm acme --password-policy-update \
     '{"Argon2idCost": {"memory_kib": 32768, "iterations": 4, "parallelism": 2}}'
   ```

   Rule of thumb: Argon2id should take 200–500 ms per hash on
   your target hardware. Measure with:

   ```sh
   geoctl bench argon2id --memory 65536 --iterations 3 --parallelism 4
   ```

## Verifying

```sh
# Try a weak password:
geoctl users credential-set --realm acme --user ada --kind password --value "password"
# → error: password matches breached password list

# Try the user's own username:
geoctl users credential-set --realm acme --user ada --kind password --value "ada"
# → error: password must not match username

# Set a strong password:
geoctl users credential-set --realm acme --user ada --kind password --value "correct-horse-battery-staple"
# → success (if not in breach list)
```

## Upgrading existing password hashes

When you change `Argon2idCost`, existing users keep their old
hash parameters. On next successful login, Geonosis **rehashes
transparently** with the new parameters and updates the
`credential` row. No migration job needed.

## Troubleshooting

- **Login takes > 1s** — Argon2id memory too high for your pod
  size, causing swap. Reduce `memory_kib` or increase pod memory.
- **HIBP check adds latency** — the API call adds ~100 ms. It
  runs only on password set/change, not on every login (login
  verifies the stored hash).
- **Users complaining about "password in breach list"** — this is
  working as intended. Educate users that their password appeared
  in a public data breach. Suggest a passphrase.

## See also

- [`02-data-model.md`](../02-data-model.md) — `PasswordPolicy`,
  `PasswordRule` enum.
- [`12-security-crypto.md`](../12-security-crypto.md) — Argon2id
  parameters, password pepper.
