# Recipes

Task-oriented how-to documents. Each recipe is **≤ 500 words**,
focused on a single operator goal, and uses real commands — no
pseudocode.

These are *companions* to the architecture docs in `docs/`. When a
recipe touches a design decision, it links back to the canonical
architecture doc rather than re-explaining it.

## v0.1 set (20 recipes)

| # | Recipe | What you'll do |
|---|---|---|
| 01 | [Run the quickstart with Docker](./01-quickstart-docker.md) | Boot Geonosis locally in under 5 minutes; get your first token |
| 02 | [Add a custom claim to client tokens](./02-add-custom-claim.md) | Bind a mapper so every token issued for a client carries `department` |
| 03 | [Configure step-up MFA](./03-step-up-mfa.md) | Make sensitive endpoints request a higher `acr_values` and re-authenticate |
| 04 | [Write a custom authenticator in Rust](./04-custom-authenticator-rust.md) | Build a WASM SPI module against `geonosis:authn@0.1.0` and install it |
| 05 | [Federate users from a REST-backed user store](./05-rest-user-storage.md) | Replace the built-in local store with a WASM `geonosis:user-storage` provider |
| 06 | [Rotate signing keys without breaking tokens in flight](./06-rotate-signing-keys.md) | Add a fresh key, promote it, retire the old one |
| 07 | [Deploy Geonosis behind nginx / Caddy / Traefik](./07-deploy-behind-ingress.md) | Production ingress + TLS termination + `frontend_url` |
| 08 | [Issue an OAuth token for an AI agent](./08-issue-agent-token.md) | Token Exchange (RFC 8693) with the `act` chain |
| 09 | [Set up a B2B Organization and invite members](./09-organization-setup.md) | Org, domain claim, IdP binding, invitation lifecycle |
| 10 | [Expose Geonosis as a SAML IdP to a SaaS app](./10-saml-idp-for-app.md) | Register the SP, download metadata, complete SSO |
| 11 | [Federate users from LDAP / Active Directory](./11-ldap-ad-federation.md) | Connect to corporate AD with LDAPS, sync users, map attributes |
| 12 | [Add social login (Google / GitHub)](./12-social-login-google-github.md) | Broker through external IdPs with first-party adapter plugins |
| 13 | [Configure TOTP enrollment and MFA policy](./13-totp-otp-enrollment.md) | Require TOTP on first login, generate recovery codes |
| 14 | [Configure consent management (system + org-level)](./14-consent-management.md) | Per-client consent screens, org-level pre-approval and blocking |
| 15 | [Configure organization roles and permissions](./15-org-roles-permissions.md) | Custom org roles with fine-grained permissions (billing, team-lead, etc.) |
| 16 | [Configure a production password policy](./16-password-policy.md) | NIST 800-63B aligned policy: breach-list check, Argon2id tuning |
| 17 | [Customize the login theme](./17-theme-customization.md) | Brand colors, logo, template overrides with hot reload |
| 18 | [Export and import a realm configuration](./18-realm-export-import.md) | YAML export for version control and environment promotion |
| 19 | [Stream events to a webhook endpoint](./19-webhook-event-sink.md) | HMAC-signed event delivery with retry and filtering |
| 20 | [Write a custom token mapper in WASM](./20-custom-mapper-wasm.md) | Compute cross-entity claims (org + user) at token mint |

## v0.2 set (planned, not yet written)

| Recipe | Phase |
|---|---|
| Provision users from Entra ID via SCIM | v0.2 — needs SCIM 2.0 |
| Write a custom authenticator in Go (TinyGo) | v0.2 — needs Go SDK |
| Write a custom mapper in JS (ComponentizeJS) | v0.2 — needs JS SDK |
| Self-enrol a passkey from the account console | v0.2 — needs passkey lifecycle |
| Stream audit events into Splunk / Datadog | v0.2 — needs cloud sinks |

These are tracked in [`14-roadmap.md`](../14-roadmap.md) and will be
written when their dependencies ship.

## Format conventions

Each recipe follows the same skeleton:

```
# NN — Recipe title

## What you'll have at the end
One-sentence success criterion.

## Prerequisites
What state you're starting from (a working Geonosis, admin token, ...).

## Steps
1. ...
2. ...
3. ...

## Verifying
A cURL / geoctl command + the expected response.

## Troubleshooting
The 2–3 most likely failure modes.

## See also
Architecture-doc links.
```

When a recipe needs a sample app, it lives under `../../examples/`
and the recipe references it by path.
