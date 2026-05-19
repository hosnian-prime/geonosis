# Security Policy

Geonosis is an enterprise-grade IAM server implementing OIDC 1.0 and OAuth 2.1. Because it handles authentication, authorization, cryptographic key material, and identity federation, we treat every security report with the highest priority.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | Yes                |
| < 0.1.0 | No                 |

Only the latest patch release within a supported minor version receives security fixes. We recommend always running the most recent release.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report vulnerabilities by email to:

```
security@hosnian-prime.com
```

If you need to communicate sensitive details, a PGP key is available on request. Send a plaintext email to the address above asking for the public key, and we will provide it promptly.

### What to Include

A good vulnerability report helps us triage and fix the issue faster. Please include as much of the following as possible:

- **Summary** -- A clear, concise description of the vulnerability.
- **Affected component** -- Which crate, module, endpoint, or protocol flow is affected (e.g., `geonosis-server`, token endpoint, SAML response parsing).
- **Reproduction steps** -- A minimal, step-by-step guide to trigger the issue. Include configuration snippets, HTTP requests, or code samples where applicable.
- **Impact assessment** -- Your understanding of the severity and what an attacker could achieve (e.g., authentication bypass, key disclosure, denial of service).
- **Environment** -- Geonosis version, operating system, Rust toolchain version, and any relevant deployment details (reverse proxy, database backend, federation provider).
- **Suggested fix** (optional) -- If you have a proposed patch or mitigation, we welcome it.

### What NOT to Do

- **Do not open public issues, pull requests, or discussions** that disclose security vulnerabilities.
- **Do not exploit vulnerabilities** beyond what is necessary to demonstrate the issue. Do not access, modify, or delete data belonging to other users or systems.
- **Do not perform denial-of-service attacks** against running instances.
- **Do not disclose the vulnerability to third parties** before it has been resolved and a coordinated disclosure timeline has been agreed upon.

## Response Timeline

We commit to the following response targets:

| Stage                  | Target                  |
| ---------------------- | ----------------------- |
| Acknowledgement        | Within 48 hours         |
| Initial triage         | Within 7 days           |
| Fix for critical issues | Within 90 days         |
| Fix for lower severity | Best effort, typically within 90 days |

If we determine the report is valid, we will keep you informed of our progress toward a fix. If we need additional information, we will reach out via the email address you used to report the issue.

## Disclosure Policy

We follow a **coordinated disclosure** model:

1. The reporter submits the vulnerability privately.
2. We acknowledge receipt and begin triage.
3. We develop and test a fix.
4. We release the fix and publish a security advisory on GitHub.
5. The reporter is free to publish their findings after the advisory is public.

If we are unable to meet the 90-day fix target, we will discuss an adjusted timeline with the reporter before any public disclosure.

### Credit

We credit reporters in the security advisory and CHANGELOG unless they prefer to remain anonymous. Please let us know your preference when you submit your report.

## Security Scope

### In Scope

The following components are covered by this security policy:

- **geonosis-server** -- The core IAM server, including all protocol endpoints (OAuth 2.1, OIDC 1.0).
- **geonosis-cache** -- Caching layer (local and Redis-backed).
- **geonosis-cli** -- The command-line administration tool.
- **Cryptographic operations** -- JWT signing and verification (RS256, ES256, EdDSA), password hashing (Argon2id), AES-GCM encryption, key management.
- **Protocol implementations** -- OAuth 2.1 grant flows, OIDC discovery, SAML federation, LDAP integration, OIDC brokering, JAR (JWT-Secured Authorization Requests).
- **Session and token management** -- Session lifecycle, token issuance, refresh token rotation, revocation.
- **Rate limiting and access control** -- Server-side rate limiting, RBAC enforcement.

### Out of Scope

The following are not covered by this policy:

- Example configurations and sample code in the `examples/` directory.
- Documentation and markdown files.
- CI/CD pipeline configurations.
- Third-party dependencies (please report these to the upstream maintainer, though we appreciate a heads-up if a dependency vulnerability affects Geonosis directly).
- Social engineering attacks against maintainers or infrastructure.

## Security Design Notes

For context, Geonosis enforces the following security properties at the code level:

- **Zero unsafe code** -- The `unsafe_code = "forbid"` lint is set project-wide.
- **Memory-safe language** -- The entire server is written in Rust with no FFI escape hatches.
- **Modern cryptographic defaults** -- Argon2id for password hashing, AES-GCM for encryption at rest, and only current-generation JWT algorithms (RS256, ES256, EdDSA).

## Contact

For security reports: `security@hosnian-prime.com`

For general questions and non-security bugs: open an issue on the GitHub repository.
