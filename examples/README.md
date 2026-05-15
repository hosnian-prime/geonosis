# Example apps

Per `docs/21-dx-package.md` §"Framework example apps" the v0.1
release ships two minimal, cargo-cult-able integration examples that
boot against the quickstart compose stack (`deploy/compose/quickstart.yml`):

| Directory | Stack | What it shows |
|---|---|---|
| `axum-resource-server/` | Rust + axum + jsonwebtoken | Resource server that verifies Geonosis-issued access tokens against the realm's JWKS. |
| `nextjs-app/` | Next.js 14 (App Router) + Auth.js v5 | OIDC client that signs users in via the Geonosis provider and exposes the access token to the React tree. |

Both examples target the quickstart realm (`acme`) with user
`ada@master.test` / `ada-pw` and OIDC client `master-web`. Each has its
own README with exact run commands.

The two examples chain end-to-end: sign in via Next.js, copy the
access token from the session, hit the axum server with it as
`Authorization: Bearer …`, get the verified subject claims back.

Each `Cargo.toml` / `package.json` is intentionally standalone (not
in the workspace) so a developer following the recipe doesn't pull
the entire server tree.
