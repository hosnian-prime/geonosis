# geonosis-nextjs-example

Minimal Next.js 14 (App Router) app that signs users in through the
Geonosis OIDC provider via [Auth.js v5](https://authjs.dev/).

Companion to `docs/recipes/01-quickstart-docker.md`.

## What it demonstrates

- OIDC provider configured against the quickstart realm.
- PKCE-bound auth-code flow (Auth.js handles the code exchange).
- Session callback exposing the access token to the client.
- Server-side `auth()` check in a React Server Component.

## Setup

The quickstart compose stack must be running first
(`docker compose -f deploy/compose/quickstart.yml up -d`).

```sh
cd examples/nextjs-app
cp .env.example .env.local
# Edit .env.local — set AUTH_SECRET to a random string.

npm install
npm run dev
```

The app boots on `http://127.0.0.1:8888`. The redirect URI Auth.js
expects (`/api/auth/callback/geonosis`) must be added to the realm's
client. The quickstart `master-web` client is registered with
`http://127.0.0.1:8888/callback` — to use this example, also register
`http://127.0.0.1:8888/api/auth/callback/geonosis`:

```sh
geoctl clients update \
    --realm acme --client_id master-web \
    --redirect-uri http://127.0.0.1:8888/api/auth/callback/geonosis
```

(Note: a v0.1 limitation — `geoctl clients update` only ships in
v0.1.x; for now edit the redirect URI list via the admin UI at
`http://localhost:8080/admin-next/realms/master/clients`.)

## Trying it

1. Open `http://127.0.0.1:8888`.
2. Click "Sign in with Geonosis".
3. Sign in as `ada@master.test` / `ada-pw`.
4. The home page now shows your verified user claims and notes the
   `accessToken` is on `(session as any).accessToken`.
5. (Optional) Combine with the `axum-resource-server` example by
   copying the access token and hitting
   `curl -H "Authorization: Bearer …" http://localhost:7000/me`.

## Production checklist (things the example deliberately skips)

- **Refresh-token rotation.** Auth.js v5 supports it via a callback;
  add a `refresh_token` branch in the `jwt` callback to rotate.
- **CSRF-hardened sign-out.** Use Auth.js' built-in `signOut()`
  CSRF token on a real form, not the inline server action shown.
- **Strict TypeScript on the session type.** The example casts
  `session.accessToken` via `as any`; declare it on the
  `next-auth.d.ts` augmentation in real apps.
