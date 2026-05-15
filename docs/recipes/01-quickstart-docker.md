# 01 — Run the quickstart with Docker

## What you'll have at the end

A locally running Geonosis at `http://localhost:8080`, a sample
realm with one user and one OIDC client, and an access token in
hand — all in under 5 minutes.

## Prerequisites

- Docker + Docker Compose (≥ v2).
- `curl` and `jq`.

## Steps

1. **Pull the quickstart compose file.**

   ```sh
   curl -fsSL https://raw.githubusercontent.com/hosnian-prime/geonosis/hive/deploy/compose/quickstart.yml -o compose.yml
   ```

2. **Start the stack.**

   ```sh
   docker compose up -d
   ```

   The compose file starts:
   - `postgres:16` on port 5432 (data lost on `docker compose down -v`)
   - `geonosis-server` on port 8080 with
     `GEONOSIS_BOOTSTRAP_QUICKSTART=1` set

   The bootstrap step creates:
   - Realm `master` with default flows + ACR policy.
   - Admin user `admin@master.test` / `admin-pw`.
   - End-user `ada@master.test` / `ada-pw`.
   - Public client `master-web` with redirect URI
     `http://127.0.0.1:8888/callback`.

3. **Verify the discovery endpoint.**

   ```sh
   curl -fsS http://localhost:8080/realms/master/.well-known/openid-configuration | jq .issuer
   ```

   Expected: `"http://localhost:8080/realms/master"`.

4. **Run a one-shot auth code grant.**

   The quickstart ships a tiny helper:

   ```sh
   docker run --rm --network host \
     ghcr.io/hosnian-prime/geonosis-quickstart-helper:latest \
     login --user ada@master.test --pw ada-pw --realm master --client master-web
   ```

   The helper drives the browser flow programmatically and prints
   the issued `access_token` and `id_token` to stdout.

5. **Decode the id token.**

   ```sh
   echo "$ID_TOKEN" | cut -d. -f2 | base64 -d | jq
   ```

   Expected claims include `iss`, `sub`, `aud=master-web`, and
   `preferred_username=ada`.

## Verifying

```sh
curl -fsS -H "Authorization: Bearer $ACCESS_TOKEN" \
  http://localhost:8080/realms/master/protocol/openid-connect/userinfo | jq
```

Returns `{"sub":"...","email":"ada@master.test","email_verified":true}`.

## Troubleshooting

- **Port 8080 already in use** — override with
  `GEONOSIS_PUBLIC_PORT=18080 docker compose up -d` and re-run all
  commands with `:18080`.
- **`bootstrap quickstart not allowed in production`** — happens if
  you re-use this image in a non-quickstart deploy. Quickstart needs
  `GEONOSIS_BOOTSTRAP_QUICKSTART=1`; production Helm charts never
  set this flag (see [`11-deployment-k8s.md`](../11-deployment-k8s.md)).
- **`unverified email blocks login`** — the bootstrap pre-verifies
  user emails. If yours doesn't, run `geoctl users verify-email
  --realm master --user ada@master.test`.

## See also

- [`docs/21-dx-package.md`](../21-dx-package.md) — DX package
  scope.
- [`docs/03-protocols-oidc.md`](../03-protocols-oidc.md) — the
  endpoints the helper hits.

## Cleanup

```sh
docker compose down -v
```

Wipes the Postgres volume and bootstrap state.
