#!/usr/bin/env bash
# Seed a FAPI 1 Baseline conformance realm with a confidential client.
# FAPI requires: confidential client, PKCE S256, signed id_token (RS256/ES256).
set -euo pipefail

BASE="${1:?usage: seed-fapi-realm.sh <base-url>}"
ADMIN="${BASE}/admin/v1"

curl -sf -X POST "${ADMIN}/realms" \
  -H 'Content-Type: application/json' \
  -d '{
    "slug": "fapi",
    "display_name": "FAPI Baseline",
    "enabled": true
  }' > /dev/null

curl -sf -X POST "${ADMIN}/realms/fapi/clients" \
  -H 'Content-Type: application/json' \
  -d '{
    "client_id": "fapi-conformance-client",
    "kind": "confidential",
    "auth_method": "client_secret_basic",
    "redirect_uris": [
      "https://www.certification.openid.net/test/a/geonosis-fapi/callback",
      "http://localhost:8443/test/a/geonosis-fapi/callback"
    ],
    "grants": {
      "authorization_code": true,
      "refresh_token": true,
      "client_credentials": false,
      "device_code": false,
      "password": false
    },
    "default_scopes": ["openid", "profile", "email"],
    "enabled": true
  }' > /dev/null

curl -sf -X POST "${ADMIN}/realms/fapi/users" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "fapiuser",
    "email": "fapiuser@fapi.local",
    "email_verified": true,
    "enabled": true
  }' > /dev/null

# Set the test user password.
curl -sf -X PUT "${ADMIN}/realms/fapi/users/fapiuser/password" \
  -H 'Content-Type: application/json' \
  -d '{"password": "FapiTest123!"}' > /dev/null

echo "fapi realm seeded"
