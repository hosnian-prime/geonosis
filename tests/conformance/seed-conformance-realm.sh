#!/usr/bin/env bash
# Seed a conformance test realm + client for the OIDC Basic RP test suite.
# Usage: seed-conformance-realm.sh <base-url>
set -euo pipefail

BASE="${1:?usage: seed-conformance-realm.sh <base-url>}"
ADMIN="${BASE}/admin/v1"
KEY="${GEONOSIS_ADMIN_API_KEY:?GEONOSIS_ADMIN_API_KEY must be set}"

AUTH_HEADER="X-Admin-Key: ${KEY}"

# Create conformance realm.
curl -sf -X POST "${ADMIN}/realms" \
  -H 'Content-Type: application/json' \
  -H "${AUTH_HEADER}" \
  -d '{
    "slug": "conformance",
    "display_name": "OIDC Conformance",
    "enabled": true
  }' > /dev/null

# Create a public client matching the RP test callback URL.
curl -sf -X POST "${ADMIN}/realms/conformance/clients" \
  -H 'Content-Type: application/json' \
  -H "${AUTH_HEADER}" \
  -d '{
    "client_id": "oidc-conformance-rp",
    "kind": "public",
    "auth_method": "none",
    "redirect_uris": [
      "https://www.certification.openid.net/test/a/geonosis/callback",
      "http://localhost:8443/test/a/geonosis/callback"
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

# Create a test user.
curl -sf -X POST "${ADMIN}/realms/conformance/users" \
  -H 'Content-Type: application/json' \
  -H "${AUTH_HEADER}" \
  -d '{
    "username": "testuser",
    "email": "testuser@conformance.local",
    "email_verified": true,
    "enabled": true
  }' > /dev/null

# Set the test user password.
curl -sf -X PUT "${ADMIN}/realms/conformance/users/testuser/password" \
  -H 'Content-Type: application/json' \
  -H "${AUTH_HEADER}" \
  -d '{"password": "ConformanceTest123!"}' > /dev/null

echo "conformance realm seeded"
