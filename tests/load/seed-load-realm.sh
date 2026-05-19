#!/usr/bin/env bash
# Seed a realm + client + user for load testing.
set -euo pipefail

BASE="${1:?usage: seed-load-realm.sh <base-url>}"
ADMIN="${BASE}/admin/v1"

curl -sf -X POST "${ADMIN}/realms" \
  -H 'Content-Type: application/json' \
  -d '{"slug":"loadtest","display_name":"Load Test","enabled":true}' > /dev/null

curl -sf -X POST "${ADMIN}/realms/loadtest/clients" \
  -H 'Content-Type: application/json' \
  -d '{
    "client_id": "load-test",
    "kind": "public",
    "auth_method": "none",
    "redirect_uris": ["http://localhost:9999/cb"],
    "grants": {"authorization_code":true,"refresh_token":false,"client_credentials":false,"device_code":false,"password":false},
    "default_scopes": ["openid"],
    "enabled": true
  }' > /dev/null

curl -sf -X POST "${ADMIN}/realms/loadtest/users" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "loaduser",
    "email": "load@test.local",
    "email_verified": true,
    "enabled": true,
    "password": "LoadTest123!"
  }' > /dev/null

echo "load test realm seeded"
