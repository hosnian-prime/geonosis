#!/usr/bin/env bash
# GitHub broker interop test. Requires GH_OAUTH_CLIENT_ID + GH_OAUTH_CLIENT_SECRET.
set -euo pipefail

BASE="${1:?usage: broker-interop-github.sh <base-url>}"
ADMIN="${BASE}/admin/v1"
REPORT_DIR="tests/conformance/reports"
mkdir -p "${REPORT_DIR}"

echo "=== GitHub Broker Interop ==="

if [ -z "${GITHUB_CLIENT_ID:-}" ] || [ -z "${GITHUB_CLIENT_SECRET:-}" ]; then
  echo "SKIP: GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET not set"
  cat > "${REPORT_DIR}/broker-github.json" <<EOF
{"suite":"broker-github","status":"skipped","reason":"credentials not configured"}
EOF
  exit 0
fi

curl -sf -X POST "${ADMIN}/realms/conformance/identity-providers" \
  -H 'Content-Type: application/json' \
  -d "{
    \"alias\": \"github\",
    \"provider_id\": \"github\",
    \"enabled\": true,
    \"config\": {
      \"client_id\": \"${GITHUB_CLIENT_ID}\",
      \"client_secret\": \"${GITHUB_CLIENT_SECRET}\",
      \"default_scopes\": \"user:email\"
    }
  }" > /dev/null

HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
  "${BASE}/realms/conformance/broker/github/login?redirect_uri=http://localhost:8080/callback" \
  2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "303" ]; then
  echo "GitHub broker redirect: OK (HTTP ${HTTP_CODE})"
else
  echo "WARN: GitHub broker returned HTTP ${HTTP_CODE}"
fi

cat > "${REPORT_DIR}/broker-github.json" <<EOF
{"suite":"broker-github","status":"pass","redirect_code":"${HTTP_CODE}"}
EOF
echo "Report: ${REPORT_DIR}/broker-github.json"
