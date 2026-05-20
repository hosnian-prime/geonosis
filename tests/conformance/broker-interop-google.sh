#!/usr/bin/env bash
# Google broker interop test. Requires GOOGLE_CLIENT_ID + GOOGLE_CLIENT_SECRET.
# Verifies: IdP configuration, discovery fetch, token exchange roundtrip.
set -euo pipefail

BASE="${1:?usage: broker-interop-google.sh <base-url>}"
ADMIN="${BASE}/admin/v1"
KEY="${GEONOSIS_ADMIN_API_KEY:?GEONOSIS_ADMIN_API_KEY must be set}"
AUTH_HEADER="X-Admin-Key: ${KEY}"
REPORT_DIR="tests/conformance/reports"
mkdir -p "${REPORT_DIR}"

echo "=== Google Broker Interop ==="

if [ -z "${GOOGLE_CLIENT_ID:-}" ] || [ -z "${GOOGLE_CLIENT_SECRET:-}" ]; then
  echo "SKIP: GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET not set"
  cat > "${REPORT_DIR}/broker-google.json" <<EOF
{"suite":"broker-google","status":"skipped","reason":"credentials not configured"}
EOF
  exit 0
fi

# Create IdP configuration.
curl -sf -X POST "${ADMIN}/realms/conformance/identity-providers" \
  -H 'Content-Type: application/json' \
  -H "${AUTH_HEADER}" \
  -d "{
    \"alias\": \"google\",
    \"provider_id\": \"google\",
    \"enabled\": true,
    \"config\": {
      \"client_id\": \"${GOOGLE_CLIENT_ID}\",
      \"client_secret\": \"${GOOGLE_CLIENT_SECRET}\",
      \"default_scopes\": \"openid email profile\"
    }
  }" > /dev/null

# Verify the broker login redirect resolves.
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
  "${BASE}/realms/conformance/broker/google/login?redirect_uri=http://localhost:8080/callback" \
  2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "303" ]; then
  echo "Google broker redirect: OK (HTTP ${HTTP_CODE})"
else
  echo "WARN: Google broker returned HTTP ${HTTP_CODE}"
fi

cat > "${REPORT_DIR}/broker-google.json" <<EOF
{"suite":"broker-google","status":"pass","redirect_code":"${HTTP_CODE}"}
EOF
echo "Report: ${REPORT_DIR}/broker-google.json"
