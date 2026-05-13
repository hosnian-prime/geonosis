# 19 — Stream events to a webhook endpoint

## What you'll have at the end

Realm `acme` pushes login events and admin events to your webhook
endpoint in real time, with HMAC signature verification and
retry-on-failure.

## Prerequisites

- A running realm `acme`.
- An HTTPS endpoint that accepts POST requests (your SIEM, Slack
  webhook, custom handler, etc.).

## Steps

1. **Create the webhook secret.**

   ```sh
   geoctl secrets put --realm acme \
     --name WEBHOOK_HMAC_SECRET \
     --value "$(openssl rand -base64 32)"
   ```

   This secret is used to HMAC-sign every webhook payload so your
   receiver can verify authenticity (like GitHub's
   `X-Hub-Signature-256`).

2. **Register the event sink.**

   ```sh
   geoctl event-sinks create \
     --realm acme \
     --alias security-siem \
     --kind webhook \
     --config '{
       "url": "https://siem.internal.acme.com/geonosis/events",
       "hmac_secret_ref": "WEBHOOK_HMAC_SECRET",
       "hmac_algorithm": "sha256",
       "timeout_ms": 5000,
       "retry_policy": {
         "max_retries": 5,
         "initial_backoff_ms": 1000,
         "max_backoff_ms": 30000,
         "backoff_multiplier": 2
       }
     }' \
     --events-filter '["login.success", "login.failure", "token.reuse_detected",
       "user.created", "user.deleted",
       "agent.token.issued", "agent.revoked",
       "consent.granted", "consent.revoked",
       "key.rotated", "key.disabled",
       "admin.realm_settings_changed"]' \
     --enabled true
   ```

   **Key decisions:**

   - **Filter events** — subscribing to all events creates noise.
     Start with security-relevant events; expand as needed.
   - **HMAC verification** — every payload includes an
     `X-Geonosis-Signature-256` header. Your receiver MUST
     verify it (constant-time comparison).
   - **Retry with exponential backoff** — failed deliveries retry
     up to 5 times (1s → 2s → 4s → 8s → 16s). After 5 failures,
     the event is logged to the audit table with
     `sink.delivery_failed`.
   - **Timeout 5s** — webhook dispatch is **async** and never
     blocks the auth flow. The event is queued in-process and
     delivered in a background task.

3. **Verify your receiver handles the payload.**

   Payload shape:

   ```json
   {
     "id": "01HK...",
     "realm_id": "01HK...",
     "occurred_at": "2025-01-08T10:21:34.521Z",
     "action": "login.success",
     "actor": {
       "kind": "user",
       "id": "01HU...",
       "ip": "203.0.113.42"
     },
     "target": {
       "kind": "session",
       "id": "01HS..."
     },
     "detail": {
       "client_id": "acme-web",
       "amr": ["pwd", "otp"],
       "acr": "2"
     }
   }
   ```

   Signature verification (Python example):

   ```python
   import hmac, hashlib

   def verify(payload: bytes, signature: str, secret: str) -> bool:
       expected = hmac.new(
           secret.encode(), payload, hashlib.sha256
       ).hexdigest()
       return hmac.compare_digest(f"sha256={expected}", signature)
   ```

## Verifying

```sh
# Trigger a login:
docker run --rm --network host \
  ghcr.io/hosnian-prime/geonosis-quickstart-helper \
  login --realm acme --user ada --pw ada-pw

# Check delivery status:
geoctl event-sinks status --realm acme --alias security-siem
```

Shows `last_delivery: success`, `events_delivered: N`,
`events_failed: 0`.

## Multiple sinks

A realm can have multiple event sinks. Each is independent:

```sh
# Slack for admin events only:
geoctl event-sinks create \
  --realm acme \
  --alias slack-admin \
  --kind webhook \
  --config '{"url": "https://hooks.slack.com/services/T.../B.../xxx"}' \
  --events-filter '["admin.realm_settings_changed", "user.deleted", "key.rotated"]'
```

## Troubleshooting

- **Events not arriving** — check `geoctl event-sinks status`.
  If `last_error` shows `timeout`, increase `timeout_ms` or
  check your endpoint's response time.
- **Signature mismatch** — ensure your receiver reads the
  **raw body bytes** before parsing JSON. Parsing and
  re-serializing changes whitespace and breaks the HMAC.
- **Duplicate events** — retries can cause duplicates. Use the
  event `id` (ULID) for idempotency on your receiver side.
- **High volume** — for high-traffic realms, filter to only
  critical events. Kafka sinks (v0.2) are better for bulk
  streaming.

## See also

- [`13-observability.md`](../13-observability.md) — Audit event
  schema, event types, retention.
- [`02-data-model.md`](../02-data-model.md) — `EventSink`,
  `EventSinkKind`, `EventConfig`.
