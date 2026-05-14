//! Twilio SMS event listener — Geonosis WASM plugin.
//!
//! Subscribes to the `geonosis:event@0.1.0` interface and acts on
//! events whose `action` matches the configured filter (default
//! `sms.send`). When matched, sends an SMS via Twilio's
//! `/2010-04-01/Accounts/{sid}/Messages.json` endpoint using the host's
//! `http-client` capability + secrets loaded from the host's
//! `secrets` capability.
//!
//! Per `docs/06-auth-flows.md` §"phone-otp": the phone-otp built-in
//! authenticator emits an audit event of shape `{ action: "sms.send",
//! detail: { to, body } }` whenever it issues an OTP. This plugin
//! turns that event into a real SMS without coupling the
//! authenticator to a specific SMS provider.
//!
//! Wire shape — `event-bytes` is a bincode-encoded `AuditEvent`. v0.1
//! takes the practical shortcut of looking only at the JSON-rendered
//! detail (operators tail audit logs anyway) instead of decoding the
//! Rust struct. v0.2 will publish a stable `EventWire` schema and
//! the plugin will deserialize directly.

#![no_main]

wit_bindgen::generate!({
    world: "event-listener-provider",
    path: "../../wit",
});

use exports::geonosis::event::event_listener::{Guest, PluginError, ProviderInfo};
use geonosis::host::http_client;
use geonosis::host::logging;
use geonosis::host::secrets;

struct SpiTwilio;

impl Guest for SpiTwilio {
    fn describe() -> ProviderInfo {
        ProviderInfo {
            urn: "wasm:spi-twilio:event@0.1.0".into(),
            display_name: "Twilio SMS event listener".into(),
            version: "0.1.0".into(),
        }
    }

    fn on_event(event_bytes: Vec<u8>) -> Result<(), PluginError> {
        // Decode the event detail. v0.1 expects bincode-as-JSON from
        // the host (the phone-otp authenticator's emit path uses
        // serde_json::to_vec); switch to typed decode in v0.2 once
        // EventWire is published.
        let event: serde_json::Value = match serde_json::from_slice(&event_bytes) {
            Ok(v) => v,
            Err(e) => {
                logging::log(
                    logging::LogLevel::Warn,
                    &format!("spi-twilio: malformed event bytes: {e}"),
                );
                return Ok(()); // Fire-forget: ignore parse failures.
            }
        };

        // Filter — only act on the action we're configured for.
        let action = event.get("action").and_then(|v| v.as_str()).unwrap_or("");
        if action != "sms.send" {
            return Ok(());
        }

        let detail = event.get("detail").cloned().unwrap_or(serde_json::Value::Null);
        let to = detail
            .get("to")
            .and_then(|v| v.as_str())
            .ok_or_else(|| PluginError {
                kind: "missing-field".into(),
                message: "event.detail.to required for sms.send".into(),
                retryable: false,
            })?;
        let body = detail.get("body").and_then(|v| v.as_str()).unwrap_or("");

        // Secrets — operator-managed via `geoctl spi set-secret`.
        let sid = read_secret("spi-twilio.account-sid")?;
        let token = read_secret("spi-twilio.auth-token")?;
        let from = read_secret("spi-twilio.from")?;

        // Twilio's Messages endpoint accepts application/x-www-form-urlencoded.
        let body_payload: String = form_urlencoded::Serializer::new(String::new())
            .append_pair("To", to)
            .append_pair("From", &from)
            .append_pair("Body", body)
            .finish();

        let auth = base64_encode(&format!("{sid}:{token}"));
        let url = format!("https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json");
        let request = http_client::HttpRequest {
            method: "POST".into(),
            url,
            headers: vec![
                ("Authorization".into(), format!("Basic {auth}")),
                ("Content-Type".into(), "application/x-www-form-urlencoded".into()),
            ],
            body: body_payload.into_bytes(),
        };

        let response = http_client::request(&request).map_err(|e| PluginError {
            kind: "http".into(),
            message: format!("twilio request: {e}"),
            retryable: true,
        })?;

        if !(200..300).contains(&response.status) {
            return Err(PluginError {
                kind: "twilio-rejected".into(),
                message: format!(
                    "twilio status={} body={:?}",
                    response.status,
                    String::from_utf8_lossy(&response.body),
                ),
                retryable: response.status >= 500,
            });
        }
        logging::log(
            logging::LogLevel::Info,
            &format!("spi-twilio: sent SMS to {to} (status={})", response.status),
        );
        Ok(())
    }
}

fn read_secret(key: &str) -> Result<String, PluginError> {
    let bytes = secrets::read(key).map_err(|e| PluginError {
        kind: "missing-secret".into(),
        message: format!("secret {key}: {e}"),
        retryable: false,
    })?;
    String::from_utf8(bytes).map_err(|e| PluginError {
        kind: "bad-secret".into(),
        message: format!("secret {key} not UTF-8: {e}"),
        retryable: false,
    })
}

/// Minimal Base64 encoder. The plugin's WASI environment doesn't
/// include `base64` by default and pulling the full crate is overkill
/// for the one Authorization header we emit.
fn base64_encode(input: &str) -> String {
    const ALPHA: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let triple = (b0 as u32) << 16 | (b1 as u32) << 8 | (b2 as u32);
        out.push(ALPHA[((triple >> 18) & 0x3f) as usize] as char);
        out.push(ALPHA[((triple >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHA[((triple >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHA[(triple & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

export!(SpiTwilio);
