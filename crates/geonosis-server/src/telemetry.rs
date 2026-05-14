//! OpenTelemetry bootstrap.
//!
//! Per `docs/13-observability.md` §"Tracing":
//! - When `GEONOSIS_OTLP_ENDPOINT` is set, the server adds a
//!   `tracing-opentelemetry` layer that exports spans via OTLP/gRPC.
//! - The Prometheus `/metrics` endpoint stays as the canonical scrape
//!   surface; OTLP is the trace/log shipping channel.
//! - Tail sampling is a collector responsibility — the server emits
//!   every span and lets the collector drop. This keeps the producer
//!   side simple and matches the doc's "tail sample at collector"
//!   guidance.
//!
//! When the env var is unset, telemetry init falls back to the v0.1
//! baseline: JSON stdout via `tracing_subscriber::fmt`. No OTel deps
//! are activated at runtime.

use std::env;

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

const ENV_VAR: &str = "GEONOSIS_OTLP_ENDPOINT";
const SERVICE_NAME: &str = "geonosis-server";

/// Initialize the global subscriber. Returns `Ok(true)` when OTLP was
/// wired, `Ok(false)` when the JSON-only fallback was used.
pub fn init() -> Result<bool, String> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer().json();

    match env::var(ENV_VAR).ok().filter(|v| !v.trim().is_empty()) {
        Some(endpoint) => {
            let tracer = build_otlp_tracer(&endpoint)?;
            let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .with(otel_layer)
                .try_init()
                .map_err(|e| e.to_string())?;
            Ok(true)
        }
        None => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .try_init()
                .map_err(|e| e.to_string())?;
            Ok(false)
        }
    }
}

/// Shut down the OTLP exporter. Call at server stop so in-flight
/// spans flush before process exit.
pub fn shutdown() {
    opentelemetry::global::shutdown_tracer_provider();
}

fn build_otlp_tracer(
    endpoint: &str,
) -> Result<opentelemetry_sdk::trace::Tracer, String> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e| format!("otlp exporter: {e}"))?;

    let resource = opentelemetry_sdk::Resource::new(vec![
        opentelemetry::KeyValue::new("service.name", SERVICE_NAME),
        opentelemetry::KeyValue::new(
            "service.version",
            env!("CARGO_PKG_VERSION").to_string(),
        ),
    ]);

    let provider = opentelemetry_sdk::trace::TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_resource(resource)
        .build();

    let tracer = provider.tracer(SERVICE_NAME);
    opentelemetry::global::set_tracer_provider(provider);
    Ok(tracer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_name_is_pinned() {
        // Operators alert on this service name; renaming silently
        // breaks dashboards. Pin with a literal.
        assert_eq!(SERVICE_NAME, "geonosis-server");
    }

    #[test]
    fn env_var_is_stable() {
        assert_eq!(ENV_VAR, "GEONOSIS_OTLP_ENDPOINT");
    }
}
