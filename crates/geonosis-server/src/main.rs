use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use geonosis_audit::Publisher;
use geonosis_cache::LocalCache;
use geonosis_crypto::{MasterKey, SoftwareKms};
use geonosis_server::{router, AppState};
use geonosis_spi_host::ProviderRegistry;
use geonosis_storage::{MemoryStorage, PostgresStorage, Storage};

#[derive(Debug, Parser)]
#[command(name = "geonosis-server", about = "Geonosis IAM server (v0.1)")]
struct Args {
    /// Address to bind, e.g. `0.0.0.0:8080`.
    #[arg(long, env = "GEONOSIS_LISTEN", default_value = "127.0.0.1:8080")]
    listen: String,

    /// Public base URL (used to construct issuer / discovery URLs).
    #[arg(long, env = "GEONOSIS_PUBLIC_URL", default_value = "http://127.0.0.1:8080")]
    public_url: String,

    /// 32-byte hex master key. Generated at random if unset (DEV ONLY).
    #[arg(long, env = "GEONOSIS_MASTER_KEY")]
    master_key_hex: Option<String>,

    /// Postgres `postgres://user:pass@host/db` URL. When set, the
    /// server uses `PostgresStorage`; otherwise it falls back to the
    /// in-memory backend (the dev default).
    #[arg(long, env = "GEONOSIS_DATABASE_URL")]
    database_url: Option<String>,

    /// If true, run pending migrations on boot (advisory-lock'd, so safe
    /// on every pod). Off-by-default: `geoctl migrate up` is the
    /// recommended deploy step.
    #[arg(long, env = "GEONOSIS_MIGRATE_ON_BOOT", default_value_t = false)]
    migrate_on_boot: bool,

    /// Comma-separated webhook URLs to forward audit events to. Each
    /// URL gets its own `WebhookSink` with the v0.1 default retry
    /// profile (4 attempts, 250ms → 8s exponential backoff,
    /// 5s per-attempt timeout). Empty disables webhook forwarding.
    #[arg(long, env = "GEONOSIS_AUDIT_WEBHOOK_URLS", default_value = "")]
    audit_webhook_urls: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .json()
        .init();

    let master = match args.master_key_hex {
        Some(h) => {
            let bytes = hex_decode_32(&h)?;
            MasterKey::from_bytes(bytes)
        }
        None => {
            tracing::warn!("GEONOSIS_MASTER_KEY unset — generating ephemeral key (DEV ONLY)");
            MasterKey::generate()
        }
    };

    let (storage, retention_pool): (Arc<dyn Storage>, Option<sqlx::postgres::PgPool>) =
        if let Some(url) = &args.database_url {
            tracing::info!(database_url = %redact_url(url), "connecting to Postgres backend");
            let pool = geonosis_storage::postgres::build_pool(url).await?;
            if args.migrate_on_boot {
                tracing::info!("running pending migrations under advisory lock");
                geonosis_migrate::run_with_leader_lock(&pool).await?;
            }
            // Refuse to start if the live schema is outside our window.
            geonosis_migrate::enforce_schema_compat(&pool, geonosis_migrate::V0_1_COMPAT)
                .await?;
            (
                Arc::new(PostgresStorage::new(pool.clone())) as Arc<dyn Storage>,
                Some(pool),
            )
        } else {
            tracing::warn!("GEONOSIS_DATABASE_URL unset — using in-memory storage (DEV ONLY)");
            (
                Arc::new(MemoryStorage::new()) as Arc<dyn Storage>,
                None,
            )
        };
    // Derive deployment-wide hash keys from the master key. Per-realm
    // derivation lands in v0.1.x.
    let refresh_hash_key = derive_subkey(&master, b"geonosis-refresh-hash-v1");
    let client_secret_hash_key = derive_subkey(&master, b"geonosis-client-secret-hash-v1");

    // Audit sinks: webhook URLs from env, plus the postgres sink when
    // a database is configured. Order matters only for log clarity;
    // the publisher fans out concurrently.
    let mut audit_sinks: Vec<std::sync::Arc<dyn geonosis_audit::AuditSink>> = Vec::new();
    for raw in args.audit_webhook_urls.split(',').filter(|s| !s.trim().is_empty()) {
        let url = raw.trim().to_string();
        match geonosis_audit::webhook::WebhookSink::new(
            geonosis_audit::webhook::WebhookSinkConfig::new(url.clone()),
        ) {
            Ok(sink) => {
                tracing::info!(url = %url, "wiring audit webhook sink");
                audit_sinks.push(std::sync::Arc::new(sink));
            }
            Err(e) => {
                tracing::error!(url = %url, error = %e, "failed to build webhook sink; skipping");
            }
        }
    }

    let state = AppState {
        storage,
        cache: Arc::new(LocalCache::default_small()),
        kms: Arc::new(SoftwareKms::new(master)),
        providers: Arc::new(ProviderRegistry::new()),
        audit: Arc::new(Publisher::new(audit_sinks)),
        public_base_url: url::Url::parse(&args.public_url)?,
        refresh_hash_key,
        client_secret_hash_key,
        authenticators: Arc::new(geonosis_server::authenticators::BuiltinAuthenticators::default()),
        broker_adapters: Arc::new(geonosis_broker::BuiltinAdapters::default()),
        broker: Arc::new(geonosis_server::broker::BrokerRuntime::new()),
        ldap: Arc::new(geonosis_server::ldap::LdapRuntime::new()),
        metrics: Arc::new(geonosis_server::metrics::MetricsState::new()),
    };

    // Spawn the audit-retention runner when Postgres is the backend.
    // The closure captures the storage Arc so the runner doesn't need
    // to know about the trait shape; v0.2 promotes this to a generic
    // hook on the audit Publisher.
    if let Some(pool) = retention_pool {
        let storage_for_retention = state.storage.clone();
        let list_retention: geonosis_audit::retention::ListRetentionFn =
            std::sync::Arc::new(move || {
                let storage = storage_for_retention.clone();
                Box::pin(async move {
                    let realms = storage
                        .list_realms()
                        .await
                        .map_err(|e| format!("list_realms: {e}"))?;
                    Ok(realms
                        .into_iter()
                        .map(|r| (r.id.to_string(), r.events.retention_days))
                        .collect())
                })
            });
        geonosis_audit::retention::spawn_runner(
            pool,
            list_retention,
            geonosis_audit::retention::DEFAULT_RUN_INTERVAL,
        );
        tracing::info!("audit retention runner spawned (hourly)");
    }

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!(listen = %args.listen, "geonosis-server starting");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

fn derive_subkey(master: &MasterKey, label: &[u8]) -> [u8; 32] {
    // BLAKE3 in keyed mode over the label gives us a deterministic 32-byte
    // domain-separated subkey. We deliberately do NOT expose the master
    // bytes; we wrap an arbitrary throwaway plaintext under it and hash
    // the ciphertext together with the label to derive the subkey.
    let proof = master
        .wrap(b"geonosis-derive")
        .expect("wrap must succeed");
    let mut hasher = blake3::Hasher::new();
    hasher.update(label);
    hasher.update(&proof.nonce);
    hasher.update(&proof.ciphertext);
    *hasher.finalize().as_bytes()
}

/// Redact userinfo from a Postgres URL so we don't accidentally log
/// the password.
fn redact_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut u) => {
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.to_string()
        }
        Err(_) => "<unparseable url>".into(),
    }
}

fn hex_decode_32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("master key must be 64 hex chars (32 bytes), got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(s.as_bytes()[i * 2])?;
        let lo = hex_nibble(s.as_bytes()[i * 2 + 1])?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        other => Err(format!("invalid hex byte: {other}")),
    }
}
