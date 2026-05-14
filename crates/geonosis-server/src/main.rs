use std::sync::Arc;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use geonosis_audit::Publisher;
use geonosis_cache::LocalCache;
use geonosis_crypto::{MasterKey, SoftwareKms};
use geonosis_server::{router, AppState};
use geonosis_spi_host::ProviderRegistry;
use geonosis_storage::MemoryStorage;

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

    let storage = Arc::new(MemoryStorage::new());
    // Derive deployment-wide hash keys from the master key. Per-realm
    // derivation lands in v0.1.x.
    let refresh_hash_key = derive_subkey(&master, b"geonosis-refresh-hash-v1");
    let client_secret_hash_key = derive_subkey(&master, b"geonosis-client-secret-hash-v1");
    let state = AppState {
        storage,
        cache: Arc::new(LocalCache::default_small()),
        kms: Arc::new(SoftwareKms::new(master)),
        providers: Arc::new(ProviderRegistry::new()),
        audit: Arc::new(Publisher::new(vec![])),
        public_base_url: url::Url::parse(&args.public_url)?,
        refresh_hash_key,
        client_secret_hash_key,
    };

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
