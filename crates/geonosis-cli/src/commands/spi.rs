//! `geoctl spi` — install / list signed WASM SPI plugins.
//!
//! This command writes directly to Postgres rather than going through
//! the admin REST API: SPI install carries the full WASM bytecode
//! (often megabytes), the SHA-256 attestation, and the binding row in
//! one logical step. Streaming megabytes through an HTTP body, then
//! re-signing the binding on the server side, would double-up
//! transaction boundaries and break the leader-locked DDL safety the
//! direct path already guarantees.
//!
//! Operators run `geoctl spi install` with `GEONOSIS_DATABASE_URL`
//! pointing at the same database the server reads from.

use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub enum SpiCmd {
    /// Install a WASM plugin under a realm. Uploads bytes + creates
    /// the SPI binding row in one flow; rollback by deleting the
    /// binding (the bytes stay addressable by sha256).
    Install {
        #[arg(long)]
        realm: String,
        /// Stable WIT interface name, e.g. `geonosis:mapper@0.1.0`.
        #[arg(long)]
        interface: String,
        /// Operator-chosen alias; becomes `wasm:{alias}:{interface-short}`.
        #[arg(long)]
        alias: String,
        /// Path to the compiled `.wasm` component.
        #[arg(long)]
        module: String,
        /// Path to the TOML plugin manifest (contains sha256, signer pubkey).
        #[arg(long)]
        manifest: Option<String>,
        /// Base64-encoded Ed25519 signature over the manifest bytes.
        #[arg(long)]
        signature: Option<String>,
        /// Skip manifest signature verification (DEV ONLY).
        #[arg(long, default_value_t = false)]
        skip_verify: bool,
        /// Provider priority. Lower binds higher in the chain.
        #[arg(long, default_value_t = 500)]
        priority: i32,
        /// Force-disables a built-in (URN) while this binding is enabled.
        #[arg(long)]
        replaces: Option<String>,
        /// JSON-encoded provider config.
        #[arg(long, default_value = "{}")]
        config: String,
    },
    /// List installed bindings for an interface.
    List {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        interface: String,
    },
}

pub async fn run(database_url: &str, cmd: SpiCmd) -> anyhow::Result<()> {
    use geonosis_core::id::{SpiBindingId, WasmModuleId};
    use geonosis_storage::{SpiBindingRow, Storage, WasmModule};

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(database_url)
        .await?;
    let storage = geonosis_storage::PostgresStorage::new(pool);
    match cmd {
        SpiCmd::Install {
            realm,
            interface,
            alias,
            module,
            manifest,
            signature,
            skip_verify,
            priority,
            replaces,
            config,
        } => {
            let realm_row = storage.get_realm_by_slug(&realm).await?;
            let bytecode = std::fs::read(&module)?;
            let sha = {
                use sha2::Digest;
                let mut h = sha2::Sha256::new();
                h.update(&bytecode);
                hex::encode(h.finalize())
            };

            // Plugin manifest verification: when --manifest and
            // --signature are provided, verify the Ed25519 signature
            // over the manifest and check the bytecode SHA-256.
            // --skip-verify bypasses this (DEV ONLY).
            if !skip_verify {
                if let (Some(manifest_path), Some(sig_b64)) = (&manifest, &signature) {
                    let manifest_bytes = std::fs::read(manifest_path)?;
                    let parsed = geonosis_spi_host::manifest::verify_signature(
                        &manifest_bytes,
                        sig_b64,
                    )
                    .map_err(|e| anyhow::anyhow!("manifest signature verification failed: {e}"))?;
                    geonosis_spi_host::manifest::verify_bytecode_sha256(&parsed, &bytecode)
                        .map_err(|e| anyhow::anyhow!("bytecode SHA-256 mismatch: {e}"))?;
                    // Trust list check: empty trusted list accepts any
                    // signer (dev mode); production operators populate
                    // the list via `geoctl spi trust`.
                    geonosis_spi_host::manifest::check_trusted(&parsed, &[])
                        .map_err(|e| anyhow::anyhow!("untrusted signer: {e}"))?;
                    println!("manifest verified: signer={}", parsed.signer_pubkey_b64);
                } else if manifest.is_some() || signature.is_some() {
                    anyhow::bail!("both --manifest and --signature are required for verification");
                }
                // When neither --manifest nor --signature is provided,
                // install proceeds without verification (backwards-compat).
            }

            let size = bytecode.len() as i64;
            let m = WasmModule {
                id: WasmModuleId::new(),
                realm_id: realm_row.id,
                alias: alias.clone(),
                interface: interface.clone(),
                sha256_hex: sha.clone(),
                size_bytes: size,
                bytecode,
                uploaded_by: None,
                created_at: chrono::Utc::now(),
            };
            storage.upload_wasm_module(m).await?;
            let cfg_json: serde_json::Value = serde_json::from_str(&config)?;
            let now = chrono::Utc::now();
            let urn_short = interface
                .strip_prefix("geonosis:")
                .and_then(|s| s.split_once('@').map(|(p, _)| p))
                .unwrap_or(&interface);
            let urn = format!("wasm:{alias}:{urn_short}");
            let binding = SpiBindingRow {
                id: SpiBindingId::new(),
                realm_id: realm_row.id,
                interface: interface.clone(),
                provider_urn: urn.clone(),
                priority,
                enabled: true,
                config: cfg_json,
                replaces,
                created_at: now,
                updated_at: now,
            };
            storage.create_spi_binding(binding).await?;
            println!("installed urn={urn} sha256={sha} bytes={size}");
        }
        SpiCmd::List { realm, interface } => {
            let r = storage.get_realm_by_slug(&realm).await?;
            let rows = storage.list_spi_bindings(r.id, &interface).await?;
            for row in rows {
                println!(
                    "{:<5} {:<60} {} {}",
                    row.priority,
                    row.provider_urn,
                    if row.enabled { "enabled" } else { "disabled" },
                    row.replaces.as_deref().unwrap_or("-")
                );
            }
        }
    }
    Ok(())
}
