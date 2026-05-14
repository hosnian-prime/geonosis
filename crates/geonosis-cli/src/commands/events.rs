//! `geoctl events` — read the audit event log.

use clap::Subcommand;

use crate::http::AdminClient;

#[derive(Subcommand, Debug)]
pub enum EventCmd {
    /// Filtered list. `--action` matches the dotted action namespace,
    /// `--actor` filters by actor key, `--from`/`--until` accept
    /// RFC-3339 timestamps.
    List {
        #[arg(long)]
        realm: String,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        actor: Option<String>,
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
}

pub async fn run(client: &AdminClient, cmd: EventCmd) -> anyhow::Result<()> {
    match cmd {
        EventCmd::List {
            realm,
            action,
            actor,
            from,
            until,
            limit,
        } => {
            let mut path = format!("/admin/v1/realms/{realm}/events?limit={limit}");
            if let Some(a) = action {
                path.push_str(&format!("&action={}", urlencoding(&a)));
            }
            if let Some(a) = actor {
                path.push_str(&format!("&actor={}", urlencoding(&a)));
            }
            if let Some(t) = from {
                path.push_str(&format!("&from={}", urlencoding(&t)));
            }
            if let Some(t) = until {
                path.push_str(&format!("&until={}", urlencoding(&t)));
            }
            let rows: serde_json::Value = client.get(&path).await?;
            println!("{}", serde_json::to_string_pretty(&rows)?);
        }
    }
    Ok(())
}

/// Tiny percent-encoder for query-string values. Keeps the dep
/// surface tight; we only encode the characters that break query
/// parsing (`&`, `=`, `#`, space). Anything that needs richer encoding
/// belongs in `reqwest`'s native query builder.
fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'&' | b'=' | b'#' | b' ' | b'+' | b'%' | b'?' => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
            _ => out.push(b as char),
        }
    }
    out
}
