//! Per-family command modules.
//!
//! Each module owns the clap sub-enum + the run function for one
//! geoctl command family. The split lets each family carry its own
//! request/response types without bloating main.rs.
//!
//! Dispatch rule (audit-led, kept consistent across the codebase):
//!
//! - **Entity-management commands** (`realms`, `clients`, `users`,
//!   `orgs`, `agents`, `keys`, `events`, `flows`) talk through the
//!   admin REST API via [`crate::http::AdminClient`]. Audit emission
//!   + bearer auth + cross-pod consistency stays in one place.
//! - **Database-admin commands** (`spi`, `migrate`, `federation`)
//!   keep their direct-Postgres path. These run on the operator's
//!   host with database credentials; routing them through HTTP would
//!   re-implement migrate-leader-election + DDL safety in two places.
//!
//! Adding a new command family — copy `realms.rs`: small request /
//! response structs at the top, a `<Family>Cmd` clap enum, a
//! `run(client, cmd)` async function. Two ~80-line files per family.

pub mod agents;
pub mod clients;
pub mod events;
pub mod federation;
pub mod flows;
pub mod keys;
pub mod migrate;
pub mod orgs;
pub mod realms;
pub mod spi;
pub mod users;
