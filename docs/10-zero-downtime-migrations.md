# 10 — Zero-Downtime Schema Migrations

This is the contract that lets us claim "no downtime for upgrades."
Every schema change MUST follow **expand-contract** and be deployable
without coordinated maintenance windows.

## The rule

> No release may include a schema change that requires the previous
> version of the server to be offline.

If you can't honor this with a single migration, split it across at
least two releases.

## Expand-contract

For any logical change (rename column, change a type, drop a column):

1. **Expand** (release N): add the new shape alongside the old.
2. **Migrate data** (release N or N+0.1 as a background job, with
   the server tolerating both shapes).
3. **Switch reads/writes** (release N+1): server reads/writes the
   new shape; the old shape remains for rollback.
4. **Contract** (release N+2): drop the old shape, after at least
   one minor cycle on the new.

The server **always** runs against at least two adjacent schema
versions during any rolling upgrade.

## Concrete examples

### Rename a column

```sql
-- v0.5  (expand)
ALTER TABLE app_user ADD COLUMN email_lc TEXT;
CREATE INDEX ON app_user (realm_id, email_lc);
-- backfill in the same migration if cheap, else release a background
-- job that writes to both columns going forward.

-- v0.5 code: writes to old AND new column; reads still from old.

-- v0.6 code: writes new column primary; reads new column with fallback.

-- v0.7 code: reads/writes new column exclusively.

-- v0.8  (contract)
ALTER TABLE app_user DROP COLUMN email_old;
```

### Change a column type (e.g. `TEXT` → `JSONB`)

Add `attributes_v2 JSONB`. Backfill. Switch. Drop old.

### Drop a table

Add a `DEPRECATED_*` view that proxies to whatever replaces it, so
older instances still see a result; after one minor, drop the table
and view together.

## Migrations toolchain

- **`sqlx::migrate`** for the migration runner — embedded in the
  binary, no separate tool.
- Migrations live in `crates/geonosis-migrate/migrations/`.
- Naming: `{timestamp}_{slug}.up.sql` and `.down.sql`. Down migrations
  required for the **expand** step; **contract** steps are
  one-way (we don't promise to undo a contract).
- Each migration starts with a comment header:

  ```
  -- kind: expand
  -- compatible-server-min: v0.5.0
  -- compatible-server-max: v0.7.x
  ```

  The server checks these on boot and refuses to run if either bound
  is violated.

## Migration runner choreography

The server image ships with a `geoctl migrate` subcommand and also
applies migrations on startup. Kubernetes deployment:

```
helm upgrade ... → new ReplicaSet rolls
   pod-new:1  pulls image
              executes `geoctl migrate` (with leader election lock)
              starts serving
   ingress shifts to pod-new:1
   pod-old:1 drains, terminates
   ...
```

The leader election uses a Postgres advisory lock:

```sql
SELECT pg_try_advisory_lock(8423651021231);
```

Only the holder runs migrations; others wait until the migration
table reaches the expected revision. Idempotent — safe to run on
every pod boot.

## Server compatibility window

Each pod advertises its **schema version range** on boot:

```rust
pub struct ServerCompat {
    pub min_schema: u32,
    pub max_schema: u32,
}
```

If the database reports a schema version outside the range, the pod
**refuses to start** with a clear error. This catches:

- New pod with old schema → "DB is at v23, server needs >= v25"
  (operator should redeploy with migrate step first).
- Old pod with new schema (rollback gone wrong) → "DB is at v25,
  server only handles up to v23" (operator must roll the DB back to
  v23 or upgrade the pod).

This makes accidental misuse loud rather than corrupt.

## Backfill strategy

For large tables:

- A **background backfill worker** runs in one pod (leader election)
  scoped to batches of N rows by `realm_id` keyspace ranges, sleeping
  between batches.
- Throttled to keep `pg_stat_activity` low; pauses if replication lag
  exceeds a threshold.
- Progress recorded in a `migration_state` table (`(name, last_id,
  done)`).
- Workers are restartable (pod loss is OK — pick up from
  `last_id`).
- Idempotent updates (`UPDATE ... WHERE x IS NULL AND ...`).

## Online schema operations

Postgres semantics we rely on:

- `ALTER TABLE ... ADD COLUMN x TYPE DEFAULT y` is cheap (PG 11+: no
  rewrite for constant defaults).
- `CREATE INDEX CONCURRENTLY` for new indexes, always.
- `ALTER TABLE ... SET NOT NULL` requires a full scan — split: add
  `CHECK (col IS NOT NULL) NOT VALID`, then `VALIDATE CONSTRAINT`,
  then convert to `NOT NULL` once validated.
- Avoid `ALTER COLUMN ... TYPE` for non-trivial types — write a new
  column.

These are documented as **migration recipes** in
`docs/migration-recipes.md` (to be added with the first real
migration).

## Configuration & feature flags

Server features that depend on a new column are gated:

```toml
[server.features]
new_search_v2 = false   # turned on after backfill completes
```

The feature flag flips after operator confirms the migration is
complete. The old code path is removed in the contract step.

## SPI & module store

WASM module bytecode changes follow the same discipline:

- Module records grow new columns; old columns stay until the
  registry has been updated across a release boundary.
- The WIT world version is independent of the schema version; a v0.2
  authn world is added next to v0.1, not replacing it.

## Rollback

We rollback **code** without rolling back schema. After an upgrade,
the previous release MUST be able to run against the new schema.
This is the entire point of the rule.

If we ever need to roll back schema (genuine data-shape error), it
must be planned ahead and accepted as **downtime**. We don't pretend
otherwise.

## Validation in CI

- A CI job runs the latest N-2 release against the head schema and
  exercises a smoke-test suite.
- A property test: starting from any tagged release, applying all
  migrations forward leaves the DB consistent.
- A migration linter rejects:
  - `DROP COLUMN` without a matching expand-contract record.
  - `ALTER TABLE ... NOT NULL` without the staged form.
  - Indexes created non-concurrently.

## Non-goals

- **Online major-version Postgres upgrade** — operator responsibility.
- **Zero-downtime cross-region failover** — out of scope.
- **Live schema editing via admin UI** — schemas are operator-managed.

## Open

- **Triggering a contract step** automatically once metrics
  confirm the old column is unread — design but defer; do it as
  an operator-driven release for now.
- **Migration progress UI** in the admin console — nice to have v0.2.
