-- kind: expand
-- compatible-server-min: 0.1.0
-- compatible-server-max: 0.1.x
-- requires-backfill: false

-- Geonosis schema bootstrap. Every tenanted table carries `realm_id`
-- and gets a `tenant_isolation` RLS policy.

-- btree_gin allows composite GIN indexes to include plain scalar columns
-- (e.g. realm_id TEXT) alongside tsvector / jsonb columns.
CREATE EXTENSION IF NOT EXISTS btree_gin;

CREATE TABLE realm (
    id            TEXT PRIMARY KEY,
    slug          TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    config        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT realm_slug_charset CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,63}$')
);

CREATE INDEX realm_slug_idx ON realm (slug);
