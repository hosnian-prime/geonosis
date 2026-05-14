-- kind: expand
-- compatible-server-min: 0.1.0
-- compatible-server-max: 0.1.x

-- WASM module bytecode store. Production deployments may switch to an
-- S3-backed store via a feature flag; v0.1 ships the Postgres `bytea`
-- form for ACID + cluster-trivial semantics.
CREATE TABLE wasm_module (
    id             TEXT PRIMARY KEY,
    realm_id       TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    alias          TEXT NOT NULL,
    interface      TEXT NOT NULL,
    sha256_hex     TEXT NOT NULL,
    size_bytes     BIGINT NOT NULL,
    bytecode       BYTEA NOT NULL,
    uploaded_by    TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT wasm_module_alias_unique UNIQUE (realm_id, alias)
);

CREATE INDEX wasm_module_sha_idx ON wasm_module (sha256_hex);

ALTER TABLE wasm_module ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON wasm_module
    USING (realm_id = current_setting('geonosis.realm_id', true));

-- Per-realm provider registry rows. Both built-ins and WASM providers
-- live here under the canonical `builtin:` / `wasm:` URN scheme.
CREATE TABLE spi_binding (
    id             TEXT PRIMARY KEY,
    realm_id       TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    interface      TEXT NOT NULL,
    provider_urn   TEXT NOT NULL,
    priority       INTEGER NOT NULL DEFAULT 1000,
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    replaces       TEXT,
    config         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT spi_binding_urn_unique UNIQUE (realm_id, interface, provider_urn)
);

CREATE INDEX spi_binding_iface_idx
    ON spi_binding (realm_id, interface, priority);

ALTER TABLE spi_binding ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON spi_binding
    USING (realm_id = current_setting('geonosis.realm_id', true));
