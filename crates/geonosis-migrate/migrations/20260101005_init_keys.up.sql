-- kind: expand
-- compatible-server-min: 0.1.0
-- compatible-server-max: 0.1.x

CREATE TABLE key_material (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    usage         TEXT NOT NULL CHECK (usage IN ('sig', 'enc')),
    alg           TEXT NOT NULL,
    state         TEXT NOT NULL CHECK (state IN ('active', 'previous-active', 'disabled')),
    public_jwk    JSONB NOT NULL,
    private_ref   JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at    TIMESTAMPTZ
);

CREATE INDEX key_material_realm_alg_state_idx ON key_material (realm_id, alg, state);

ALTER TABLE key_material ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON key_material
    USING (realm_id = current_setting('geonosis.realm_id', true));
