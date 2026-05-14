-- kind: expand
-- compatible-server-min: 0.1.0
-- compatible-server-max: 0.1.x

CREATE TABLE app_user (
    id                 TEXT PRIMARY KEY,
    realm_id           TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    username           TEXT NOT NULL,
    username_lc        TEXT NOT NULL,
    email              TEXT,
    email_lc           TEXT,
    email_verified     BOOLEAN NOT NULL DEFAULT FALSE,
    name               JSONB,
    attributes         JSONB NOT NULL DEFAULT '{}'::jsonb,
    required_actions   JSONB NOT NULL DEFAULT '[]'::jsonb,
    required_flow      TEXT,
    organizations      JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled            BOOLEAN NOT NULL DEFAULT TRUE,

    -- Brute-force runtime fields (see docs/12-security-crypto.md).
    failed_attempts    INTEGER NOT NULL DEFAULT 0,
    locked_until       TIMESTAMPTZ,
    last_failed_at     TIMESTAMPTZ,

    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Full-text search column. Weight: A (username) > B (email) > C (name).
    search_vector tsvector GENERATED ALWAYS AS (
        setweight(to_tsvector('simple', coalesce(username_lc, '')), 'A') ||
        setweight(to_tsvector('simple', coalesce(email_lc, '')),    'B') ||
        setweight(to_tsvector('simple', coalesce(name->>'given',  '')), 'C') ||
        setweight(to_tsvector('simple', coalesce(name->>'family', '')), 'C')
    ) STORED,

    CONSTRAINT app_user_username_lc_unique UNIQUE (realm_id, username_lc)
);

CREATE INDEX app_user_realm_id_idx ON app_user (realm_id);
CREATE INDEX app_user_email_lc_idx ON app_user (realm_id, email_lc) WHERE email_lc IS NOT NULL;
CREATE INDEX app_user_search_vector_idx ON app_user USING GIN (realm_id, search_vector);

-- Row-level security: every read MUST filter to the current realm.
ALTER TABLE app_user ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON app_user
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE credential (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN (
        'password', 'otp', 'webauthn-passwordless', 'webauthn', 'recovery-code', 'magic-link'
    )),
    label         TEXT,
    secret_data   BYTEA NOT NULL,
    public_data   BYTEA NOT NULL DEFAULT ''::bytea,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);

CREATE INDEX credential_user_idx ON credential (user_id, kind);

ALTER TABLE credential ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON credential
    USING (realm_id = current_setting('geonosis.realm_id', true));
