-- kind: expand
-- compatible-server-min: 0.1.0
-- compatible-server-max: 0.1.x

CREATE TABLE code_grant (
    code            TEXT PRIMARY KEY,
    realm_id        TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    client_id       TEXT NOT NULL REFERENCES client(id) ON DELETE CASCADE,
    user_id         TEXT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    session_id      TEXT NOT NULL,
    scope           JSONB NOT NULL DEFAULT '[]'::jsonb,
    redirect_uri    TEXT NOT NULL,
    code_challenge  JSONB,
    nonce           TEXT,
    state           TEXT,
    amr             JSONB NOT NULL DEFAULT '[]'::jsonb,
    auth_time       TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX code_grant_realm_idx ON code_grant (realm_id);
CREATE INDEX code_grant_expires_idx ON code_grant (expires_at);

ALTER TABLE code_grant ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON code_grant
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE refresh_token (
    id            TEXT PRIMARY KEY,
    family_id     TEXT NOT NULL,
    realm_id      TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    client_id     TEXT NOT NULL REFERENCES client(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    session_id    TEXT NOT NULL,
    scope         JSONB NOT NULL DEFAULT '[]'::jsonb,
    issued_at     TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    used          BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX refresh_token_family_idx ON refresh_token (family_id);
CREATE INDEX refresh_token_user_idx ON refresh_token (realm_id, user_id);
CREATE INDEX refresh_token_expires_idx ON refresh_token (expires_at);

ALTER TABLE refresh_token ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON refresh_token
    USING (realm_id = current_setting('geonosis.realm_id', true));
