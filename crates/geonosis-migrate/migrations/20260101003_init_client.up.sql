-- kind: expand
-- compatible-server-min: 0.1.0
-- compatible-server-max: 0.1.x

CREATE TABLE client (
    id                  TEXT PRIMARY KEY,
    realm_id            TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    client_id           TEXT NOT NULL,
    display_name        TEXT,
    kind                TEXT NOT NULL CHECK (kind IN (
        'confidential', 'public', 'bearer-only',
        'service-account', 'saml-service-provider', 'scim-client'
    )),
    config              JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    client_secret_hash  TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT client_id_charset CHECK (client_id ~ '^[A-Za-z0-9_.-]{1,128}$'),
    CONSTRAINT client_id_unique  UNIQUE (realm_id, client_id)
);

CREATE INDEX client_realm_idx ON client (realm_id);

ALTER TABLE client ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON client
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE session (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    authn_level   TEXT NOT NULL,
    idp_alias     TEXT,
    started_at    TIMESTAMPTZ NOT NULL,
    last_seen_at  TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,
    clients       JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX session_realm_user_idx ON session (realm_id, user_id);
CREATE INDEX session_expires_idx ON session (expires_at);

ALTER TABLE session ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON session
    USING (realm_id = current_setting('geonosis.realm_id', true));
