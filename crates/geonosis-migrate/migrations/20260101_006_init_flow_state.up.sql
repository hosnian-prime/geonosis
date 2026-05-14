-- kind: expand
-- compatible-server-min: 0.1.0
-- compatible-server-max: 0.1.x

CREATE TABLE auth_flow (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    alias         TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    version       INTEGER NOT NULL,
    graph         JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT auth_flow_alias_version UNIQUE (realm_id, alias, version)
);

ALTER TABLE auth_flow ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON auth_flow
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE flow_state (
    id                TEXT PRIMARY KEY,
    realm_id          TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    flow_id           TEXT NOT NULL,
    flow_version      INTEGER NOT NULL,
    current_node      TEXT NOT NULL,
    history           JSONB NOT NULL DEFAULT '[]'::jsonb,
    context           JSONB NOT NULL DEFAULT '{}'::jsonb,
    authorize_params  JSONB NOT NULL DEFAULT '{}'::jsonb,
    started_at        TIMESTAMPTZ NOT NULL,
    last_activity_at  TIMESTAMPTZ NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    csrf_token        TEXT NOT NULL
);

CREATE INDEX flow_state_expires_idx ON flow_state (expires_at);

ALTER TABLE flow_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON flow_state
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE par_request (
    request_uri   TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    client_id     TEXT NOT NULL REFERENCES client(id) ON DELETE CASCADE,
    params        JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL
);

CREATE INDEX par_request_expires_idx ON par_request (expires_at);

ALTER TABLE par_request ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON par_request
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE device_grant (
    device_code        TEXT PRIMARY KEY,
    user_code          TEXT NOT NULL UNIQUE,
    realm_id           TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    client_id          TEXT NOT NULL REFERENCES client(id) ON DELETE CASCADE,
    scope              JSONB NOT NULL DEFAULT '[]'::jsonb,
    interval_seconds   INTEGER NOT NULL,
    status             TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    user_id            TEXT,
    session_id         TEXT,
    created_at         TIMESTAMPTZ NOT NULL,
    expires_at         TIMESTAMPTZ NOT NULL,
    last_polled_at     TIMESTAMPTZ
);

CREATE INDEX device_grant_expires_idx ON device_grant (expires_at);

ALTER TABLE device_grant ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON device_grant
    USING (realm_id = current_setting('geonosis.realm_id', true));
