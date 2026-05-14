-- kind: expand
-- compatible-server-min: 0.1.0
-- compatible-server-max: 0.1.x

CREATE TABLE identity_provider (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    alias         TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('oidc', 'saml')),
    adapter_urn   TEXT,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    link_only     BOOLEAN NOT NULL DEFAULT FALSE,
    first_login_flow_alias TEXT NOT NULL,
    post_login_flow_alias  TEXT,
    config        JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT identity_provider_alias_unique UNIQUE (realm_id, alias)
);

ALTER TABLE identity_provider ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON identity_provider
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE broker_authn_state (
    id                    TEXT PRIMARY KEY,
    realm_id              TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    idp_alias             TEXT NOT NULL,
    state                 TEXT NOT NULL,
    nonce                 TEXT,
    pkce_verifier         TEXT,
    return_to_flow_state  TEXT NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at            TIMESTAMPTZ NOT NULL,

    CONSTRAINT broker_authn_state_unique UNIQUE (realm_id, state)
);

CREATE INDEX broker_authn_state_exp_idx ON broker_authn_state (expires_at);

ALTER TABLE broker_authn_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON broker_authn_state
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE broker_link (
    id                TEXT PRIMARY KEY,
    realm_id          TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    user_id           TEXT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    idp_alias         TEXT NOT NULL,
    external_id       TEXT NOT NULL,
    external_username TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at     TIMESTAMPTZ,

    CONSTRAINT broker_link_external_unique UNIQUE (realm_id, idp_alias, external_id)
);

CREATE INDEX broker_link_user_idx ON broker_link (realm_id, user_id);

ALTER TABLE broker_link ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON broker_link
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE ldap_federation (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    alias         TEXT NOT NULL,
    priority      INTEGER NOT NULL DEFAULT 100,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    config        JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT ldap_federation_alias_unique UNIQUE (realm_id, alias)
);

ALTER TABLE ldap_federation ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON ldap_federation
    USING (realm_id = current_setting('geonosis.realm_id', true));
