-- kind: expand
-- compatible-server-min: 0.1.0
-- compatible-server-max: 0.1.x

CREATE TABLE consent_grant (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    client_id     TEXT NOT NULL REFERENCES client(id) ON DELETE CASCADE,
    scopes        JSONB NOT NULL DEFAULT '[]'::jsonb,
    granted_at    TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL,

    CONSTRAINT consent_grant_unique UNIQUE (realm_id, user_id, client_id)
);

ALTER TABLE consent_grant ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON consent_grant
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE organization (
    id              TEXT PRIMARY KEY,
    realm_id        TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    alias           TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    description     TEXT,
    branding        JSONB NOT NULL DEFAULT '{}'::jsonb,
    attributes      JSONB NOT NULL DEFAULT '{}'::jsonb,
    default_idp_alias TEXT,
    redirect_url    TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT organization_alias_unique UNIQUE (realm_id, alias)
);

ALTER TABLE organization ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON organization
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE org_domain (
    id                  TEXT PRIMARY KEY,
    organization_id     TEXT NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    realm_id            TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    domain              TEXT NOT NULL,
    verified            BOOLEAN NOT NULL DEFAULT FALSE,
    verification_token  TEXT,
    verified_at         TIMESTAMPTZ,

    CONSTRAINT org_domain_unique UNIQUE (realm_id, domain)
);

ALTER TABLE org_domain ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON org_domain
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE org_membership (
    organization_id     TEXT NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    realm_id            TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    user_id             TEXT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    roles               JSONB NOT NULL DEFAULT '[]'::jsonb,
    invited_by          TEXT,
    state               TEXT NOT NULL CHECK (state IN ('active', 'invited', 'suspended')),
    joined_at           TIMESTAMPTZ NOT NULL,

    PRIMARY KEY (organization_id, user_id)
);

CREATE INDEX org_membership_user_idx ON org_membership (realm_id, user_id);

ALTER TABLE org_membership ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON org_membership
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE org_role (
    id              TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    realm_id        TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    description     TEXT,
    permissions     JSONB NOT NULL DEFAULT '[]'::jsonb,
    built_in        BOOLEAN NOT NULL DEFAULT FALSE,

    CONSTRAINT org_role_name_unique UNIQUE (organization_id, name)
);

ALTER TABLE org_role ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON org_role
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE org_invitation (
    id                TEXT PRIMARY KEY,
    organization_id   TEXT NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    realm_id          TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    email             TEXT NOT NULL,
    roles             JSONB NOT NULL DEFAULT '[]'::jsonb,
    invited_by        TEXT NOT NULL,
    token             TEXT NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    accepted_at       TIMESTAMPTZ
);

CREATE INDEX org_invitation_email_idx ON org_invitation (realm_id, email);

ALTER TABLE org_invitation ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON org_invitation
    USING (realm_id = current_setting('geonosis.realm_id', true));
