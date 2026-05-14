-- kind: expand
-- compatible-server-min: 0.1.0
-- compatible-server-max: 0.1.x
--
-- Foundation tables that the v0.1 feature-parity audit (docs 02, 15, 16,
-- 18) flagged as missing. Strictly additive — no existing table or
-- column is touched.

-- ---------- Roles (realm + client-scoped) ----------

CREATE TABLE realm_role (
    id           TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    -- NULL => realm-wide role; non-NULL => client-scoped role.
    client_id    TEXT REFERENCES client(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    description  TEXT,
    composites   JSONB NOT NULL DEFAULT '{"realm_roles":[],"client_roles":{}}'::jsonb,
    attributes   JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT realm_role_name_unique UNIQUE (realm_id, client_id, name)
);

CREATE INDEX realm_role_client_idx ON realm_role (realm_id, client_id);

ALTER TABLE realm_role ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON realm_role
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE user_role (
    realm_id   TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role_id    TEXT NOT NULL REFERENCES realm_role(id) ON DELETE CASCADE,

    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX user_role_role_idx ON user_role (realm_id, role_id);

ALTER TABLE user_role ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON user_role
    USING (realm_id = current_setting('geonosis.realm_id', true));

-- ---------- Groups (hierarchical) ----------

CREATE TABLE app_group (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    parent_id   TEXT REFERENCES app_group(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    path        TEXT NOT NULL,
    attributes  JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT app_group_path_unique UNIQUE (realm_id, path)
);

CREATE INDEX app_group_parent_idx ON app_group (realm_id, parent_id);

ALTER TABLE app_group ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON app_group
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE user_group (
    realm_id  TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    user_id   TEXT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    group_id  TEXT NOT NULL REFERENCES app_group(id) ON DELETE CASCADE,

    PRIMARY KEY (user_id, group_id)
);

CREATE INDEX user_group_group_idx ON user_group (realm_id, group_id);

ALTER TABLE user_group ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON user_group
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE group_role (
    realm_id  TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    group_id  TEXT NOT NULL REFERENCES app_group(id) ON DELETE CASCADE,
    role_id   TEXT NOT NULL REFERENCES realm_role(id) ON DELETE CASCADE,

    PRIMARY KEY (group_id, role_id)
);

CREATE INDEX group_role_role_idx ON group_role (realm_id, role_id);

ALTER TABLE group_role ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON group_role
    USING (realm_id = current_setting('geonosis.realm_id', true));

-- ---------- User-profile schema (one per realm) ----------

CREATE TABLE user_profile_schema (
    realm_id          TEXT PRIMARY KEY REFERENCES realm(id) ON DELETE CASCADE,
    attributes        JSONB NOT NULL DEFAULT '[]'::jsonb,
    groups            JSONB NOT NULL DEFAULT '[]'::jsonb,
    unmanaged_policy  TEXT NOT NULL DEFAULT 'reject',
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE user_profile_schema ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON user_profile_schema
    USING (realm_id = current_setting('geonosis.realm_id', true));

-- ---------- Agent identity ----------

CREATE TABLE agent (
    id                TEXT PRIMARY KEY,
    realm_id          TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    alias             TEXT NOT NULL,
    display_name      TEXT NOT NULL,
    kind              TEXT NOT NULL,
    model_hint        TEXT,
    vendor            TEXT,
    version           TEXT,
    parent_subject    JSONB NOT NULL,
    capabilities      JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_scopes    JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_audiences JSONB NOT NULL DEFAULT '[]'::jsonb,
    rate_limit        JSONB NOT NULL,
    auth_method       TEXT NOT NULL,
    public_jwk        JSONB,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ,
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT agent_alias_unique UNIQUE (realm_id, alias)
);

CREATE INDEX agent_realm_idx ON agent (realm_id);

ALTER TABLE agent ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent
    USING (realm_id = current_setting('geonosis.realm_id', true));

-- ---------- Org-level consent policy (per (org, client)) ----------

CREATE TABLE org_consent_policy (
    id                       TEXT PRIMARY KEY,
    organization_id          TEXT NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    realm_id                 TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    client_id                TEXT NOT NULL REFERENCES client(id) ON DELETE CASCADE,
    mode                     TEXT NOT NULL CHECK (mode IN ('user-decides','org-pre-approved','org-managed')),
    pre_approved_scopes      JSONB NOT NULL DEFAULT '[]'::jsonb,
    blocked_scopes           JSONB NOT NULL DEFAULT '[]'::jsonb,
    require_admin_approval   BOOLEAN NOT NULL DEFAULT FALSE,
    created_by               TEXT NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT org_consent_policy_unique UNIQUE (organization_id, client_id)
);

CREATE INDEX org_consent_policy_client_idx ON org_consent_policy (realm_id, client_id);

ALTER TABLE org_consent_policy ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON org_consent_policy
    USING (realm_id = current_setting('geonosis.realm_id', true));

-- ---------- Per-org IdP binding ----------

CREATE TABLE org_idp_binding (
    organization_id  TEXT NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    realm_id         TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    idp_alias        TEXT NOT NULL,
    priority         INTEGER NOT NULL DEFAULT 0,
    enabled          BOOLEAN NOT NULL DEFAULT TRUE,

    PRIMARY KEY (organization_id, idp_alias)
);

CREATE INDEX org_idp_binding_idp_idx ON org_idp_binding (realm_id, idp_alias);

ALTER TABLE org_idp_binding ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON org_idp_binding
    USING (realm_id = current_setting('geonosis.realm_id', true));
