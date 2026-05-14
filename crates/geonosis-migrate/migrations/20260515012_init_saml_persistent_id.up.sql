-- kind: expand
-- compatible-server-min: 0.1.0
-- compatible-server-max: 0.1.x
--
-- SAML 2.0 persistent NameID table.
--
-- Per docs/20-saml-idp.md §"NameID strategies": for SPs configured
-- with `name_id_format = persistent`, Geonosis MUST return the same
-- NameID across sessions for a given (user, SP) tuple. This table
-- carries the per-(realm, user, sp_entity_id) opaque identifier.
--
-- The `name_id` value is rendered at mint time as
-- `g_<ULID-base32>` so it never leaks the underlying user ULID to
-- the SP. The combination of `(realm_id, user_id, sp_entity_id)` is
-- unique; same user + same SP → same NameID across sessions.
--
-- Forward-compat note: deleting a row revokes the SP's view of the
-- user. The admin REST surface for this lands alongside the
-- `geoctl saml persistent-id` CLI in v0.1.x+ once we have an
-- operational use case for revocation.

CREATE TABLE saml_persistent_id (
    realm_id      TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    user_id       TEXT NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    sp_entity_id  TEXT NOT NULL,
    name_id       TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (realm_id, user_id, sp_entity_id)
);

-- Lookup direction for SLO / IdP-initiated flows that have the
-- NameID and need the user.
CREATE INDEX saml_persistent_id_lookup_by_name
    ON saml_persistent_id (realm_id, sp_entity_id, name_id);

ALTER TABLE saml_persistent_id ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON saml_persistent_id
    USING (realm_id = current_setting('geonosis.realm_id', true));
