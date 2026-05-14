-- kind: expand
-- compatible-server-min: 0.1.0
-- compatible-server-max: 0.1.x
--
-- Audit log. Per docs/13-observability.md: partitioned by month on
-- `occurred_at` so retention can drop partitions atomically. v0.1
-- creates the partitioned root + the current-month and next-month
-- partitions; a maintenance job creates upcoming partitions.

CREATE TABLE audit_event (
    id            TEXT NOT NULL,
    realm_id      TEXT NOT NULL,
    occurred_at   TIMESTAMPTZ NOT NULL,
    actor         JSONB NOT NULL,
    action        TEXT NOT NULL,
    target        JSONB,
    detail        JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (occurred_at, id)
) PARTITION BY RANGE (occurred_at);

-- Bootstrap partitions: current month + next month. Future months are
-- created by the `audit-partition-maintainer` background job.
CREATE TABLE audit_event_p_2026_01 PARTITION OF audit_event
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
CREATE TABLE audit_event_p_2026_02 PARTITION OF audit_event
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE audit_event_p_2026_03 PARTITION OF audit_event
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE audit_event_p_2026_04 PARTITION OF audit_event
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE audit_event_p_2026_05 PARTITION OF audit_event
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE audit_event_p_2026_06 PARTITION OF audit_event
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE INDEX audit_event_realm_time_idx ON audit_event (realm_id, occurred_at DESC);
CREATE INDEX audit_event_action_idx     ON audit_event (realm_id, action, occurred_at DESC);

ALTER TABLE audit_event ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_event
    USING (realm_id = current_setting('geonosis.realm_id', true));

CREATE TABLE event_sink (
    id              TEXT PRIMARY KEY,
    realm_id        TEXT NOT NULL REFERENCES realm(id) ON DELETE CASCADE,
    alias           TEXT NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('postgres', 'webhook', 'kafka', 'cloud')),
    config          JSONB NOT NULL DEFAULT '{}'::jsonb,
    events_filter   JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled         BOOLEAN NOT NULL DEFAULT TRUE
);

ALTER TABLE event_sink ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON event_sink
    USING (realm_id = current_setting('geonosis.realm_id', true));

-- Backfill progress tracking for the expand-contract pipeline.
CREATE TABLE migration_state (
    name      TEXT PRIMARY KEY,
    last_id   TEXT,
    done      BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
