-- Immutable audit log: the append-only record of every security-relevant
-- authorization decision the control plane makes.
--
-- Design rules enforced here:
--
--   * Append-only. audit_events has no updated_at column and no UPDATE path.
--     A BEFORE UPDATE trigger rejects every update at the database level, so a
--     written audit record can never be altered after the fact -- not by
--     application code, not by an operator with a SQL console. Row-level DELETE
--     is reachable only through ON DELETE CASCADE when an organization is
--     deleted (tenant teardown); the store package exposes no delete of its
--     own.
--   * Both verdicts are recorded. decision is 'allowed' or 'denied' -- a denied
--     authorization decision is as much a part of the trail as an allowed one,
--     so the audit log is the source of truth for "who was refused what".
--   * Tenant-scoped. Every row carries organization_id with a foreign key to
--     organizations, so the audit log is partitioned by tenant and a query
--     scoped to one organization can never observe another's.
--   * No secrets. metadata is redacted by the audit service before it is ever
--     handed to this table; no column stores tokens, API keys, cookies, or
--     rendered environment variable values.

CREATE TABLE audit_events (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    -- The actor is the authenticated principal. Both columns are empty for a
    -- denied decision that never resolved a principal (an unauthenticated
    -- request is still audited).
    actor_id        text        NOT NULL DEFAULT '',
    actor_kind      text        NOT NULL DEFAULT ''
                        CHECK (actor_kind IN ('', 'usr', 'sa', 'system')),
    action          text        NOT NULL CHECK (length(action) > 0),
    resource_kind   text        NOT NULL CHECK (length(resource_kind) > 0),
    resource_id     text        NOT NULL DEFAULT '',
    decision        text        NOT NULL CHECK (decision IN ('allowed', 'denied')),
    reason          text        NOT NULL CHECK (length(reason) > 0),
    request_id      text        NOT NULL DEFAULT '',
    correlation_id  text        NOT NULL DEFAULT '',
    ip_address      text        NOT NULL DEFAULT '',
    user_agent      text        NOT NULL DEFAULT '',
    -- Redacted diff / context metadata. The audit service replaces values under
    -- secret-shaped keys wholesale and scrubs known secret transport patterns
    -- before this is persisted, so the column never stores credential material.
    metadata        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now()
    -- No updated_at column: an audit record is immutable once written.
);

-- The audit log is read newest-first within an organization; the dedicated
-- indexes keep the common scoped queries (recent activity, by action, by
-- actor, by request id) off a sequential scan.
CREATE INDEX audit_events_org_occurred_idx ON audit_events (organization_id, occurred_at DESC);
CREATE INDEX audit_events_org_action_idx ON audit_events (organization_id, action);
CREATE INDEX audit_events_org_actor_idx ON audit_events (organization_id, actor_id)
    WHERE actor_id <> '';
CREATE INDEX audit_events_request_id_idx ON audit_events (request_id)
    WHERE request_id <> '';

-- audit_events_reject_update enforces immutability at the database level: every
-- UPDATE against audit_events is rejected, so a written audit record can never
-- be altered. DELETE is intentionally not blocked here -- it must stay
-- reachable through the organizations ON DELETE CASCADE for tenant teardown,
-- and the store package exposes no row-level delete of its own.
CREATE FUNCTION audit_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only: UPDATE is not permitted'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_events_reject_update();
