-- Deployment events: the append-only timeline of observable state transitions
-- and notable progress events the worker records as it converges a deployment
-- toward Dokploy. A deployments row carries the current converged lifecycle
-- status (the customer-facing latest snapshot); a deployment_events row is one
-- record on the history that produced that snapshot. The customer-facing
-- "show me the timeline of deployment dep_..." endpoint reads from this table,
-- ordered by occurred_at ASC so the user sees the deployment unfold forward
-- in time.
--
-- Design rules enforced here:
--
--   * Append-only. deployment_events has no updated_at column and no UPDATE
--     path. A BEFORE UPDATE trigger rejects every update at the database
--     level, so a written event record can never be altered after the fact --
--     not by application code, not by an operator with a SQL console. The
--     reasoning mirrors audit_events: the timeline is a forensic record of
--     what the worker observed; rewriting it after the fact would let a
--     buggy or compromised writer hide a failure transition. Row-level DELETE
--     is reachable only through ON DELETE CASCADE when the parent deployment
--     is removed (which itself cascades from the organization), so a tenant
--     teardown still clears the table; the store package exposes no
--     row-level delete.
--   * Tenant-scoped at the database. The composite FK
--     (organization_id, deployment_id) references the matching composite
--     UNIQUE (organization_id, id) on deployments with ON DELETE CASCADE, so
--     a deployment teardown cascades through its event history and an event
--     row can never sit under a foreign tenant's deployment. The
--     organization_id leg is persisted directly here (not derived through
--     the FK at read time) so every customer-facing read can be tenant-scoped
--     by a simple WHERE organization_id = $1 predicate; the FK is the
--     database's belt-and-braces guarantee that the persisted leg matches
--     the parent deployment's organization_id.
--   * Event type is closed-set. The event_type column confines the value to
--     a small taxonomy the worker writes verbatim ('queued', 'running',
--     'succeeded', 'failed', 'cancelled', 'rolled_back', 'progress', 'log').
--     The first six mirror the deployments.status taxonomy so a state
--     transition can be reconstructed by replaying the event log; 'progress'
--     is a non-terminal worker progress beat (for long-running deploys)
--     that does not change the deployment's status; 'log' is a redacted
--     worker log line. A future event type requires both an application
--     change and a migration so the database CHECK stays authoritative.
--   * No secrets in the schema. message stores a redacted human-readable
--     summary the worker observed; metadata stores redacted structured
--     details. The worker runs every value through the output redactor
--     before this is persisted, so tokens, API keys, cookies, and rendered
--     environment variable values can never reach either column. The
--     redaction layer is the audit/output redactor used by every other
--     event-emitting surface in the control plane.
--   * Both worker- and request-correlatable. request_id is the originating
--     customer request's id (empty when the writer is a pure worker beat
--     with no originating request, e.g. a periodic progress poll);
--     correlation_id is the worker job's correlation id, so a single
--     deployment's event log can be joined to the durable job's runtime
--     trail.
--   * Worker-observed timestamps. occurred_at is the wallclock the writer
--     observed the event; created_at is when the row was persisted. The
--     two diverge whenever a worker batches events or reconciles a
--     deployment after a restart, so the timeline is reconstructed by
--     ORDER BY occurred_at, not created_at.

CREATE TABLE deployment_events (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    deployment_id   text        NOT NULL,
    event_type      text        NOT NULL
                        CHECK (event_type IN (
                            'queued', 'running',
                            'succeeded', 'failed', 'cancelled', 'rolled_back',
                            'progress', 'log'
                        )),
    -- Redacted human-readable summary. The worker runs every value through
    -- the output redactor before write -- never tokens, API keys, cookies,
    -- or rendered environment variable values.
    message         text        NOT NULL DEFAULT '',
    -- Redacted structured event metadata. The audit/output redactor scrubs
    -- known secret-shaped keys and transport patterns before this is
    -- persisted, so the column never stores credential material.
    metadata        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    request_id      text        NOT NULL DEFAULT '',
    correlation_id  text        NOT NULL DEFAULT '',
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- No updated_at column: a deployment event is immutable once written.
    -- Tenant-scoped composite foreign key: the deployment row and the
    -- event row share an organization_id leg, so an event can never
    -- reference another tenant's deployment.
    FOREIGN KEY (organization_id, deployment_id)
        REFERENCES deployments (organization_id, id) ON DELETE CASCADE
);

-- Customer-facing list path: events of a single deployment in chronological
-- order. The composite predicate (organization_id, deployment_id) is the
-- tenant-scoped leg the repository's ListByDeployment uses; occurred_at ASC
-- is the order the timeline endpoint renders.
CREATE INDEX deployment_events_deployment_occurred_idx
    ON deployment_events (organization_id, deployment_id, occurred_at, id);

-- Tenant-scoped recency scan: most recent deployment events across all
-- deployments owned by an organization, newest first. Useful for the
-- "what is happening right now" operator view and for the future
-- audit cross-reference query.
CREATE INDEX deployment_events_org_occurred_idx
    ON deployment_events (organization_id, occurred_at DESC);

-- Append-only enforcement. The trigger rejects every UPDATE at the database
-- level, so a written event record can never be altered after the fact --
-- not by application code, not by an operator with a SQL console. DELETE is
-- intentionally not blocked here -- it must stay reachable through the
-- deployments / organizations ON DELETE CASCADE for tenant teardown, and the
-- store package exposes no row-level delete of its own.
CREATE FUNCTION deployment_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'deployment_events is append-only: UPDATE is not permitted'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER deployment_events_no_update
    BEFORE UPDATE ON deployment_events
    FOR EACH ROW EXECUTE FUNCTION deployment_events_reject_update();
