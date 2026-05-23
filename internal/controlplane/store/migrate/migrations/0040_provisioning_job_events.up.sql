-- Provisioning job events: the append-only lifecycle timeline for the durable
-- provisioning_jobs queue. A provisioning_jobs row carries the current status;
-- a provisioning_job_events row records each accepted state transition with
-- actor, request, previous state, next state, and redacted reason metadata.
--
-- Design rules enforced here:
--
--   * Append-only. provisioning_job_events has no updated_at column and no
--     UPDATE path. A BEFORE UPDATE trigger rejects every update at the database
--     level, matching audit_events, deployment_events, and job_attempts.
--   * Tenant-scoped at the database. The composite FK
--     (organization_id, job_id) references provisioning_jobs
--     (organization_id, id), so an event row can never sit under a foreign
--     tenant's job.
--   * Event type is closed-set. The event_type column mirrors
--     provisioning_jobs.status exactly, so replaying the timeline reconstructs
--     the accepted state transitions.
--   * No secrets in the schema. message and metadata are redacted by the store
--     transition path before persistence.

CREATE TABLE provisioning_job_events (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    job_id          text        NOT NULL,
    event_type      text        NOT NULL
                        CHECK (event_type IN (
                            'queued', 'running', 'retrying',
                            'succeeded', 'failed', 'cancelled', 'dead_letter'
                        )),
    message         text        NOT NULL DEFAULT '',
    metadata        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    request_id      text        NOT NULL DEFAULT '',
    correlation_id  text        NOT NULL DEFAULT '',
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, job_id)
        REFERENCES provisioning_jobs (organization_id, id) ON DELETE CASCADE
);

CREATE INDEX provisioning_job_events_job_occurred_idx
    ON provisioning_job_events (organization_id, job_id, occurred_at, id);

CREATE INDEX provisioning_job_events_org_occurred_idx
    ON provisioning_job_events (organization_id, occurred_at DESC);

CREATE FUNCTION provisioning_job_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'provisioning_job_events is append-only: UPDATE is not permitted'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER provisioning_job_events_no_update
    BEFORE UPDATE ON provisioning_job_events
    FOR EACH ROW EXECUTE FUNCTION provisioning_job_events_reject_update();
