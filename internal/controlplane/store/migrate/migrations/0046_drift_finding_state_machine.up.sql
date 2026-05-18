-- Drift finding lifecycle state machine. drift_findings.status is the
-- explicit source of truth for accepted lifecycle transitions; resolved_at and
-- resolved_by_actor_id remain the resolution stamps for terminal rows.
-- drift_finding_events is the append-only timeline of accepted transitions.

ALTER TABLE drift_findings
    ADD COLUMN status text NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'resolved'));

UPDATE drift_findings
   SET status = 'resolved'
 WHERE resolved_at IS NOT NULL;

ALTER TABLE drift_findings
    ADD CONSTRAINT drift_findings_status_resolution_consistent CHECK (
        (status = 'open' AND resolved_at IS NULL AND resolved_by_actor_id = '') OR
        (status = 'resolved' AND resolved_at IS NOT NULL AND length(resolved_by_actor_id) > 0)
    );

CREATE TABLE drift_finding_events (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    finding_id      text        NOT NULL,
    event_type      text        NOT NULL
                        CHECK (event_type IN ('open', 'resolved')),
    message         text        NOT NULL DEFAULT '',
    metadata        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    request_id      text        NOT NULL DEFAULT '',
    correlation_id  text        NOT NULL DEFAULT '',
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, finding_id)
        REFERENCES drift_findings (organization_id, id) ON DELETE CASCADE
);

CREATE INDEX drift_finding_events_finding_occurred_idx
    ON drift_finding_events (organization_id, finding_id, occurred_at, id);

CREATE INDEX drift_finding_events_org_occurred_idx
    ON drift_finding_events (organization_id, occurred_at DESC);

CREATE FUNCTION drift_finding_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'drift_finding_events is append-only: UPDATE is not permitted'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER drift_finding_events_no_update
    BEFORE UPDATE ON drift_finding_events
    FOR EACH ROW EXECUTE FUNCTION drift_finding_events_reject_update();
