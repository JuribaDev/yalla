-- Project lifecycle state machine. projects.status is the current
-- source-of-truth lifecycle state; project_events is the append-only timeline
-- of accepted transitions.

ALTER TABLE projects
    ADD COLUMN status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('pending', 'active', 'suspended', 'deleting', 'deleted'));

CREATE TABLE project_events (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    project_id      text        NOT NULL,
    event_type      text        NOT NULL
                        CHECK (event_type IN (
                            'pending', 'active', 'suspended', 'deleting', 'deleted'
                        )),
    message         text        NOT NULL DEFAULT '',
    metadata        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    request_id      text        NOT NULL DEFAULT '',
    correlation_id  text        NOT NULL DEFAULT '',
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects (organization_id, id) ON DELETE CASCADE
);

CREATE INDEX project_events_project_occurred_idx
    ON project_events (organization_id, project_id, occurred_at, id);

CREATE INDEX project_events_org_occurred_idx
    ON project_events (organization_id, occurred_at DESC);

CREATE FUNCTION project_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'project_events is append-only: UPDATE is not permitted'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER project_events_no_update
    BEFORE UPDATE ON project_events
    FOR EACH ROW EXECUTE FUNCTION project_events_reject_update();
