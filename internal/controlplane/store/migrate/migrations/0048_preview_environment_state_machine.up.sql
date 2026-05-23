-- Preview environment lifecycle state machine. preview_environments.status was
-- introduced with the table; this migration adds the append-only transition
-- timeline used to audit every accepted state change.

CREATE TABLE preview_environment_events (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    preview_id      text        NOT NULL,
    event_type      text        NOT NULL
                        CHECK (event_type IN (
                            'pending', 'provisioning', 'ready', 'deleting', 'deleted', 'failed'
                        )),
    message         text        NOT NULL DEFAULT '',
    metadata        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    request_id      text        NOT NULL DEFAULT '',
    correlation_id  text        NOT NULL DEFAULT '',
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, preview_id)
        REFERENCES preview_environments (organization_id, id) ON DELETE CASCADE
);

CREATE INDEX preview_environment_events_preview_occurred_idx
    ON preview_environment_events (organization_id, preview_id, occurred_at, id);

CREATE INDEX preview_environment_events_org_occurred_idx
    ON preview_environment_events (organization_id, occurred_at DESC);

CREATE FUNCTION preview_environment_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'preview_environment_events is append-only: UPDATE is not permitted'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER preview_environment_events_no_update
    BEFORE UPDATE ON preview_environment_events
    FOR EACH ROW EXECUTE FUNCTION preview_environment_events_reject_update();
