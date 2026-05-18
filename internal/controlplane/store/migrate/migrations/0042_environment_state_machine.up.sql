-- Environment lifecycle state machine. environments.status is the current
-- source-of-truth lifecycle state; environment_events is the append-only
-- timeline of accepted transitions.

ALTER TABLE environments
    ADD COLUMN status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('pending', 'active', 'suspended', 'deleting', 'deleted'));

CREATE TABLE environment_events (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    environment_id  text        NOT NULL,
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
    FOREIGN KEY (organization_id, environment_id)
        REFERENCES environments (organization_id, id) ON DELETE CASCADE
);

CREATE INDEX environment_events_environment_occurred_idx
    ON environment_events (organization_id, environment_id, occurred_at, id);

CREATE INDEX environment_events_org_occurred_idx
    ON environment_events (organization_id, occurred_at DESC);

CREATE FUNCTION environment_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'environment_events is append-only: UPDATE is not permitted'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER environment_events_no_update
    BEFORE UPDATE ON environment_events
    FOR EACH ROW EXECUTE FUNCTION environment_events_reject_update();
