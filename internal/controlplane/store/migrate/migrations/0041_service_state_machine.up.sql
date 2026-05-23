-- Service lifecycle state machine. services.status is the current
-- source-of-truth lifecycle state; service_events is the append-only timeline
-- of accepted transitions.

ALTER TABLE services
    ADD COLUMN status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('pending', 'active', 'suspended', 'deleting', 'deleted'));

CREATE TABLE service_events (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    service_id      text        NOT NULL,
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
    FOREIGN KEY (organization_id, service_id)
        REFERENCES services (organization_id, id) ON DELETE CASCADE
);

CREATE INDEX service_events_service_occurred_idx
    ON service_events (organization_id, service_id, occurred_at, id);

CREATE INDEX service_events_org_occurred_idx
    ON service_events (organization_id, occurred_at DESC);

CREATE FUNCTION service_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'service_events is append-only: UPDATE is not permitted'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER service_events_no_update
    BEFORE UPDATE ON service_events
    FOR EACH ROW EXECUTE FUNCTION service_events_reject_update();
