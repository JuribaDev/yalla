-- Quota reservation lifecycle state machine. quota_reservations.status already
-- carries the current source-of-truth lifecycle state; quota_reservation_events
-- is the append-only timeline of accepted transitions.

CREATE TABLE quota_reservation_events (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    reservation_id  text        NOT NULL,
    event_type      text        NOT NULL
                        CHECK (event_type IN ('active', 'committed', 'released', 'expired')),
    message         text        NOT NULL DEFAULT '',
    metadata        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    request_id      text        NOT NULL DEFAULT '',
    correlation_id  text        NOT NULL DEFAULT '',
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, reservation_id)
        REFERENCES quota_reservations (organization_id, id) ON DELETE CASCADE
);

CREATE INDEX quota_reservation_events_reservation_occurred_idx
    ON quota_reservation_events (organization_id, reservation_id, occurred_at, id);

CREATE INDEX quota_reservation_events_org_occurred_idx
    ON quota_reservation_events (organization_id, occurred_at DESC);

CREATE FUNCTION quota_reservation_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'quota_reservation_events is append-only: UPDATE is not permitted'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER quota_reservation_events_no_update
    BEFORE UPDATE ON quota_reservation_events
    FOR EACH ROW EXECUTE FUNCTION quota_reservation_events_reject_update();
