-- API key lifecycle state machine. api_keys.status is the current source of
-- truth for explicit key lifecycle; expires_at remains the time-bound
-- authentication guard for active keys. api_key_events is the append-only
-- timeline of accepted transitions.

ALTER TABLE api_keys
    ADD COLUMN status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked', 'expired'));

UPDATE api_keys
   SET status = 'revoked'
 WHERE revoked_at IS NOT NULL;

UPDATE api_keys
   SET status = 'expired'
 WHERE revoked_at IS NULL
   AND expires_at IS NOT NULL
   AND expires_at <= now();

CREATE TABLE api_key_events (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    key_id          text        NOT NULL,
    event_type      text        NOT NULL
                        CHECK (event_type IN ('active', 'revoked', 'expired')),
    message         text        NOT NULL DEFAULT '',
    metadata        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    request_id      text        NOT NULL DEFAULT '',
    correlation_id  text        NOT NULL DEFAULT '',
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, key_id)
        REFERENCES api_keys (organization_id, id) ON DELETE CASCADE
);

CREATE INDEX api_key_events_key_occurred_idx
    ON api_key_events (organization_id, key_id, occurred_at, id);

CREATE INDEX api_key_events_org_occurred_idx
    ON api_key_events (organization_id, occurred_at DESC);

CREATE FUNCTION api_key_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'api_key_events is append-only: UPDATE is not permitted'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER api_key_events_no_update
    BEFORE UPDATE ON api_key_events
    FOR EACH ROW EXECUTE FUNCTION api_key_events_reject_update();
