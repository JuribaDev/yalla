-- Break-glass lifecycle state machine. break_glass_sessions.status is the
-- explicit source of truth for accepted lifecycle transitions; expires_at
-- remains the time-bound guard for active sessions. break_glass_session_events
-- is the append-only timeline of accepted transitions.

ALTER TABLE break_glass_sessions
    ADD COLUMN status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked', 'expired'));

UPDATE break_glass_sessions
   SET status = 'revoked'
 WHERE revoked_at IS NOT NULL;

UPDATE break_glass_sessions
   SET status = 'expired'
 WHERE revoked_at IS NULL
   AND expires_at <= now();

ALTER TABLE break_glass_sessions
    ADD CONSTRAINT break_glass_sessions_organization_id_id_unique
    UNIQUE (organization_id, id);

DROP TRIGGER break_glass_sessions_no_rewrite ON break_glass_sessions;
DROP FUNCTION break_glass_sessions_reject_rewrite();

-- The state-machine repository is the only normal writer for status changes;
-- the append-mostly trigger allows only status and revocation columns to move.
CREATE FUNCTION break_glass_sessions_reject_rewrite() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF length(NEW.reason) = 0 THEN
        RAISE EXCEPTION 'break_glass_sessions.reason must remain set'
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW.id              <> OLD.id              OR
       NEW.organization_id <> OLD.organization_id OR
       NEW.actor_id        <> OLD.actor_id        OR
       NEW.actor_kind      <> OLD.actor_kind      OR
       NEW.reason          <> OLD.reason          OR
       NEW.started_at      <> OLD.started_at      OR
       NEW.expires_at      <> OLD.expires_at      OR
       NEW.request_id      <> OLD.request_id      OR
       NEW.correlation_id  <> OLD.correlation_id  THEN
        RAISE EXCEPTION 'break_glass_sessions is append-mostly: UPDATE may only set lifecycle columns'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER break_glass_sessions_no_rewrite
    BEFORE UPDATE ON break_glass_sessions
    FOR EACH ROW EXECUTE FUNCTION break_glass_sessions_reject_rewrite();

CREATE TABLE break_glass_session_events (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    session_id      text        NOT NULL,
    event_type      text        NOT NULL
                        CHECK (event_type IN ('active', 'revoked', 'expired')),
    message         text        NOT NULL DEFAULT '',
    metadata        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    request_id      text        NOT NULL DEFAULT '',
    correlation_id  text        NOT NULL DEFAULT '',
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, session_id)
        REFERENCES break_glass_sessions (organization_id, id) ON DELETE CASCADE
);

CREATE INDEX break_glass_session_events_session_occurred_idx
    ON break_glass_session_events (organization_id, session_id, occurred_at, id);

CREATE INDEX break_glass_session_events_org_occurred_idx
    ON break_glass_session_events (organization_id, occurred_at DESC);

CREATE FUNCTION break_glass_session_events_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'break_glass_session_events is append-only: UPDATE is not permitted'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER break_glass_session_events_no_update
    BEFORE UPDATE ON break_glass_session_events
    FOR EACH ROW EXECUTE FUNCTION break_glass_session_events_reject_update();
