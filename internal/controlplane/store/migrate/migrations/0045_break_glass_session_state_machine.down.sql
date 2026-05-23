DROP TRIGGER IF EXISTS break_glass_session_events_no_update ON break_glass_session_events;
DROP FUNCTION IF EXISTS break_glass_session_events_reject_update();
DROP TABLE IF EXISTS break_glass_session_events;

DROP TRIGGER IF EXISTS break_glass_sessions_no_rewrite ON break_glass_sessions;
DROP FUNCTION IF EXISTS break_glass_sessions_reject_rewrite();

ALTER TABLE break_glass_sessions
    DROP CONSTRAINT IF EXISTS break_glass_sessions_organization_id_id_unique;

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
        RAISE EXCEPTION 'break_glass_sessions is append-mostly: UPDATE may only set revocation columns'
            USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER break_glass_sessions_no_rewrite
    BEFORE UPDATE ON break_glass_sessions
    FOR EACH ROW EXECUTE FUNCTION break_glass_sessions_reject_rewrite();

ALTER TABLE break_glass_sessions
    DROP COLUMN IF EXISTS status;
