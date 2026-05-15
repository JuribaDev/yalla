-- Break-glass sessions: the durable record of every internal-support session
-- in which an admin uses their support capability to access another tenant's
-- data. The table is the source of truth for "who reached into which tenant,
-- when, why, and for how long".
--
-- Design rules enforced here:
--
--   * Time-bounded. Every session carries a non-null expires_at strictly
--     after started_at, so a session always has an expiration and the
--     authorization layer can deny a request whose session has elapsed
--     without trusting application-side bookkeeping.
--
--   * Reason-required. reason is a non-empty justification string. A row
--     cannot be created without it, so the audit trail names not only the
--     actor and the target tenant but also why access was granted.
--
--   * Append-mostly. Once created the only mutation the application
--     performs is revocation: revoked_at and revoked_by are set to mark a
--     session as ended early. The schema accepts no other update; rewriting
--     a session's reason or expiration would corrupt the trail. Updates are
--     constrained by a CHECK so an UPDATE cannot blank an existing reason
--     or rewrite the actor or target.
--
--   * Tenant-scoped target. organization_id names the tenant the admin
--     reached into. A foreign key with ON DELETE CASCADE removes a row
--     when its target tenant is deleted, matching how audit_events is
--     partitioned. The actor is identified by actor_id/actor_kind; the
--     actor's own home organization is captured in actor_organization_id
--     for the audit projection but carries no foreign key (the actor is
--     usually a Yalla support principal who lives outside the target
--     tenant).
--
--   * No secrets in the schema. A break-glass row stores only structural
--     identifiers, a free-form reason, request/correlation ids, and times.
--     The reason field is operator-authored and the audit service redacts
--     metadata before it is ever handed to the audit log; this column is
--     for the human-readable justification (incident id, ticket id) and is
--     not expected to carry credential material. A separate redaction
--     guard at the service layer scrubs the reason before persistence.
--
--   * Optimistic concurrency. version is a bigint maintained by the
--     bump_version() trigger from migration 0011, mirroring projects /
--     environments / grants / variables.

CREATE TABLE break_glass_sessions (
    id                       text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id          text        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    actor_id                 text        NOT NULL CHECK (length(actor_id) > 0),
    actor_kind               text        NOT NULL CHECK (actor_kind IN ('usr', 'sa')),
    actor_organization_id    text        NOT NULL DEFAULT '',
    reason                   text        NOT NULL CHECK (length(reason) > 0),
    started_at               timestamptz NOT NULL,
    expires_at               timestamptz NOT NULL,
    revoked_at               timestamptz,
    revoked_by_id            text        NOT NULL DEFAULT '',
    revoked_by_kind          text        NOT NULL DEFAULT ''
                                CHECK (revoked_by_kind IN ('', 'usr', 'sa')),
    request_id               text        NOT NULL DEFAULT '',
    correlation_id           text        NOT NULL DEFAULT '',
    ip_address               text        NOT NULL DEFAULT '',
    user_agent               text        NOT NULL DEFAULT '',
    version                  bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at > started_at)
);

CREATE INDEX break_glass_sessions_org_started_idx
    ON break_glass_sessions (organization_id, started_at DESC);
CREATE INDEX break_glass_sessions_actor_idx
    ON break_glass_sessions (actor_id, started_at DESC)
    WHERE actor_id <> '';
CREATE INDEX break_glass_sessions_active_idx
    ON break_glass_sessions (organization_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE TRIGGER break_glass_sessions_set_updated_at
    BEFORE UPDATE ON break_glass_sessions
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER break_glass_sessions_bump_version
    BEFORE UPDATE ON break_glass_sessions
    FOR EACH ROW EXECUTE FUNCTION bump_version();

-- break_glass_sessions_reject_rewrite enforces append-mostly semantics: an
-- UPDATE must not blank an existing reason, change the actor, the target, the
-- started_at, the original expires_at, or the request/correlation ids. The
-- only mutation the application performs is marking a session revoked
-- (revoked_at / revoked_by_*); rewriting the rest would corrupt the trail.
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
