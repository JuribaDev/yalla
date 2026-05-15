-- Environment deletion scheduling: the soft-delete marker that lets the
-- control plane accept a "delete this environment" request without tearing
-- the environment and everything underneath it (services, secrets, audit
-- log) down synchronously.
--
-- This mirrors migration 0013 for projects, which itself mirrors migration
-- 0010 for organizations. The design rules are the same and intentionally
-- identical:
--
--   * Scheduled, not immediate. DELETE /v1/environments/{environment_id}
--     records the intent by stamping deletion_scheduled_at; the destructive
--     teardown -- the environments ON DELETE CASCADE that removes services
--     and the audit log -- is a later worker story. Until then the row, and
--     its audit trail, still exist, so the environment.delete audit event is
--     never cascaded away by the very request that wrote it.
--   * Nullable, and write-once in spirit. A NULL deletion_scheduled_at is a
--     live environment; a non-NULL value is one already scheduled for
--     teardown. The store layer treats a second schedule request as a typed
--     conflict rather than moving the timestamp.
--   * No secrets. The column is a timestamp; it carries no credential
--     material.
--
-- This column is the environments-table analogue of
-- projects.deletion_scheduled_at. A future "tear down the scheduled
-- environments" worker scans the same way the projects cleanup worker
-- will.

ALTER TABLE environments
    ADD COLUMN deletion_scheduled_at timestamptz;

-- The worker that performs environment teardown will scan for environments
-- pending deletion. A partial index keeps that scan off a sequential pass
-- while staying tiny, because the overwhelming majority of environments
-- are live (NULL).
CREATE INDEX environments_deletion_scheduled_at_idx
    ON environments (deletion_scheduled_at)
    WHERE deletion_scheduled_at IS NOT NULL;
