-- Project deletion scheduling: the soft-delete marker that lets the control
-- plane accept a "delete this project" request without tearing the project
-- and everything underneath it (environments, services, secrets, audit log)
-- down synchronously.
--
-- This mirrors migration 0010 for organizations. The design rules are the
-- same and intentionally identical:
--
--   * Scheduled, not immediate. DELETE /v1/projects/{project_id} records the
--     intent by stamping deletion_scheduled_at; the destructive teardown --
--     the projects ON DELETE CASCADE that removes environments, services,
--     and the audit log -- is a later worker story. Until then the row, and
--     its audit trail, still exist, so the project.delete audit event is
--     never cascaded away by the very request that wrote it.
--   * Nullable, and write-once in spirit. A NULL deletion_scheduled_at is a
--     live project; a non-NULL value is one already scheduled for teardown.
--     The store layer treats a second schedule request as a typed conflict
--     rather than moving the timestamp.
--   * No secrets. The column is a timestamp; it carries no credential
--     material.
--
-- This column is the projects-table analogue of organizations.deletion_scheduled_at.
-- A future "tear down the scheduled projects" worker scans the same way the
-- organizations cleanup worker will.

ALTER TABLE projects
    ADD COLUMN deletion_scheduled_at timestamptz;

-- The worker that performs project teardown will scan for projects pending
-- deletion. A partial index keeps that scan off a sequential pass while
-- staying tiny, because the overwhelming majority of projects are live
-- (NULL).
CREATE INDEX projects_deletion_scheduled_at_idx
    ON projects (deletion_scheduled_at)
    WHERE deletion_scheduled_at IS NOT NULL;
