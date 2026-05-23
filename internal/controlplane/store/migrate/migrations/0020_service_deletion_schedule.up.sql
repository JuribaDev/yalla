-- Service deletion scheduling: the soft-delete marker that lets the
-- control plane accept a "delete this service" request without tearing
-- the service and the Dokploy object it provisions down synchronously.
--
-- This mirrors migration 0016 for environments, which itself mirrors
-- 0013 for projects and 0010 for organizations. The design rules are
-- the same and intentionally identical:
--
--   * Scheduled, not immediate. DELETE /v1/services/{service_id}
--     records the intent by stamping deletion_scheduled_at; the
--     destructive teardown -- the worker job that retires the Dokploy
--     object and the row's audit log -- is a later worker story. Until
--     then the row, and its audit trail, still exist, so the
--     service.delete audit event is never cascaded away by the very
--     request that wrote it.
--   * Nullable, and write-once in spirit. A NULL deletion_scheduled_at
--     is a live service; a non-NULL value is one already scheduled for
--     teardown. The store layer treats a second schedule request as a
--     typed conflict rather than moving the timestamp.
--   * No secrets. The column is a timestamp; it carries no credential
--     material.
--
-- This column is the services-table analogue of
-- environments.deletion_scheduled_at. A future "tear down the scheduled
-- services" worker scans the same way the environments cleanup worker
-- will.

ALTER TABLE services
    ADD COLUMN deletion_scheduled_at timestamptz;

-- The worker that performs service teardown will scan for services
-- pending deletion. A partial index keeps that scan off a sequential
-- pass while staying tiny, because the overwhelming majority of
-- services are live (NULL).
CREATE INDEX services_deletion_scheduled_at_idx
    ON services (deletion_scheduled_at)
    WHERE deletion_scheduled_at IS NOT NULL;
