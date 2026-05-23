-- Revert the api_keys addition to the quota_resource DOMAIN by
-- restoring the closed set from migration 0026 verbatim.
--
-- This is a structural narrowing: any row whose resource column
-- holds 'api_keys' will fail the restored CHECK constraint.
-- Migration runners must surface that as a hard failure, which is
-- the correct behaviour — silently dropping the api_keys rows would
-- lose audit-relevant state. The expectation is that an operator
-- deletes or migrates those rows before running the down.

DO $$
DECLARE
    cname text;
BEGIN
    SELECT conname
      INTO cname
      FROM pg_constraint
     WHERE contypid = 'quota_resource'::regtype
       AND contype  = 'c'
     LIMIT 1;
    IF cname IS NOT NULL THEN
        EXECUTE format('ALTER DOMAIN quota_resource DROP CONSTRAINT %I', cname);
    END IF;
END;
$$;

ALTER DOMAIN quota_resource ADD CONSTRAINT quota_resource_check
    CHECK (VALUE IN (
        'projects',
        'environments',
        'services',
        'applications',
        'compose_stacks',
        'databases',
        'domains',
        'preview_environments',
        'cpu_millicores',
        'memory_mb',
        'storage_gb',
        'backups',
        'backup_schedules',
        'concurrent_deployments',
        'monthly_deployments'
    ));
