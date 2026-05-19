-- Add billing-grade deployment metering resources to quota_resource.
--
-- deployments is the successful deployment counter emitted from Yalla's
-- deployment_events timeline. failed_deployments is the failure counter so
-- pricing entitlements can distinguish failed deploy attempts from successful
-- deploys. build_minutes is the duration dimension emitted from worker job
-- timestamps and job_attempts rows.

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
        'api_keys',
        'members',
        'concurrent_deployments',
        'monthly_deployments',
        'deployments',
        'failed_deployments',
        'build_minutes'
    ));
