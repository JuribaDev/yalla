-- Revert the container memory duration metering resource from quota_resource.

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
        'build_minutes',
        'http_requests',
        'http_response_bytes',
        'http_request_bytes',
        'http_bandwidth_total',
        'container_cpu_millicore_seconds'
    ));
