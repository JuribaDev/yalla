-- Provisioning job table: the durable, source-of-truth queue of Dokploy
-- provisioning operations the worker executes on behalf of customer requests.
--
-- Design rules enforced here:
--
--   * Durable and idempotent. Every job carries an idempotency_key that is
--     unique within its organization, so a retried customer request enqueues
--     the same job exactly once -- never a duplicate Dokploy mutation.
--   * Lease-based. A job is claimed by exactly one worker at a time:
--     lease_owner and lease_deadline are set together while status is
--     'running' and cleared together otherwise, enforced by a CHECK. A crashed
--     worker's lease becomes reclaimable once lease_deadline passes.
--   * Explicit state machine. status moves through queued -> running ->
--     (succeeded | retrying | failed | dead_letter | cancelled), with
--     retrying -> running for the next attempt. The valid transitions are
--     enforced by application code (store.JobStatus.CanTransitionTo); the
--     table enforces the closed status set, that a terminal status always
--     carries finished_at while a non-terminal one never does, and that
--     attempts never exceeds the retry budget.
--   * Tenant-scoped. organization_id has a foreign key to organizations and
--     every resource-target column uses a COMPOSITE foreign key, so a job can
--     never target another tenant's project, environment, or service.
--   * No secrets. error_summary is run through the output redactor by the job
--     repository before it is persisted, and payload carries only non-secret
--     references (resource ids, desired version, flags) -- never tokens, API
--     keys, cookies, or rendered environment variable values.

CREATE TABLE provisioning_jobs (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    job_type        text        NOT NULL CHECK (length(job_type) > 0),
    -- Resource targets. All optional: a job may target only the organization
    -- (e.g. ensure_dokploy_organization) or walk the hierarchy down to a
    -- single service. Each composite foreign key pins the target to the job's
    -- own tenant, so a job can never reference another organization's resource.
    project_id      text,
    environment_id  text,
    service_id      text,
    -- The desired-state version this job is converging the resource toward. It
    -- is optimistic-concurrency aware: a newer job supersedes an older one.
    desired_version bigint      NOT NULL DEFAULT 0 CHECK (desired_version >= 0),
    -- One idempotency key enqueues exactly one job per organization, so a
    -- retried customer request never produces a duplicate Dokploy mutation.
    idempotency_key text        NOT NULL CHECK (length(idempotency_key) > 0),
    status          text        NOT NULL DEFAULT 'queued'
                        CHECK (status IN (
                            'queued', 'running', 'retrying',
                            'succeeded', 'failed', 'cancelled', 'dead_letter'
                        )),
    attempts        integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts    integer     NOT NULL DEFAULT 20 CHECK (max_attempts > 0),
    -- Lease columns: set together while the job is running, cleared together
    -- otherwise. A worker claims a job by taking the lease; the lease becomes
    -- reclaimable once lease_deadline passes.
    lease_owner     text        NOT NULL DEFAULT '',
    lease_deadline  timestamptz,
    -- The earliest time the job is eligible to be claimed. A retry pushes this
    -- into the future so backoff is durable across worker restarts.
    next_run_at     timestamptz NOT NULL DEFAULT now(),
    -- Redacted, human-readable summary of the most recent failure. The job
    -- repository runs every value through the output redactor before it is
    -- stored, so the column can never hold a token or API key surfaced by a
    -- Dokploy error string.
    error_summary   text        NOT NULL DEFAULT '',
    -- Non-secret job payload: resource references, flags, desired-state hints.
    -- Never tokens, API keys, cookies, or rendered environment variable values.
    payload         jsonb       NOT NULL DEFAULT '{}'::jsonb,
    request_id      text        NOT NULL DEFAULT '',
    correlation_id  text        NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz,
    -- A terminal job always carries finished_at; a non-terminal one never does.
    CONSTRAINT provisioning_jobs_finished_consistent CHECK (
        (status IN ('succeeded', 'failed', 'cancelled', 'dead_letter') AND finished_at IS NOT NULL) OR
        (status IN ('queued', 'running', 'retrying') AND finished_at IS NULL)
    ),
    -- The lease is held exactly while the job is running.
    CONSTRAINT provisioning_jobs_lease_consistent CHECK (
        (status =  'running' AND lease_owner <> '' AND lease_deadline IS NOT NULL) OR
        (status <> 'running' AND lease_owner =  '' AND lease_deadline IS NULL)
    ),
    -- attempts can never exceed the retry budget.
    CONSTRAINT provisioning_jobs_attempts_bounded CHECK (attempts <= max_attempts),
    -- Idempotency: a given key enqueues exactly one job per organization.
    UNIQUE (organization_id, idempotency_key),
    -- Composite-FK target: job_attempts and quota_reservations reference a job
    -- by (organization_id, id) so the link can never cross a tenant boundary.
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, environment_id)
        REFERENCES environments (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, service_id)
        REFERENCES services (organization_id, id) ON DELETE CASCADE
);

-- The worker claims the oldest eligible job: queued or retrying and due now.
-- The partial index keeps that hot path off a sequential scan.
CREATE INDEX provisioning_jobs_claim_idx
    ON provisioning_jobs (next_run_at)
    WHERE status IN ('queued', 'retrying');

-- The lease reaper scans for running jobs whose lease has expired.
CREATE INDEX provisioning_jobs_lease_deadline_idx
    ON provisioning_jobs (lease_deadline)
    WHERE status = 'running';

-- Tenant-scoped listing: recent jobs for an organization, optionally by status.
CREATE INDEX provisioning_jobs_org_created_idx
    ON provisioning_jobs (organization_id, created_at DESC);
CREATE INDEX provisioning_jobs_org_status_idx
    ON provisioning_jobs (organization_id, status);

-- Reverse lookups from a targeted resource to its jobs.
CREATE INDEX provisioning_jobs_service_id_idx
    ON provisioning_jobs (service_id) WHERE service_id IS NOT NULL;
CREATE INDEX provisioning_jobs_environment_id_idx
    ON provisioning_jobs (environment_id) WHERE environment_id IS NOT NULL;
CREATE INDEX provisioning_jobs_project_id_idx
    ON provisioning_jobs (project_id) WHERE project_id IS NOT NULL;

CREATE TRIGGER provisioning_jobs_set_updated_at
    BEFORE UPDATE ON provisioning_jobs
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Wire up the foreign key that migration 0006 (quota_policy_schema) deferred:
-- a reservation's job_id must name a provisioning job in the SAME tenant. The
-- composite key is MATCH SIMPLE, so it is enforced only when job_id is set.
ALTER TABLE quota_reservations
    ADD CONSTRAINT quota_reservations_job_fk
    FOREIGN KEY (organization_id, job_id)
    REFERENCES provisioning_jobs (organization_id, id);
