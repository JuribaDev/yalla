-- Job attempts: the append-only history of execution attempts a worker made
-- against a provisioning_jobs row. A provisioning_jobs row carries the
-- aggregate state (current status, current attempts counter, current lease);
-- a job_attempts row is one terminal record on the history that produced
-- that aggregate. The customer-facing "show me why this job retried" and
-- internal "show me the runtime trail of job_..." views read from this table,
-- ordered by attempt_number ASC so the operator sees the job unfold forward
-- in time.
--
-- Design rules enforced here:
--
--   * Append-only. job_attempts has no updated_at column and no UPDATE path.
--     A BEFORE UPDATE trigger rejects every update at the database level, so
--     a written attempt record can never be altered after the fact -- not by
--     application code, not by an operator with a SQL console. The reasoning
--     mirrors audit_events and deployment_events: an attempt is a forensic
--     record of what the worker observed when it released the lease;
--     rewriting it after the fact would let a buggy or compromised writer
--     hide a failure. Row-level DELETE is reachable only through ON DELETE
--     CASCADE when the parent provisioning_jobs row is removed (which itself
--     cascades from the organization), so a tenant teardown still clears the
--     table; the store package exposes no row-level delete.
--   * Tenant-scoped at the database. The composite FK
--     (organization_id, job_id) references the matching composite UNIQUE
--     (organization_id, id) on provisioning_jobs with ON DELETE CASCADE, so
--     a job teardown cascades through its attempt history and an attempt row
--     can never sit under a foreign tenant's job. The organization_id leg
--     is persisted directly here (not derived through the FK at read time)
--     so every customer-facing read can be tenant-scoped by a simple
--     WHERE organization_id = $1 predicate; the FK is the database's
--     belt-and-braces guarantee that the persisted leg matches the parent
--     job's organization_id.
--   * Status is a closed terminal set. The status column confines the value
--     to the four terminal kinds a worker may observe at the end of an
--     attempt ('succeeded', 'failed', 'cancelled', 'timed_out'). A 'running'
--     attempt is not persisted here -- the running state lives on the parent
--     provisioning_jobs row's lease columns -- so a job_attempts row is
--     always a complete, immutable post-mortem of a finished attempt. A
--     future status requires both an application change and a migration so
--     the database CHECK stays authoritative.
--   * Attempt number is unique per job. The
--     UNIQUE (organization_id, job_id, attempt_number) constraint means a
--     retried claim that re-uses the parent job's attempts counter is a
--     deterministic Conflict, never a duplicate row; an attempt number of
--     zero is rejected by CHECK (attempt_number > 0) -- a worker that has
--     never claimed the job has no attempt to record.
--   * Worker identity is recorded but the lease state is not. worker_id
--     is the lease_owner the worker held during the attempt; lease_deadline
--     and other lease bookkeeping live on the parent job row while the
--     attempt is running, and the attempt row is written only once the
--     lease is released (succeeded/failed/cancelled/timed_out).
--   * finished_at never predates started_at. The CHECK
--     (finished_at >= started_at) constraint pins the timestamps so a
--     worker that supplies wallclock observations cannot persist an
--     impossibly-ordered attempt -- the duration of an attempt is always
--     a non-negative interval.
--   * No secrets in the schema. error_summary stores a redacted
--     human-readable summary the worker observed; error_code stores a
--     short non-secret classification. The repository runs every value
--     through the output redactor before this is persisted, so tokens,
--     API keys, cookies, and rendered environment variable values can
--     never reach either column.
--   * Both worker- and request-correlatable. request_id is the originating
--     customer request's id (empty when the attempt is a pure worker-side
--     retry with no originating request); correlation_id is the worker
--     run's correlation id, so a single job's attempt history can be
--     joined to the worker's structured log and trace records.

CREATE TABLE job_attempts (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    job_id          text        NOT NULL,
    attempt_number  integer     NOT NULL CHECK (attempt_number > 0),
    worker_id       text        NOT NULL CHECK (length(worker_id) > 0),
    status          text        NOT NULL
                        CHECK (status IN (
                            'succeeded', 'failed', 'cancelled', 'timed_out'
                        )),
    error_summary   text        NOT NULL DEFAULT '',
    error_code      text        NOT NULL DEFAULT '',
    request_id      text        NOT NULL DEFAULT '',
    correlation_id  text        NOT NULL DEFAULT '',
    started_at      timestamptz NOT NULL,
    finished_at     timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- No updated_at column: a job attempt is immutable once written.
    -- Tenant-scoped composite foreign key: the provisioning_jobs row and the
    -- attempt row share an organization_id leg, so an attempt can never
    -- reference another tenant's job.
    FOREIGN KEY (organization_id, job_id)
        REFERENCES provisioning_jobs (organization_id, id) ON DELETE CASCADE,
    -- A given (job, attempt_number) tuple is unique: a worker that re-uses
    -- the parent job's attempts counter is rejected as a Conflict.
    UNIQUE (organization_id, job_id, attempt_number),
    -- An attempt's duration is always a non-negative interval.
    CONSTRAINT job_attempts_finished_after_started
        CHECK (finished_at >= started_at)
);

-- Customer-facing list path: attempts of a single job in chronological order.
-- The composite predicate (organization_id, job_id) is the tenant-scoped leg
-- the repository's ListByJob uses; attempt_number ASC is the order the
-- timeline endpoint renders.
CREATE INDEX job_attempts_job_attempt_idx
    ON job_attempts (organization_id, job_id, attempt_number);

-- Tenant-scoped recency scan: most recently finished attempts across all
-- jobs owned by an organization, newest first. Useful for the "what failed
-- recently" operator view and for the future audit cross-reference query.
CREATE INDEX job_attempts_org_finished_idx
    ON job_attempts (organization_id, finished_at DESC);

-- Append-only enforcement. The trigger rejects every UPDATE at the database
-- level, so a written attempt record can never be altered after the fact --
-- not by application code, not by an operator with a SQL console. DELETE is
-- intentionally not blocked here -- it must stay reachable through the
-- provisioning_jobs / organizations ON DELETE CASCADE for tenant teardown,
-- and the store package exposes no row-level delete of its own.
CREATE FUNCTION job_attempts_reject_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'job_attempts is append-only: UPDATE is not permitted'
        USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER job_attempts_no_update
    BEFORE UPDATE ON job_attempts
    FOR EACH ROW EXECUTE FUNCTION job_attempts_reject_update();
