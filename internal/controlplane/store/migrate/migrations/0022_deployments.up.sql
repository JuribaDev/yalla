-- Deployments: the source-of-truth record of a customer-initiated deploy
-- of a single service. A deployment is a state-bearing resource the worker
-- converges toward Dokploy through a durable provisioning job; the row
-- captures the customer intent (which service, which source ref, which
-- principal asked for it), the immutable correlation identifiers the
-- audit trail and the worker job share, and the current lifecycle status.
--
-- The Dokploy provisioning job itself lives in provisioning_jobs and is
-- linked to this row by deployment_id (set when the worker enqueues the
-- mirror job inside the SAME transaction as the deployments insert). The
-- worker mutates the deployments.status column as it observes the job
-- and the upstream Dokploy state — the customer never writes status.
--
-- Design rules enforced here:
--
--   * Tenant-scoped at the database. The composite FK
--     (organization_id, service_id) references the matching composite
--     UNIQUE (organization_id, id) on services with ON DELETE CASCADE,
--     so a service teardown cascades through its deployment history and
--     a deployment row can never sit under a foreign tenant's service.
--     The parent project_id and environment_id legs are persisted here
--     because customer reads filter by them — but each leg carries its
--     own composite FK (organization_id, project_id) and
--     (organization_id, environment_id) so the deployment can never
--     reference another tenant's parent.
--   * Source intent is closed-set. The source column confines the value
--     to a small Dokploy-aligned taxonomy ('git', 'image', 'manual') the
--     application validates before any database work; the database
--     CHECK is the belt-and-braces.
--   * Status is closed-set and lifecycle-aware. status moves through
--     'queued' -> 'running' -> ('succeeded' | 'failed' | 'cancelled' |
--     'rolled_back'), with the worker as the only writer of non-queued
--     values. The set mirrors provisioning_jobs.status semantics so the
--     customer-visible deployment status and the internal job status
--     converge through the same state machine. A terminal status always
--     carries finished_at; a non-terminal one never does.
--   * Idempotency is per-organization. idempotency_key is unique within
--     organization_id (matching provisioning_jobs's idempotency
--     contract), so a retried customer request enqueues the same
--     deployment exactly once.
--   * Optimistic concurrency. version is the database-owned
--     optimistic-concurrency token: it starts at 1 on INSERT and is
--     bumped by the bump_version() trigger from migration 0011 on every
--     UPDATE, mirroring services / environments / projects / variables.
--   * No secrets in the schema. error_message stores the most recent
--     redacted failure summary the worker observed; the worker runs
--     every value through the output redactor before it is persisted,
--     so tokens, API keys, cookies, and rendered environment variable
--     values can never reach the column. The deployment itself stores
--     only structural identifiers and the source ref (a branch / commit
--     / tag / image reference) — never credentials.

CREATE TABLE deployments (
    id              text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id text        NOT NULL,
    project_id      text        NOT NULL,
    environment_id  text        NOT NULL,
    service_id      text        NOT NULL,
    source          text        NOT NULL CHECK (source IN ('git', 'image', 'manual')),
    source_ref      text        NOT NULL DEFAULT '',
    status          text        NOT NULL DEFAULT 'queued'
                        CHECK (status IN (
                            'queued', 'running',
                            'succeeded', 'failed', 'cancelled', 'rolled_back'
                        )),
    requested_by    text        NOT NULL CHECK (length(requested_by) > 0),
    -- One idempotency key enqueues exactly one deployment per organization,
    -- so a retried customer request never produces a duplicate Dokploy
    -- mutation.
    idempotency_key text        NOT NULL CHECK (length(idempotency_key) > 0),
    -- The worker observes the upstream Dokploy state and writes back the
    -- most recent redacted failure summary when a deployment fails. The
    -- column is always redacted before write — never tokens, API keys,
    -- or rendered environment variable values.
    error_code      text        NOT NULL DEFAULT '',
    error_message   text        NOT NULL DEFAULT '',
    version         bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    request_id      text        NOT NULL DEFAULT '',
    correlation_id  text        NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz,
    -- A terminal status always carries finished_at; a non-terminal one
    -- never does. Mirrors provisioning_jobs_finished_consistent.
    CONSTRAINT deployments_finished_consistent CHECK (
        (status IN ('succeeded', 'failed', 'cancelled', 'rolled_back') AND finished_at IS NOT NULL) OR
        (status IN ('queued', 'running') AND finished_at IS NULL)
    ),
    -- Tenant-scoped composite foreign keys: the parent resource and the
    -- deployment row share an organization_id leg, so a deployment can
    -- never reference another tenant's project, environment, or service.
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, environment_id)
        REFERENCES environments (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, service_id)
        REFERENCES services (organization_id, id) ON DELETE CASCADE,
    UNIQUE (organization_id, idempotency_key),
    -- Composite-FK target: provisioning_jobs and audit_events can
    -- reference a deployment by (organization_id, id) so the link can
    -- never cross a tenant boundary.
    UNIQUE (organization_id, id)
);

-- Customer-facing list path: deployments of a service in reverse
-- chronological order.
CREATE INDEX deployments_service_created_idx
    ON deployments (organization_id, service_id, created_at DESC);

-- Tenant-scoped recency scan: most recent deployments across the
-- organization, used by usage dashboards and reporting.
CREATE INDEX deployments_org_created_idx
    ON deployments (organization_id, created_at DESC);

-- Worker reverse-lookup: deployments currently in a non-terminal state.
CREATE INDEX deployments_status_idx
    ON deployments (organization_id, status)
    WHERE status IN ('queued', 'running');

CREATE TRIGGER deployments_set_updated_at
    BEFORE UPDATE ON deployments
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER deployments_bump_version
    BEFORE UPDATE ON deployments
    FOR EACH ROW EXECUTE FUNCTION bump_version();
