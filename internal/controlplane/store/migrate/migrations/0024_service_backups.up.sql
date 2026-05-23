-- Service-scoped backups: the per-service backup policies (schedule,
-- retention, on/off flag) and the most recent run state Yalla's
-- worker projects when it drives Dokploy backups. A row here binds a
-- backup policy to a single service inside a single tenant, so a
-- record can never sit under a foreign tenant's service (the FK
-- refuses the insert structurally before the application layer's
-- tenant predicate runs).
--
-- Design rules enforced here:
--
--   * Tenant-scoped at the database. The composite FK
--     (organization_id, service_id) references the matching composite
--     UNIQUE (organization_id, id) on services with ON DELETE CASCADE,
--     so a service teardown removes its backup policies and a row can
--     never sit under a foreign tenant's service. The transitive
--     parents (environment, project) are reached through services —
--     this table does not duplicate environment_id or project_id, the
--     same way service_domains and service_variables do not.
--   * Composite uniqueness (organization_id, id) is exposed as the FK
--     target any future backup-run table can use to enforce "a run
--     row's organization_id must match its referenced parent
--     backup-policy's organization_id".
--   * Optimistic concurrency. Every row carries a bigint version that
--     the bump_version() trigger from migration 0011 maintains,
--     mirroring services / environments / projects / *_variables /
--     *_grants / service_domains. Future PATCH / DELETE / run stories
--     will accept If-Match against this column.
--   * No secrets in the schema. The schedule column is a cron-style
--     expression. The actual backup artefact bytes are held by the
--     worker / Dokploy / object-storage layer and never round-tripped
--     through this table; the table only holds desired-state policy
--     and the worker-driven run state (last_run_at / last_succeeded_at
--     / status), never credentials.
--   * Closed-set status enumeration. The status column is constrained
--     by CHECK to {disabled, pending, running, succeeded, failed} so
--     an agent reading the column can branch on the value without
--     escape-decoding it. The worker is the authority for transitions
--     between running and {succeeded, failed}; the customer-facing
--     PATCH is restricted to {disabled, pending} so a customer cannot
--     forge a successful run.

CREATE TABLE service_backups (
    id                 text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id    text        NOT NULL,
    service_id         text        NOT NULL,
    display_name       text        NOT NULL CHECK (length(display_name) > 0),
    schedule           text        NOT NULL CHECK (length(schedule) > 0),
    retention_count    integer     NOT NULL DEFAULT 7
                                   CHECK (retention_count >= 1 AND retention_count <= 365),
    enabled            boolean     NOT NULL DEFAULT true,
    status             text        NOT NULL DEFAULT 'pending'
                                   CHECK (status IN ('disabled', 'pending', 'running', 'succeeded', 'failed')),
    last_run_at        timestamptz,
    last_succeeded_at  timestamptz,
    version            bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, service_id)
        REFERENCES services (organization_id, id) ON DELETE CASCADE,
    UNIQUE (organization_id, id)
);

CREATE INDEX service_backups_service_idx
    ON service_backups (organization_id, service_id);

CREATE TRIGGER service_backups_set_updated_at
    BEFORE UPDATE ON service_backups
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER service_backups_bump_version
    BEFORE UPDATE ON service_backups
    FOR EACH ROW EXECUTE FUNCTION bump_version();
