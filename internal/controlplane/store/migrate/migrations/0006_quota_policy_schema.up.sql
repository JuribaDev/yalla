-- Quota policy schema: the source-of-truth tables for Yalla's quota system —
-- the limits a tenant is allowed, the resources it has actually allocated, the
-- in-flight reservations that prevent concurrent over-allocation, and the
-- append-only log of every quota movement.
--
-- Design rules enforced here:
--
--   * Quota dimensions are a closed set. The quota_resource DOMAIN names every
--     countable resource exactly once and is reused by all four tables, so a
--     typo'd or unknown dimension is rejected by the database, not discovered
--     at runtime. Adding a dimension is a new, higher-versioned migration that
--     runs ALTER DOMAIN.
--   * A limit can be inherited from a plan default and overridden per
--     organization. quota_policies carries both scopes in one table: a
--     plan_default row is keyed by (plan, resource); an organization override
--     row is keyed by (organization_id, resource). The quota checker resolves
--     a tenant's effective limit as "organization override if present, else
--     plan default". There is no foreign key to a plans table yet — plans are
--     introduced by a later migration — so plan is plain text here.
--   * Reservations are short-lived. Every reservation carries an expires_at so
--     a crashed job cannot strand quota forever, and a status lifecycle
--     (active -> committed | released | expired) so it is released on job
--     completion or failure. A settled reservation always carries settled_at;
--     an active one never does — enforced by a CHECK.
--   * Every customer-data table is tenant-scoped: it carries organization_id
--     with a foreign key to organizations, and a cross-table link
--     (usage_events.reservation_id) uses a COMPOSITE foreign key so a row can
--     never reference another tenant's reservation.
--   * usage_events is append-only: no updated_at column and no update trigger.
--   * No table stores secrets, tokens, API keys, or rendered environment
--     variable values.

-- quota_resource is the closed set of countable quota dimensions. It is the
-- single source of truth shared by quota_policies, quota_usage,
-- quota_reservations, and usage_events.
CREATE DOMAIN quota_resource AS text
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
        'concurrent_deployments',
        'monthly_deployments'
    ));

-- quota_enforcement_mode is how a limit is enforced. 'hard' rejects over the
-- limit; 'soft' warns but allows; 'metered' tracks usage for billing without a
-- ceiling; 'disabled' is not enforced at all.
CREATE DOMAIN quota_enforcement_mode AS text
    CHECK (VALUE IN ('hard', 'soft', 'metered', 'disabled'));

-- quota_policies holds the limit for one resource dimension at one scope. A
-- row is either a plan default (keyed by plan) or an organization override
-- (keyed by organization_id) — never both, never neither.
CREATE TABLE quota_policies (
    id               text                   PRIMARY KEY CHECK (length(id) > 0),
    scope_kind       text                   NOT NULL CHECK (scope_kind IN ('plan_default', 'organization')),
    plan             text                   CHECK (plan IS NULL OR length(plan) > 0),
    organization_id  text                   REFERENCES organizations (id) ON DELETE CASCADE,
    resource         quota_resource         NOT NULL,
    limit_value      bigint                 NOT NULL CHECK (limit_value >= 0),
    enforcement_mode quota_enforcement_mode NOT NULL DEFAULT 'hard',
    created_at       timestamptz            NOT NULL DEFAULT now(),
    updated_at       timestamptz            NOT NULL DEFAULT now(),
    -- Exactly one scope identifier is set, and it matches scope_kind.
    CONSTRAINT quota_policies_scope_consistent CHECK (
        (scope_kind = 'plan_default' AND plan IS NOT NULL AND organization_id IS NULL) OR
        (scope_kind = 'organization' AND organization_id IS NOT NULL AND plan IS NULL)
    )
);

-- A plan defines at most one default per resource; an organization overrides
-- at most one policy per resource. The two scopes are independent, so a plan
-- default and an organization override for the same resource coexist.
CREATE UNIQUE INDEX quota_policies_plan_resource_idx
    ON quota_policies (plan, resource)
    WHERE scope_kind = 'plan_default';

CREATE UNIQUE INDEX quota_policies_org_resource_idx
    ON quota_policies (organization_id, resource)
    WHERE scope_kind = 'organization';

CREATE INDEX quota_policies_organization_id_idx
    ON quota_policies (organization_id)
    WHERE organization_id IS NOT NULL;

CREATE TRIGGER quota_policies_set_updated_at
    BEFORE UPDATE ON quota_policies
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- quota_usage is the actual, currently-allocated amount of a resource for a
-- tenant — one counter row per (organization, resource). The quota checker
-- reads and locks this row to make an allocation decision.
CREATE TABLE quota_usage (
    id              text           PRIMARY KEY CHECK (length(id) > 0),
    organization_id text           NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    resource        quota_resource NOT NULL,
    used_value      bigint         NOT NULL DEFAULT 0 CHECK (used_value >= 0),
    created_at      timestamptz    NOT NULL DEFAULT now(),
    updated_at      timestamptz    NOT NULL DEFAULT now(),
    UNIQUE (organization_id, resource)
);

CREATE INDEX quota_usage_organization_id_idx ON quota_usage (organization_id);

CREATE TRIGGER quota_usage_set_updated_at
    BEFORE UPDATE ON quota_usage
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- quota_reservations holds amounts claimed by an in-flight unit of work before
-- the resource actually exists. An active reservation counts against the
-- tenant's limit; it is committed when the work succeeds, released when it
-- fails or is cancelled, and expired when expires_at passes without a verdict.
CREATE TABLE quota_reservations (
    id              text           PRIMARY KEY CHECK (length(id) > 0),
    organization_id text           NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    resource        quota_resource NOT NULL,
    amount          bigint         NOT NULL CHECK (amount > 0),
    status          text           NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'committed', 'released', 'expired')),
    -- The provisioning job that owns this reservation. There is no foreign key
    -- yet: provisioning_jobs is created by a later migration, which also adds
    -- the composite (organization_id, job_id) foreign key.
    job_id          text,
    request_id      text,
    expires_at      timestamptz    NOT NULL,
    settled_at      timestamptz,
    created_at      timestamptz    NOT NULL DEFAULT now(),
    updated_at      timestamptz    NOT NULL DEFAULT now(),
    -- A reservation carries settled_at exactly when it has left the 'active'
    -- state; an active reservation never carries one.
    CONSTRAINT quota_reservations_settled_consistent CHECK (
        (status = 'active'  AND settled_at IS NULL) OR
        (status <> 'active' AND settled_at IS NOT NULL)
    ),
    -- Composite-FK target so usage_events can reference a reservation without
    -- being able to cross the tenant boundary.
    UNIQUE (organization_id, id)
);

-- Summing live reservations for a tenant+resource is the hot path of the quota
-- checker; the partial index keeps it to active rows only.
CREATE INDEX quota_reservations_active_idx
    ON quota_reservations (organization_id, resource)
    WHERE status = 'active';

-- The reservation sweeper scans for active rows that have passed their expiry.
CREATE INDEX quota_reservations_expiry_idx
    ON quota_reservations (expires_at)
    WHERE status = 'active';

CREATE INDEX quota_reservations_job_id_idx
    ON quota_reservations (job_id)
    WHERE job_id IS NOT NULL;

CREATE TRIGGER quota_reservations_set_updated_at
    BEFORE UPDATE ON quota_reservations
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- usage_events is the append-only log of every quota movement: a reservation
-- being made, committed, released, expired, or a counter being consumed or
-- adjusted directly. It is the audit trail the metering and billing stories
-- build period counters from. delta is signed: a release or refund is
-- negative. There is no updated_at column and no update trigger — rows are
-- never modified after insert.
CREATE TABLE usage_events (
    id              text           PRIMARY KEY CHECK (length(id) > 0),
    organization_id text           NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    resource        quota_resource NOT NULL,
    event_type      text           NOT NULL
                        CHECK (event_type IN ('reserved', 'committed', 'released', 'expired', 'consumed', 'adjusted')),
    delta           bigint         NOT NULL,
    reservation_id  text,
    request_id      text,
    metadata        jsonb          NOT NULL DEFAULT '{}'::jsonb,
    occurred_at     timestamptz    NOT NULL DEFAULT now(),
    created_at      timestamptz    NOT NULL DEFAULT now(),
    -- The reservation link is optional. The composite foreign key is
    -- MATCH SIMPLE, so it is enforced only when reservation_id is set — and
    -- when it is, it pins the event's organization to the reservation's, so a
    -- cross-tenant reservation reference is rejected by the database.
    FOREIGN KEY (organization_id, reservation_id)
        REFERENCES quota_reservations (organization_id, id)
);

CREATE INDEX usage_events_org_occurred_idx ON usage_events (organization_id, occurred_at);
CREATE INDEX usage_events_org_resource_idx ON usage_events (organization_id, resource);
CREATE INDEX usage_events_reservation_id_idx
    ON usage_events (reservation_id)
    WHERE reservation_id IS NOT NULL;
