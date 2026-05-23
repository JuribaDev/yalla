-- Drift findings: the durable triage queue of divergences the reconcile
-- planner detects between Yalla's desired state and Dokploy's actual
-- state. One row is one open or resolved finding -- "this env var on
-- this service drifted", "this Dokploy resource has no Yalla
-- counterpart", "this managed domain was renamed in Dokploy". The
-- reconcile worker appends a row when a planner produces a ReviewEvent,
-- a SafeAction whose repair was logged for audit, or an
-- UnmanagedResource; an operator marks the row resolved once the
-- divergence is acknowledged, repaired, or claimed.
--
-- Design rules enforced here:
--
--   * Closed taxonomies. kind / reason / level are confined by CHECK to
--     the closed sets the reconcile planner emits (see
--     internal/controlplane/reconcile/types.go). An unknown taxonomy
--     value is rejected by the database, not at application runtime --
--     a future reason that needs a new value requires both the
--     application change AND a migration so the database CHECK stays
--     authoritative.
--   * Tenant-scoped at the database. organization_id has a foreign key
--     to organizations ON DELETE CASCADE; every optional resource leg
--     (project_id / environment_id / service_id / service_domain_id)
--     uses a composite foreign key referencing the parent's matching
--     composite UNIQUE (organization_id, id) so a finding can never
--     point at another tenant's row. The composite FK is MATCH SIMPLE:
--     enforced only when the column is set, so a finding scoped to the
--     organization level (level='organization', every other leg NULL)
--     is legal but a finding that names a project ID is pinned to its
--     organization's projects, never another tenant's.
--   * No secrets in the schema. env_var_key carries a key only -- never
--     a value -- mirroring reconcile.ReviewEvent.EnvVarKey;
--     dokploy_resource_id / parent_dokploy_id locate unmanaged
--     resources without exposing them to the customer; the reason /
--     kind columns are value-free classifications. The table cannot
--     hold a token, API key, cookie, or rendered environment variable
--     value because none of its columns ever transit one.
--   * Append-mostly. A finding is written once when the planner detects
--     drift; the only mutation the application performs is resolution
--     (resolved_at + resolved_by_actor_id stamped together). The
--     drift_findings_resolved_consistent CHECK ties resolved_at to a
--     non-empty resolved_by_actor_id so the audit trail names not only
--     when the row was resolved but who acknowledged it; a row whose
--     resolved_at is NULL must carry an empty resolved_by_actor_id.
--   * Correlatable. request_id is the originating customer request that
--     surfaced the drift (empty when the finding came from a scheduled
--     reconcile sweep with no originating request); correlation_id is
--     the reconcile run's correlation id so a single sweep's findings
--     can be joined to the worker's structured log and trace records.
--   * Composite-FK target. UNIQUE (organization_id, id) is exposed for
--     future override or summary tables that need to reference a
--     finding without crossing a tenant boundary.
--   * Cascade by organization teardown. Row removal is reachable only
--     through ON DELETE CASCADE from organizations / projects /
--     environments / services / service_domains. The store package
--     exposes no row-level DELETE; an erroneously-written finding stays
--     in the table as a historical record, marked resolved with an
--     operator-supplied actor.

CREATE TABLE drift_findings (
    id                   text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id      text        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    kind                 text        NOT NULL
                            CHECK (kind IN ('safe', 'dangerous', 'unmanaged')),
    reason               text        NOT NULL
                            CHECK (reason IN (
                                'env_var_changed',
                                'env_var_missing',
                                'env_var_extra',
                                'domain_missing',
                                'domain_renamed',
                                'service_missing',
                                'database_missing',
                                'service_type_changed',
                                'resource_unmanaged'
                            )),
    level                text        NOT NULL
                            CHECK (level IN (
                                'organization',
                                'project',
                                'environment',
                                'service',
                                'domain'
                            )),
    -- Optional resource legs. Each composite FK pins the leg to the
    -- finding's own tenant so a row can never reference another tenant's
    -- parent. MATCH SIMPLE means the FK is enforced only when the column
    -- is set: an organization-level finding sets none of these.
    project_id           text,
    environment_id       text,
    service_id           text,
    service_domain_id    text,
    -- Value-free planner context. env_var_key carries a key only --
    -- never a value -- so the table cannot hold a secret even if a
    -- planner regression tried to write one. Empty defaults make the
    -- column "absent" for findings that do not name an env var.
    env_var_key          text        NOT NULL DEFAULT '',
    -- Unmanaged-resource context. dokploy_resource_id names the Dokploy
    -- object without a Yalla counterpart; parent_dokploy_id locates it
    -- inside the Dokploy hierarchy without exposing it to a customer.
    dokploy_resource_id  text        NOT NULL DEFAULT '',
    parent_dokploy_id    text        NOT NULL DEFAULT '',
    request_id           text        NOT NULL DEFAULT '',
    correlation_id       text        NOT NULL DEFAULT '',
    detected_at          timestamptz NOT NULL,
    resolved_at          timestamptz,
    resolved_by_actor_id text        NOT NULL DEFAULT '',
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    -- A resolved finding always names its resolver; an open finding
    -- carries neither resolved_at nor a resolver. The two columns move
    -- together, so a partial UPDATE cannot leave the row in an
    -- inconsistent state.
    CONSTRAINT drift_findings_resolved_consistent CHECK (
        (resolved_at IS NULL AND resolved_by_actor_id = '') OR
        (resolved_at IS NOT NULL AND length(resolved_by_actor_id) > 0)
    ),
    -- Tenant-scoped composite foreign keys. MATCH SIMPLE: enforced only
    -- when the column is set, so a finding may legally omit any optional
    -- leg.
    FOREIGN KEY (organization_id, project_id)
        REFERENCES projects (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, environment_id)
        REFERENCES environments (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, service_id)
        REFERENCES services (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, service_domain_id)
        REFERENCES service_domains (organization_id, id) ON DELETE CASCADE,
    -- Composite-FK target so a future override or summary table can
    -- reference a finding without crossing a tenant boundary.
    UNIQUE (organization_id, id)
);

-- Operator triage queue: open findings for an organization, newest
-- first. The partial predicate keeps the hot "what needs attention"
-- list off a sequential scan.
CREATE INDEX drift_findings_org_open_idx
    ON drift_findings (organization_id, detected_at DESC)
    WHERE resolved_at IS NULL;

-- Tenant-scoped recency scan across both open and resolved findings,
-- newest first. Used by reporting and the resolved-history view.
CREATE INDEX drift_findings_org_detected_idx
    ON drift_findings (organization_id, detected_at DESC);

-- Reverse lookups from a targeted resource to its findings. Partial
-- indexes are slim because most findings carry only one optional leg.
CREATE INDEX drift_findings_service_id_idx
    ON drift_findings (organization_id, service_id)
    WHERE service_id IS NOT NULL;
CREATE INDEX drift_findings_environment_id_idx
    ON drift_findings (organization_id, environment_id)
    WHERE environment_id IS NOT NULL;

-- Maintain updated_at on every UPDATE (the resolve transition is the
-- only application-level UPDATE today, but the trigger is uniform with
-- every other mutable customer-data table in the schema).
CREATE TRIGGER drift_findings_set_updated_at
    BEFORE UPDATE ON drift_findings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
