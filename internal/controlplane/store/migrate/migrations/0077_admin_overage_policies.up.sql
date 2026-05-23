CREATE DOMAIN admin_overage_policy_scope AS text
    CHECK (VALUE IN ('global', 'plan', 'organization'));

CREATE DOMAIN admin_overage_policy_mode AS text
    CHECK (VALUE IN ('allow', 'warn', 'block', 'require_admin_review'));

CREATE TABLE admin_overage_policies (
    id               text                       PRIMARY KEY CHECK (length(id) > 0),
    scope            admin_overage_policy_scope NOT NULL,
    plan_id          text                       REFERENCES plans (id) ON DELETE CASCADE,
    organization_id  text                       REFERENCES organizations (id) ON DELETE CASCADE,
    entitlement_key  text                       NOT NULL CHECK (entitlement_key ~ '^[a-z0-9][a-z0-9_.-]{0,127}$'),
    mode             admin_overage_policy_mode  NOT NULL,
    effective_at     timestamptz                NOT NULL,
    reason           text                       NOT NULL DEFAULT '' CHECK (length(reason) <= 500),
    actor_id         text                       NOT NULL CHECK (length(btrim(actor_id)) BETWEEN 1 AND 128),
    actor_kind       text                       NOT NULL CHECK (actor_kind IN ('user', 'api_key', 'service_account', 'worker', 'system')),
    request_id       text                       NOT NULL CHECK (length(btrim(request_id)) BETWEEN 1 AND 128),
    correlation_id   text                       NOT NULL CHECK (length(btrim(correlation_id)) BETWEEN 1 AND 128),
    revision         bigint                     NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at       timestamptz                NOT NULL DEFAULT now(),
    updated_at       timestamptz                NOT NULL DEFAULT now(),
    CONSTRAINT admin_overage_policies_scope_target_valid CHECK (
        (scope = 'global' AND plan_id IS NULL AND organization_id IS NULL) OR
        (scope = 'plan' AND plan_id IS NOT NULL AND organization_id IS NULL) OR
        (scope = 'organization' AND plan_id IS NULL AND organization_id IS NOT NULL)
    ),
    UNIQUE (scope, plan_id, organization_id, entitlement_key, effective_at)
);

CREATE INDEX admin_overage_policies_runtime_idx
    ON admin_overage_policies (entitlement_key, effective_at DESC, created_at DESC, id DESC);

CREATE INDEX admin_overage_policies_plan_idx
    ON admin_overage_policies (plan_id, entitlement_key, effective_at DESC)
    WHERE scope = 'plan';

CREATE INDEX admin_overage_policies_org_idx
    ON admin_overage_policies (organization_id, entitlement_key, effective_at DESC)
    WHERE scope = 'organization';

CREATE TRIGGER admin_overage_policies_set_updated_at
    BEFORE UPDATE ON admin_overage_policies
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
