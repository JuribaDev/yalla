-- Pricing plan catalog: versioned package definitions and their default
-- entitlements. Subscriptions that land later should reference the accepted
-- plan row directly, so a customer can always be audited against the exact
-- version they accepted even after the plan slug moves to a newer version.

CREATE DOMAIN pricing_plan_status AS text
    CHECK (VALUE IN ('draft', 'active', 'archived'));

CREATE DOMAIN pricing_billing_period AS text
    CHECK (VALUE IN ('monthly', 'annual', 'custom'));

CREATE TABLE plans (
    id             text                  PRIMARY KEY CHECK (length(id) > 0),
    slug           citext                NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    name           text                  NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 120),
    status         pricing_plan_status   NOT NULL DEFAULT 'draft',
    billing_period pricing_billing_period NOT NULL,
    display_order  integer               NOT NULL DEFAULT 0 CHECK (display_order >= 0),
    version        integer               NOT NULL CHECK (version > 0),
    archived_at    timestamptz,
    created_at     timestamptz           NOT NULL DEFAULT now(),
    updated_at     timestamptz           NOT NULL DEFAULT now(),
    CONSTRAINT plans_archived_at_consistent CHECK (
        (status = 'archived' AND archived_at IS NOT NULL) OR
        (status <> 'archived' AND archived_at IS NULL)
    ),
    UNIQUE (slug, billing_period, version)
);

-- Only one active version of a package may exist for a billing period. Draft
-- future versions may coexist until an admin publishes one.
CREATE UNIQUE INDEX plans_active_slug_period_idx
    ON plans (slug, billing_period)
    WHERE status = 'active';

CREATE INDEX plans_slug_period_idx ON plans (slug, billing_period);
CREATE INDEX plans_status_display_idx ON plans (status, display_order, slug);

CREATE TRIGGER plans_set_updated_at
    BEFORE UPDATE ON plans
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE plan_entitlements (
    id               text                   PRIMARY KEY CHECK (length(id) > 0),
    plan_id          text                   NOT NULL REFERENCES plans (id) ON DELETE CASCADE,
    entitlement_key  text                   NOT NULL CHECK (entitlement_key ~ '^[a-z0-9][a-z0-9_.-]{0,127}$'),
    limit_value      bigint                 CHECK (limit_value IS NULL OR limit_value >= 0),
    enforcement_mode quota_enforcement_mode NOT NULL,
    metadata         jsonb                  NOT NULL DEFAULT '{}'::jsonb,
    created_at       timestamptz            NOT NULL DEFAULT now(),
    updated_at       timestamptz            NOT NULL DEFAULT now(),
    UNIQUE (plan_id, entitlement_key)
);

CREATE INDEX plan_entitlements_plan_id_idx ON plan_entitlements (plan_id);
CREATE INDEX plan_entitlements_key_idx ON plan_entitlements (entitlement_key);

CREATE TRIGGER plan_entitlements_set_updated_at
    BEFORE UPDATE ON plan_entitlements
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

INSERT INTO plans (id, slug, name, status, billing_period, display_order, version)
VALUES
    ('plan_starter_monthly_v1', 'starter', 'Starter', 'active', 'monthly', 10, 1),
    ('plan_pro_monthly_v1', 'pro', 'Pro', 'active', 'monthly', 20, 1),
    ('plan_business_monthly_v1', 'business', 'Business', 'active', 'monthly', 30, 1),
    ('plan_enterprise_monthly_v1', 'enterprise', 'Enterprise', 'active', 'monthly', 40, 1);

INSERT INTO plan_entitlements (id, plan_id, entitlement_key, limit_value, enforcement_mode)
VALUES
    ('pent_starter_projects_v1', 'plan_starter_monthly_v1', 'projects', 1, 'hard'),
    ('pent_starter_bandwidth_v1', 'plan_starter_monthly_v1', 'http_bandwidth_total', 100, 'soft'),
    ('pent_pro_projects_v1', 'plan_pro_monthly_v1', 'projects', 5, 'hard'),
    ('pent_pro_overage_v1', 'plan_pro_monthly_v1', 'http_bandwidth_total', NULL, 'metered'),
    ('pent_business_projects_v1', 'plan_business_monthly_v1', 'projects', 25, 'hard'),
    ('pent_business_support_v1', 'plan_business_monthly_v1', 'priority_support', NULL, 'disabled'),
    ('pent_enterprise_projects_v1', 'plan_enterprise_monthly_v1', 'projects', 100, 'soft'),
    ('pent_enterprise_overage_v1', 'plan_enterprise_monthly_v1', 'http_bandwidth_total', NULL, 'metered');
