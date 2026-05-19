ALTER TABLE usage_counters
    ADD COLUMN entitlement_key text,
    ADD COLUMN overage_policy_mode text,
    ADD COLUMN overage_decision text,
    ADD COLUMN included_quantity double precision,
    ADD COLUMN overage_quantity double precision,
    ADD COLUMN overage_evaluated_at timestamptz,
    ADD CONSTRAINT usage_counters_entitlement_key_valid
        CHECK (entitlement_key IS NULL OR entitlement_key ~ '^[a-z0-9][a-z0-9_.-]{0,127}$'),
    ADD CONSTRAINT usage_counters_overage_policy_mode_valid
        CHECK (overage_policy_mode IS NULL OR overage_policy_mode IN ('allow', 'warn', 'block', 'require_admin_review')),
    ADD CONSTRAINT usage_counters_overage_decision_valid
        CHECK (overage_decision IS NULL OR overage_decision IN ('within_included', 'allowed', 'warned', 'blocked', 'admin_review_required')),
    ADD CONSTRAINT usage_counters_included_quantity_finite
        CHECK (included_quantity IS NULL OR (included_quantity = included_quantity AND included_quantity NOT IN ('Infinity'::double precision, '-Infinity'::double precision))),
    ADD CONSTRAINT usage_counters_overage_quantity_finite
        CHECK (overage_quantity IS NULL OR (overage_quantity = overage_quantity AND overage_quantity NOT IN ('Infinity'::double precision, '-Infinity'::double precision))),
    ADD CONSTRAINT usage_counters_overage_quantity_nonnegative
        CHECK (overage_quantity IS NULL OR overage_quantity >= 0);

ALTER TABLE billing_export_items
    ADD COLUMN entitlement_key text,
    ADD COLUMN overage_policy_mode text,
    ADD COLUMN overage_decision text,
    ADD COLUMN included_quantity double precision,
    ADD COLUMN overage_quantity double precision,
    ADD CONSTRAINT billing_export_items_entitlement_key_valid
        CHECK (entitlement_key IS NULL OR entitlement_key ~ '^[a-z0-9][a-z0-9_.-]{0,127}$'),
    ADD CONSTRAINT billing_export_items_overage_policy_mode_valid
        CHECK (overage_policy_mode IS NULL OR overage_policy_mode IN ('allow', 'warn', 'block', 'require_admin_review')),
    ADD CONSTRAINT billing_export_items_overage_decision_valid
        CHECK (overage_decision IS NULL OR overage_decision IN ('within_included', 'allowed', 'warned', 'blocked', 'admin_review_required')),
    ADD CONSTRAINT billing_export_items_included_quantity_finite
        CHECK (included_quantity IS NULL OR (included_quantity = included_quantity AND included_quantity NOT IN ('Infinity'::double precision, '-Infinity'::double precision))),
    ADD CONSTRAINT billing_export_items_overage_quantity_finite
        CHECK (overage_quantity IS NULL OR (overage_quantity = overage_quantity AND overage_quantity NOT IN ('Infinity'::double precision, '-Infinity'::double precision))),
    ADD CONSTRAINT billing_export_items_overage_quantity_nonnegative
        CHECK (overage_quantity IS NULL OR overage_quantity >= 0);
