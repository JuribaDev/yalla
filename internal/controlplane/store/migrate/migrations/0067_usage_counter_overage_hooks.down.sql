ALTER TABLE billing_export_items
    DROP CONSTRAINT IF EXISTS billing_export_items_overage_quantity_nonnegative,
    DROP CONSTRAINT IF EXISTS billing_export_items_overage_quantity_finite,
    DROP CONSTRAINT IF EXISTS billing_export_items_included_quantity_finite,
    DROP CONSTRAINT IF EXISTS billing_export_items_overage_decision_valid,
    DROP CONSTRAINT IF EXISTS billing_export_items_overage_policy_mode_valid,
    DROP CONSTRAINT IF EXISTS billing_export_items_entitlement_key_valid,
    DROP COLUMN IF EXISTS overage_quantity,
    DROP COLUMN IF EXISTS included_quantity,
    DROP COLUMN IF EXISTS overage_decision,
    DROP COLUMN IF EXISTS overage_policy_mode,
    DROP COLUMN IF EXISTS entitlement_key;

ALTER TABLE usage_counters
    DROP CONSTRAINT IF EXISTS usage_counters_overage_quantity_nonnegative,
    DROP CONSTRAINT IF EXISTS usage_counters_overage_quantity_finite,
    DROP CONSTRAINT IF EXISTS usage_counters_included_quantity_finite,
    DROP CONSTRAINT IF EXISTS usage_counters_overage_decision_valid,
    DROP CONSTRAINT IF EXISTS usage_counters_overage_policy_mode_valid,
    DROP CONSTRAINT IF EXISTS usage_counters_entitlement_key_valid,
    DROP COLUMN IF EXISTS overage_evaluated_at,
    DROP COLUMN IF EXISTS overage_quantity,
    DROP COLUMN IF EXISTS included_quantity,
    DROP COLUMN IF EXISTS overage_decision,
    DROP COLUMN IF EXISTS overage_policy_mode,
    DROP COLUMN IF EXISTS entitlement_key;
