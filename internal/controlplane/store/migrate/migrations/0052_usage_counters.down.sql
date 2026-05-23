DROP INDEX IF EXISTS usage_counter_adjustments_org_period_idx;
DROP TABLE IF EXISTS usage_counter_adjustments;

DROP INDEX IF EXISTS usage_counters_org_period_idx;
DROP TRIGGER IF EXISTS usage_counters_set_updated_at ON usage_counters;
DROP TABLE IF EXISTS usage_counters;
