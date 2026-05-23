DROP TRIGGER IF EXISTS admin_metric_definitions_set_updated_at ON admin_metric_definitions;
DROP INDEX IF EXISTS admin_metric_definitions_current_unique;
DROP INDEX IF EXISTS admin_metric_definitions_runtime_idx;
DROP TABLE IF EXISTS admin_metric_definitions;
DROP DOMAIN IF EXISTS metric_aggregation_function;
