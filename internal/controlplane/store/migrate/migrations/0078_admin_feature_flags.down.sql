DROP TRIGGER IF EXISTS admin_feature_flags_set_updated_at ON admin_feature_flags;
DROP INDEX IF EXISTS admin_feature_flags_runtime_idx;
DROP TABLE IF EXISTS admin_feature_flags;
DROP DOMAIN IF EXISTS feature_flag_value_type;
