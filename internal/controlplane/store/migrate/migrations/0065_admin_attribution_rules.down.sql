DROP TRIGGER IF EXISTS admin_attribution_rules_set_updated_at ON admin_attribution_rules;
DROP INDEX IF EXISTS admin_attribution_rules_runtime_idx;
DROP TABLE IF EXISTS admin_attribution_rules;
DROP DOMAIN IF EXISTS attribution_rule_confidence;
DROP DOMAIN IF EXISTS attribution_rule_match_kind;
DROP DOMAIN IF EXISTS attribution_rule_source;
