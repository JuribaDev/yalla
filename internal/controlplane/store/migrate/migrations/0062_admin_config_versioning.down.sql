DROP TRIGGER IF EXISTS admin_config_versions_set_updated_at ON admin_config_versions;
DROP TABLE IF EXISTS admin_config_versions;

DROP TRIGGER IF EXISTS admin_config_sets_set_updated_at ON admin_config_sets;
DROP TABLE IF EXISTS admin_config_sets;

DROP DOMAIN IF EXISTS admin_config_version_status;
DROP DOMAIN IF EXISTS admin_config_domain;
