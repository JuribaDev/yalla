DROP TRIGGER IF EXISTS admin_metering_sources_set_updated_at ON admin_metering_sources;
DROP INDEX IF EXISTS admin_metering_sources_secret_routing_idx;
DROP INDEX IF EXISTS admin_metering_sources_runtime_idx;
DROP TABLE IF EXISTS admin_metering_sources;
DROP DOMAIN IF EXISTS metering_source_type;
