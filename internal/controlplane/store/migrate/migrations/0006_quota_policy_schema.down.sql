-- Reverse of 0006_quota_policy_schema: drop the quota tables in reverse
-- dependency order, then the shared domains. Each DROP TABLE also drops the
-- table's indexes and BEFORE UPDATE trigger; the set_updated_at() function
-- itself belongs to the baseline migration and is left in place.

DROP TABLE IF EXISTS usage_events;
DROP TABLE IF EXISTS quota_reservations;
DROP TABLE IF EXISTS quota_usage;
DROP TABLE IF EXISTS quota_policies;

DROP DOMAIN IF EXISTS quota_enforcement_mode;
DROP DOMAIN IF EXISTS quota_resource;
