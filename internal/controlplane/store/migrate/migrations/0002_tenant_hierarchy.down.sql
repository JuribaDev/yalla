-- Reverse of 0002_tenant_hierarchy: drop the tenant hierarchy tables in
-- reverse dependency order. Each DROP TABLE also drops the table's indexes and
-- BEFORE UPDATE trigger; the set_updated_at() function itself belongs to the
-- baseline migration and is left in place.

DROP TABLE IF EXISTS dokploy_refs;
DROP TABLE IF EXISTS services;
DROP TABLE IF EXISTS environments;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS memberships;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS organizations;
