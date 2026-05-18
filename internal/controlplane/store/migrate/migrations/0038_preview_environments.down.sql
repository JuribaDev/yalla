DROP TRIGGER IF EXISTS preview_environments_bump_version ON preview_environments;
DROP TRIGGER IF EXISTS preview_environments_set_updated_at ON preview_environments;
DROP TRIGGER IF EXISTS preview_environments_enforce_preview_kind ON preview_environments;
DROP TABLE IF EXISTS preview_environments;
DROP FUNCTION IF EXISTS preview_environments_enforce_preview_kind();
