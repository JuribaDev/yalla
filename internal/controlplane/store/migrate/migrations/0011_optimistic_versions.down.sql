DROP TRIGGER IF EXISTS services_bump_version ON services;
DROP TRIGGER IF EXISTS environments_bump_version ON environments;
DROP TRIGGER IF EXISTS projects_bump_version ON projects;
DROP TRIGGER IF EXISTS organizations_bump_version ON organizations;

ALTER TABLE services       DROP COLUMN IF EXISTS version;
ALTER TABLE environments   DROP COLUMN IF EXISTS version;
ALTER TABLE projects       DROP COLUMN IF EXISTS version;
ALTER TABLE organizations  DROP COLUMN IF EXISTS version;

DROP FUNCTION IF EXISTS bump_version();
