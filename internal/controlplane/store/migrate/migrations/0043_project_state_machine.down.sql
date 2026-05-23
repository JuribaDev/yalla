DROP TRIGGER IF EXISTS project_events_no_update ON project_events;
DROP FUNCTION IF EXISTS project_events_reject_update();
DROP INDEX IF EXISTS project_events_org_occurred_idx;
DROP INDEX IF EXISTS project_events_project_occurred_idx;
DROP TABLE IF EXISTS project_events;

ALTER TABLE projects
    DROP COLUMN IF EXISTS status;
