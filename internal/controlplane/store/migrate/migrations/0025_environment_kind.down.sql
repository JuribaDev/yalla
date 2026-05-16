DROP INDEX IF EXISTS environments_preview_kind_idx;

ALTER TABLE environments
    DROP COLUMN IF EXISTS kind;
