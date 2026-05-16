-- The environment 'kind' axis is the closed taxonomy of how an environment is
-- used inside its project. Standard environments are the long-lived staging,
-- production, and ad-hoc named environments a project carries; preview
-- environments are the ephemeral, per-change-set instances that the preview
-- API (POST /v1/projects/{project_id}/previews) cloning workflow creates and
-- the preview teardown sweeper destroys when the underlying change set goes
-- away. The axis is per-row so a single project can mix standard environments
-- and preview environments under the same parent, which is the only sensible
-- shape for the per-change-set preview lifecycle.
--
-- The kind axis is required by the BE-0330 quota story: every Create that
-- writes a preview-kind environment row must Reserve the per-subtype
-- 'preview_environments' quota dimension alongside the existing
-- 'environments' dimension, and every standard-kind Create must consume only
-- the 'environments' dimension. The Reserve is gated on the value persisted
-- here, so the column is the source of truth the quota path consults.
--
-- The CHECK constraint mirrors the closed Go enum (EnvironmentKindStandard,
-- EnvironmentKindPreview) one-to-one, so a typo or an unknown value is
-- rejected by the database, never discovered at runtime. The default value
-- 'standard' makes the migration safe to apply over a populated environments
-- table: every existing row is a standard environment by definition (preview
-- environments did not exist before this migration), and existing callers
-- that do not set the column fall back to the standard taxonomy member.
ALTER TABLE environments
    ADD COLUMN kind text NOT NULL DEFAULT 'standard'
        CHECK (kind IN ('standard', 'preview'));

-- The preview lifecycle sweeper scans for preview-kind rows; a partial index
-- keeps that scan off a sequential pass while staying tiny, because the
-- overwhelming majority of environments are standard. Standard environments
-- are not selected through this predicate, so no index is needed for them
-- beyond the existing tenant-scoped indexes from migration 0002.
CREATE INDEX environments_preview_kind_idx
    ON environments (organization_id, project_id)
    WHERE kind = 'preview';
