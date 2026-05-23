-- Project-scoped preview-environment lifecycle rows. A preview environment is
-- implemented as an ordinary environments row with kind='preview', while this
-- table carries the preview-specific source/change metadata and teardown
-- lifecycle that the preview API and worker need.
--
-- Design rules enforced here:
--
--   * Tenant-scoped at the database. Every row carries organization_id and
--     project_id directly, and both the preview environment and source
--     environment links are composite FKs against environments
--     (organization_id, project_id, id), so a preview row can never reference
--     an environment from another tenant or another project.
--   * The preview environment link is unique. One cloned environment can be
--     represented by at most one preview row, which makes
--     DELETE /v1/projects/{project_id}/previews/{preview_id} and worker
--     cleanup deterministic.
--   * The wrapped environment must actually be an environments.kind='preview'
--     row, enforced by a trigger because a CHECK constraint cannot look up the
--     referenced row. The source environment must be a distinct row in the
--     same tenant/project.
--   * Optimistic concurrency mirrors projects/environments/services: version
--     starts at 1 and bump_version() advances it on every UPDATE.
--   * Soft deletion is explicit. API deletion marks deletion_scheduled_at and
--     status='deleting' so the worker can drive Dokploy teardown; hard DELETE
--     remains available for the worker after teardown or parent cascade.
--   * No secrets. change_ref is a branch/PR/commit-like identifier, not a
--     credential. The table stores no tokens, rendered variables, or Dokploy
--     secrets.

CREATE TABLE preview_environments (
    id                    text        PRIMARY KEY CHECK (length(id) > 0),
    organization_id       text        NOT NULL,
    project_id            text        NOT NULL,
    environment_id        text        NOT NULL,
    source_environment_id text        NOT NULL,
    display_name          text        NOT NULL CHECK (length(display_name) > 0),
    change_ref            text        NOT NULL CHECK (length(change_ref) > 0),
    status                text        NOT NULL DEFAULT 'pending'
                                      CHECK (status IN ('pending', 'provisioning', 'ready', 'deleting', 'deleted', 'failed')),
    expires_at            timestamptz,
    deletion_scheduled_at timestamptz,
    version               bigint      NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CHECK (environment_id <> source_environment_id),
    FOREIGN KEY (organization_id, project_id, environment_id)
        REFERENCES environments (organization_id, project_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, project_id, source_environment_id)
        REFERENCES environments (organization_id, project_id, id) ON DELETE CASCADE,
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, project_id, environment_id)
);

CREATE INDEX preview_environments_project_idx
    ON preview_environments (organization_id, project_id);

CREATE INDEX preview_environments_deletion_idx
    ON preview_environments (organization_id, project_id, deletion_scheduled_at)
    WHERE deletion_scheduled_at IS NOT NULL;

CREATE TRIGGER preview_environments_set_updated_at
    BEFORE UPDATE ON preview_environments
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER preview_environments_bump_version
    BEFORE UPDATE ON preview_environments
    FOR EACH ROW EXECUTE FUNCTION bump_version();

CREATE OR REPLACE FUNCTION preview_environments_enforce_preview_kind()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM environments
         WHERE organization_id = NEW.organization_id
           AND project_id = NEW.project_id
           AND id = NEW.environment_id
           AND kind = 'preview'
    ) THEN
        RAISE EXCEPTION 'preview environment row must reference an environment with kind=preview'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER preview_environments_enforce_preview_kind
    BEFORE INSERT OR UPDATE OF organization_id, project_id, environment_id ON preview_environments
    FOR EACH ROW EXECUTE FUNCTION preview_environments_enforce_preview_kind();
