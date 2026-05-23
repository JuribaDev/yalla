-- Reverse the encryption-at-rest schema for project_variables.
--
-- The down migration drops the routing index, the consistency CHECK,
-- and the three encryption columns. It is destructive: rows whose
-- is_secret = true currently store the secret bytes ONLY in
-- secret_ciphertext (the plain value column is forced to ''). Dropping
-- the ciphertext columns would silently lose every secret value.
--
-- To prevent that loss, the down migration refuses to run while any
-- is_secret = true rows are present. An operator that genuinely needs
-- to roll back must first export the sealed rows, Open them through the
-- secrets provider, and re-write them as is_secret = false (a deliberate
-- demotion) — or accept the loss explicitly by deleting them.

DO $$
DECLARE
    leftover bigint;
BEGIN
    SELECT count(*) INTO leftover
      FROM project_variables
     WHERE is_secret = true;
    IF leftover > 0 THEN
        RAISE EXCEPTION 'migration 0030 down refuses to run: % project_variables rows still hold sealed secret values; export, decrypt, and demote them before rolling back', leftover;
    END IF;
END
$$;

DROP INDEX IF EXISTS project_variables_secret_routing_idx;

ALTER TABLE project_variables
    DROP CONSTRAINT IF EXISTS project_variables_secret_columns_consistent;

ALTER TABLE project_variables
    DROP COLUMN IF EXISTS secret_ciphertext,
    DROP COLUMN IF EXISTS secret_key_id,
    DROP COLUMN IF EXISTS secret_provider;
