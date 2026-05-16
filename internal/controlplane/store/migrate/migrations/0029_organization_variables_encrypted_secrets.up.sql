-- Encryption-at-rest for organization_variables secret values.
--
-- Migration 0012 created organization_variables with a single `value`
-- column that stored both plaintext config values AND the plaintext of
-- secret values. The HTTP layer redacted secret values on the wire and
-- the audit layer redacted every value in audit metadata, but the
-- source-of-truth column carried the secret bytes verbatim. BE-0339
-- moves secret values behind a documented secret provider abstraction
-- (internal/controlplane/secrets): every row whose is_secret = true
-- now stores its plaintext under (secret_provider, secret_key_id,
-- secret_ciphertext) and forces `value` to '' so the unencrypted
-- column can never carry secret content again.
--
-- Design rules enforced here:
--
--   * Self-describing storage. (secret_provider, secret_key_id) name
--     the secrets.Provider implementation and key id that sealed the
--     row, so a future process can route Open() correctly even after
--     a provider migration.
--   * Defence-in-depth invariant. The CHECK constraint pins the
--     contract "is_secret => ciphertext columns are populated AND the
--     plain value column is empty"; "is_secret = false => ciphertext
--     columns are NULL". A bug in the application layer that tries to
--     write a plaintext secret rolls back as a deterministic 409, never
--     a silent corruption.
--   * Wire surface unchanged. Secret values still project as the
--     redaction sentinel through the HTTP layer; encryption-at-rest is
--     an additional layer, not a replacement.
--   * Audit metadata unchanged. The audit layer continues to record
--     only counts (PUT) or stable field names (PATCH); ciphertext is
--     never recorded.
--
-- This migration assumes the table has been managed entirely through
-- the application since 0012 — no row currently has is_secret = true
-- in any environment because the application path did not commit to
-- the at-rest seam yet. The pre-migration check below makes that
-- explicit so a future re-application against a database that
-- accumulated secret rows fails loudly rather than silently leaving
-- plaintext secrets behind.

DO $$
DECLARE
    leftover bigint;
BEGIN
    SELECT count(*) INTO leftover
      FROM organization_variables
     WHERE is_secret = true;
    IF leftover > 0 THEN
        RAISE EXCEPTION 'migration 0028 refuses to run: % organization_variables rows still hold plaintext secret values; back them up and re-seal under the secrets provider before applying this migration', leftover;
    END IF;
END
$$;

ALTER TABLE organization_variables
    ADD COLUMN secret_provider   text  NULL,
    ADD COLUMN secret_key_id     text  NULL,
    ADD COLUMN secret_ciphertext bytea NULL;

-- The plain `value` column is kept (NOT NULL) for non-secret rows. For
-- secret rows the column is forced to '' by the CHECK below — a single
-- non-empty plaintext byte for a secret row rolls the transaction back
-- as a deterministic 23xxx constraint violation, which the store layer
-- maps to apierr.Conflict.
ALTER TABLE organization_variables
    ADD CONSTRAINT organization_variables_secret_columns_consistent
    CHECK (
        (
            is_secret = false
            AND secret_provider   IS NULL
            AND secret_key_id     IS NULL
            AND secret_ciphertext IS NULL
        )
        OR
        (
            is_secret = true
            AND secret_provider   IS NOT NULL
            AND length(secret_provider) > 0
            AND secret_key_id     IS NOT NULL
            AND length(secret_key_id)   > 0
            AND secret_ciphertext IS NOT NULL
            AND octet_length(secret_ciphertext) > 0
            AND value = ''
        )
    );

-- Partial index over rows that still reference a given (provider, key)
-- pair. The future key-rotation worker (BE-0351) lists rows that still
-- carry a retired key id by joining this index, so the operator never
-- needs a full-table scan to find re-seal candidates.
CREATE INDEX organization_variables_secret_routing_idx
    ON organization_variables (secret_provider, secret_key_id)
 WHERE is_secret = true;
