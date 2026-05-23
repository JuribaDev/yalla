-- Reverse 0004_service_accounts: drop the api_keys ownership link first, then
-- the table. DROP TABLE removes the service_accounts index and BEFORE UPDATE
-- trigger with it; the shared set_updated_at() function belongs to the
-- baseline migration and is left in place.
ALTER TABLE api_keys DROP CONSTRAINT IF EXISTS api_keys_service_account_id_fkey;
DROP INDEX IF EXISTS api_keys_service_account_id_idx;
ALTER TABLE api_keys DROP COLUMN IF EXISTS service_account_id;
DROP TABLE IF EXISTS service_accounts;
