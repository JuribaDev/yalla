-- Reverse 0005_membership_role_version: drop the role_version column. The
-- CHECK constraint is attached to the column and is removed with it.
ALTER TABLE memberships DROP COLUMN IF EXISTS role_version;
