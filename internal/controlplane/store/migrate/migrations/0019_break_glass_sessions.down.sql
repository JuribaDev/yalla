DROP TRIGGER IF EXISTS break_glass_sessions_no_rewrite ON break_glass_sessions;
DROP FUNCTION IF EXISTS break_glass_sessions_reject_rewrite();
DROP TRIGGER IF EXISTS break_glass_sessions_bump_version ON break_glass_sessions;
DROP TRIGGER IF EXISTS break_glass_sessions_set_updated_at ON break_glass_sessions;
DROP INDEX IF EXISTS break_glass_sessions_active_idx;
DROP INDEX IF EXISTS break_glass_sessions_actor_idx;
DROP INDEX IF EXISTS break_glass_sessions_org_started_idx;
DROP TABLE IF EXISTS break_glass_sessions;
