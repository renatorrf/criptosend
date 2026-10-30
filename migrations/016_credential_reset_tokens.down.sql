DROP INDEX IF EXISTS manager_recovery_tokens_active_idx;
DROP TABLE IF EXISTS manager_recovery_tokens;

DROP INDEX IF EXISTS user_access_reset_tokens_expiration_idx;
DROP INDEX IF EXISTS user_access_reset_tokens_active_user_idx;
DROP TABLE IF EXISTS user_access_reset_tokens;

DROP INDEX IF EXISTS user_credentials_reset_required_idx;
ALTER TABLE user_credentials
  DROP CONSTRAINT IF EXISTS user_credentials_reset_state_check,
  DROP COLUMN IF EXISTS reset_requested_by_user_id,
  DROP COLUMN IF EXISTS reset_reason,
  DROP COLUMN IF EXISTS reset_required_at;
