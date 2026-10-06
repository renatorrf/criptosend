DROP INDEX IF EXISTS auth_sessions_family_idx;

ALTER TABLE auth_sessions
  DROP COLUMN IF EXISTS replaced_by_id,
  DROP COLUMN IF EXISTS rotated_from_id,
  DROP COLUMN IF EXISTS session_family_id;

DROP TABLE IF EXISTS phone_verification_challenges;

DROP TRIGGER IF EXISTS user_credentials_set_updated_at ON user_credentials;
DROP TABLE IF EXISTS user_credentials;

