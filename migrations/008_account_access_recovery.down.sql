DROP INDEX IF EXISTS phone_verification_flow_expiration_idx;
DROP TABLE IF EXISTS account_reset_requests;
DROP TRIGGER IF EXISTS account_recovery_credentials_set_updated_at
  ON account_recovery_credentials;
DROP TABLE IF EXISTS account_recovery_credentials;

ALTER TABLE phone_verification_challenges
  DROP COLUMN IF EXISTS recovery_challenge,
  DROP COLUMN IF EXISTS flow_expires_at,
  DROP COLUMN IF EXISTS flow_token_hash,
  DROP COLUMN IF EXISTS verified_at,
  DROP COLUMN IF EXISTS requested_name_encrypted,
  DROP COLUMN IF EXISTS purpose;

ALTER TABLE user_credentials
  RENAME COLUMN password_hash TO pin_hash;
