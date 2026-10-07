DROP TABLE IF EXISTS invitation_codes;

DROP INDEX IF EXISTS users_manager_status_idx;
DROP INDEX IF EXISTS users_username_unique_idx;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_format_check;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM users
    WHERE phone_encrypted IS NULL OR phone_lookup_hash IS NULL
  ) THEN
    RAISE EXCEPTION 'Cannot restore mandatory phone columns while phone-less users exist';
  END IF;
END;
$$;

ALTER TABLE users
  DROP COLUMN IF EXISTS phone_updated_at,
  DROP COLUMN IF EXISTS manager_user_id,
  DROP COLUMN IF EXISTS role,
  DROP COLUMN IF EXISTS username,
  ALTER COLUMN phone_lookup_hash SET NOT NULL,
  ALTER COLUMN phone_encrypted SET NOT NULL;
