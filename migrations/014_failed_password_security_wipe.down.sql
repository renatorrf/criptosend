DROP INDEX IF EXISTS users_security_wiped_at_idx;

ALTER TABLE users
  DROP COLUMN IF EXISTS security_wiped_at;

