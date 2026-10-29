ALTER TABLE users
  ADD COLUMN security_wiped_at TIMESTAMPTZ;

CREATE INDEX users_security_wiped_at_idx
ON users (security_wiped_at)
WHERE security_wiped_at IS NOT NULL;

