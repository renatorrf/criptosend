ALTER TABLE users
  ALTER COLUMN phone_encrypted DROP NOT NULL,
  ALTER COLUMN phone_lookup_hash DROP NOT NULL,
  ADD COLUMN username VARCHAR(40),
  ADD COLUMN role VARCHAR(24) NOT NULL DEFAULT 'USER'
    CHECK (role IN ('PLATFORM_ADMIN', 'MANAGER', 'USER')),
  ADD COLUMN manager_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN phone_updated_at TIMESTAMPTZ;

ALTER TABLE users
  ADD CONSTRAINT users_username_format_check
  CHECK (username IS NULL OR username ~ '^[a-z0-9][a-z0-9._-]{2,39}$');

CREATE UNIQUE INDEX users_username_unique_idx
ON users (username)
WHERE username IS NOT NULL;

CREATE INDEX users_manager_status_idx
ON users (manager_user_id, status)
WHERE manager_user_id IS NOT NULL;

CREATE TABLE invitation_codes (
  id UUID PRIMARY KEY,
  code_hash CHAR(64) NOT NULL UNIQUE CHECK (code_hash ~ '^[a-f0-9]{64}$'),
  role VARCHAR(24) NOT NULL CHECK (role IN ('MANAGER', 'USER')),
  created_by_user_id UUID NOT NULL REFERENCES users(id),
  used_by_user_id UUID REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  CHECK (expires_at > created_at),
  CHECK ((used_at IS NULL) = (used_by_user_id IS NULL)),
  CHECK (NOT (used_at IS NOT NULL AND revoked_at IS NOT NULL))
);

CREATE INDEX invitation_codes_creator_time_idx
ON invitation_codes (created_by_user_id, created_at DESC);

CREATE INDEX invitation_codes_active_idx
ON invitation_codes (expires_at)
WHERE used_at IS NULL AND revoked_at IS NULL;
