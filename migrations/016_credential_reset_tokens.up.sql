ALTER TABLE user_credentials
  ADD COLUMN reset_required_at TIMESTAMPTZ,
  ADD COLUMN reset_reason VARCHAR(32)
    CHECK (reset_reason IS NULL OR reset_reason IN ('MANAGER_REQUEST', 'FAILED_ATTEMPTS')),
  ADD COLUMN reset_requested_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  ADD CONSTRAINT user_credentials_reset_state_check CHECK (
    (reset_required_at IS NULL AND reset_reason IS NULL)
    OR
    (reset_required_at IS NOT NULL AND reset_reason IS NOT NULL)
  );

CREATE INDEX user_credentials_reset_required_idx
ON user_credentials (reset_required_at)
WHERE reset_required_at IS NOT NULL;

CREATE TABLE user_access_reset_tokens (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL CHECK (token_hash LIKE '$argon2id$%'),
  created_by_user_id UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX user_access_reset_tokens_active_user_idx
ON user_access_reset_tokens (user_id)
WHERE consumed_at IS NULL;

CREATE INDEX user_access_reset_tokens_expiration_idx
ON user_access_reset_tokens (expires_at)
WHERE consumed_at IS NULL;

CREATE TABLE manager_recovery_tokens (
  manager_user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL CHECK (token_hash LIKE '$argon2id$%'),
  generated_by_user_id UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  consumed_at TIMESTAMPTZ
);

CREATE INDEX manager_recovery_tokens_active_idx
ON manager_recovery_tokens (manager_user_id)
WHERE consumed_at IS NULL;
