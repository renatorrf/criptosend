CREATE TABLE username_recovery_challenges (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  challenge BYTEA NOT NULL CHECK (octet_length(challenge) = 32),
  attempts SMALLINT NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts SMALLINT NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 10),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  CHECK (expires_at > created_at)
);

CREATE INDEX username_recovery_challenges_expiration_idx
ON username_recovery_challenges (expires_at)
WHERE consumed_at IS NULL;

CREATE INDEX username_recovery_challenges_user_time_idx
ON username_recovery_challenges (user_id, created_at DESC);
