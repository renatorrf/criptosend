CREATE TABLE user_credentials (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  pin_hash TEXT NOT NULL CHECK (length(pin_hash) >= 32),
  failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
  locked_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER user_credentials_set_updated_at
BEFORE UPDATE ON user_credentials
FOR EACH ROW EXECUTE PROCEDURE set_updated_at();

CREATE TABLE phone_verification_challenges (
  id UUID PRIMARY KEY,
  phone_encrypted BYTEA NOT NULL CHECK (octet_length(phone_encrypted) > 0),
  phone_lookup_hash CHAR(64) NOT NULL CHECK (phone_lookup_hash ~ '^[a-f0-9]{64}$'),
  code_lookup_hash CHAR(64) NOT NULL CHECK (code_lookup_hash ~ '^[a-f0-9]{64}$'),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts INTEGER NOT NULL DEFAULT 5 CHECK (max_attempts BETWEEN 1 AND 10),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (expires_at > created_at)
);

CREATE INDEX phone_verification_phone_time_idx
ON phone_verification_challenges (phone_lookup_hash, created_at DESC);

CREATE INDEX phone_verification_expiration_idx
ON phone_verification_challenges (expires_at)
WHERE consumed_at IS NULL;

ALTER TABLE auth_sessions
  ADD COLUMN session_family_id UUID,
  ADD COLUMN rotated_from_id UUID REFERENCES auth_sessions(id) ON DELETE SET NULL,
  ADD COLUMN replaced_by_id UUID REFERENCES auth_sessions(id) ON DELETE SET NULL;

CREATE INDEX auth_sessions_family_idx
ON auth_sessions (session_family_id, created_at DESC);

