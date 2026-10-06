ALTER TABLE user_credentials
  RENAME COLUMN pin_hash TO password_hash;

ALTER TABLE phone_verification_challenges
  ADD COLUMN purpose VARCHAR(24) NOT NULL DEFAULT 'ACCESS'
    CHECK (purpose IN ('ACCESS', 'PASSWORD_RECOVERY', 'ADMIN_RESET')),
  ADD COLUMN requested_name_encrypted BYTEA,
  ADD COLUMN verified_at TIMESTAMPTZ,
  ADD COLUMN flow_token_hash CHAR(64)
    CHECK (flow_token_hash IS NULL OR flow_token_hash ~ '^[a-f0-9]{64}$'),
  ADD COLUMN flow_expires_at TIMESTAMPTZ,
  ADD COLUMN recovery_challenge BYTEA;

CREATE TABLE account_recovery_credentials (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  key_id UUID NOT NULL UNIQUE,
  public_key BYTEA NOT NULL CHECK (octet_length(public_key) BETWEEN 64 AND 256),
  wrapped_private_key BYTEA NOT NULL CHECK (octet_length(wrapped_private_key) > 32),
  wrapping_iv BYTEA NOT NULL CHECK (octet_length(wrapping_iv) = 12),
  kdf_salt BYTEA NOT NULL CHECK (octet_length(kdf_salt) BETWEEN 16 AND 64),
  kdf_parameters JSONB NOT NULL,
  version SMALLINT NOT NULL DEFAULT 1 CHECK (version = 1),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER account_recovery_credentials_set_updated_at
BEFORE UPDATE ON account_recovery_credentials
FOR EACH ROW EXECUTE PROCEDURE set_updated_at();

CREATE TABLE account_reset_requests (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  claim_token_hash CHAR(64) NOT NULL UNIQUE CHECK (claim_token_hash ~ '^[a-f0-9]{64}$'),
  status VARCHAR(16) NOT NULL DEFAULT 'PENDING'
    CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'COMPLETED', 'EXPIRED')),
  requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  approved_at TIMESTAMPTZ,
  approved_by VARCHAR(120),
  completed_at TIMESTAMPTZ,
  CHECK (expires_at > requested_at),
  CHECK ((status IN ('APPROVED', 'COMPLETED')) = (approved_at IS NOT NULL))
);

CREATE INDEX account_reset_requests_user_status_idx
ON account_reset_requests (user_id, status, requested_at DESC);

CREATE INDEX phone_verification_flow_expiration_idx
ON phone_verification_challenges (flow_expires_at)
WHERE flow_token_hash IS NOT NULL AND consumed_at IS NULL;
