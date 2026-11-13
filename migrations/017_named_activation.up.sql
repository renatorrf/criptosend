ALTER TABLE invitation_codes
  ADD COLUMN assigned_username VARCHAR(40)
    CHECK (assigned_username IS NULL OR assigned_username ~ '^[a-z0-9][a-z0-9._-]{2,39}$');

CREATE INDEX invitation_codes_pending_username_idx
ON invitation_codes (assigned_username, expires_at)
WHERE assigned_username IS NOT NULL AND used_at IS NULL AND revoked_at IS NULL;
