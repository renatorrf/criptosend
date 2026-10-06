CREATE TABLE device_media_keys (
  device_id UUID PRIMARY KEY,
  user_id UUID NOT NULL,
  public_key BYTEA NOT NULL CHECK (
    octet_length(public_key) >= 64 AND octet_length(public_key) <= 256
  ),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (device_id, user_id)
    REFERENCES devices(id, user_id) ON DELETE CASCADE
);

CREATE INDEX device_media_keys_user_idx
ON device_media_keys (user_id, created_at, device_id);
