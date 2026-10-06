ALTER TABLE device_prekeys
  ADD COLUMN claimed_by_device_id UUID REFERENCES devices(id) ON DELETE SET NULL;

CREATE UNIQUE INDEX device_prekeys_one_active_signed_idx
ON device_prekeys (device_id)
WHERE is_signed = TRUE AND used_at IS NULL;

CREATE INDEX device_prekeys_claimed_by_idx
ON device_prekeys (claimed_by_device_id)
WHERE claimed_by_device_id IS NOT NULL;

