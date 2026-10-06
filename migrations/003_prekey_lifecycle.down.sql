DROP INDEX IF EXISTS device_prekeys_claimed_by_idx;
DROP INDEX IF EXISTS device_prekeys_one_active_signed_idx;

ALTER TABLE device_prekeys
  DROP COLUMN IF EXISTS claimed_by_device_id;

