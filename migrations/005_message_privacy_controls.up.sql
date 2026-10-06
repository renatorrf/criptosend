ALTER TABLE messages
  ADD COLUMN deletion_reason VARCHAR(16);

UPDATE messages
SET deletion_reason = 'USER'
WHERE deleted_at IS NOT NULL;

ALTER TABLE messages
  ADD CONSTRAINT messages_deletion_reason_check
  CHECK (
    (deleted_at IS NULL AND deletion_reason IS NULL)
    OR
    (deleted_at IS NOT NULL AND deletion_reason IN ('USER', 'EXPIRED'))
  );

ALTER TABLE message_events
  DROP CONSTRAINT message_events_event_type_check;

ALTER TABLE message_events
  ADD CONSTRAINT message_events_event_type_check
  CHECK (event_type IN ('DELETED_FOR_ALL', 'EXPIRED'));

