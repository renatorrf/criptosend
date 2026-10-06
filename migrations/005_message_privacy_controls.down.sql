ALTER TABLE message_events
  DROP CONSTRAINT IF EXISTS message_events_event_type_check;

DELETE FROM message_events
WHERE event_type = 'EXPIRED';

ALTER TABLE message_events
  ADD CONSTRAINT message_events_event_type_check
  CHECK (event_type IN ('DELETED_FOR_ALL'));

ALTER TABLE messages
  DROP CONSTRAINT IF EXISTS messages_deletion_reason_check;

ALTER TABLE messages
  DROP COLUMN IF EXISTS deletion_reason;
