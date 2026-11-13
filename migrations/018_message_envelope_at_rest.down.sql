DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM messages WHERE envelope_at_rest IS NOT NULL) THEN
    RAISE EXCEPTION 'Cannot roll back while protected message envelopes are stored';
  END IF;
END;
$$;

DROP TRIGGER messages_clear_deleted_envelope ON messages;
DROP FUNCTION clear_deleted_message_envelope();
DROP INDEX messages_unsealed_envelope_idx;
ALTER TABLE messages DROP CONSTRAINT messages_envelope_at_rest_exclusive,
  DROP COLUMN envelope_at_rest;
