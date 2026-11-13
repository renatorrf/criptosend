ALTER TABLE messages ADD COLUMN envelope_at_rest BYTEA;

ALTER TABLE messages ADD CONSTRAINT messages_envelope_at_rest_exclusive
  CHECK (envelope_at_rest IS NULL OR (
    deleted_at IS NULL AND ciphertext = decode('00', 'hex') AND crypto_header IS NULL
  ));

CREATE INDEX messages_unsealed_envelope_idx ON messages (id)
  WHERE envelope_at_rest IS NULL AND deleted_at IS NULL;

CREATE FUNCTION clear_deleted_message_envelope() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.deleted_at IS NOT NULL THEN
    NEW.envelope_at_rest := NULL;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER messages_clear_deleted_envelope
  BEFORE UPDATE OF deleted_at ON messages
  FOR EACH ROW EXECUTE PROCEDURE clear_deleted_message_envelope();
