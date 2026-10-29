DROP INDEX IF EXISTS conversations_creator_type_idx;

DELETE FROM conversations WHERE type = 'GROUP';

ALTER TABLE conversations
  DROP CONSTRAINT conversations_direct_shape_check,
  DROP CONSTRAINT conversations_type_check,
  DROP COLUMN created_by_user_id,
  DROP COLUMN name_encrypted,
  ADD CONSTRAINT conversations_type_check CHECK (type IN ('DIRECT')),
  ADD CONSTRAINT conversations_check CHECK (type <> 'DIRECT' OR direct_key IS NOT NULL);

DROP INDEX IF EXISTS users_nickname_lookup_idx;
DROP INDEX IF EXISTS users_network_nickname_unique_idx;

ALTER TABLE users
  DROP CONSTRAINT users_nickname_format_check,
  DROP COLUMN nickname;
