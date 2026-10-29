ALTER TABLE users
  ADD COLUMN nickname VARCHAR(40);

UPDATE users
SET nickname = COALESCE(
  username,
  'user-' || SUBSTRING(REPLACE(id::text, '-', '') FROM 1 FOR 8)
);

ALTER TABLE users
  ALTER COLUMN nickname SET NOT NULL,
  ADD CONSTRAINT users_nickname_format_check
    CHECK (nickname ~ '^[a-z0-9][a-z0-9._-]{2,39}$');

CREATE UNIQUE INDEX users_network_nickname_unique_idx
ON users (COALESCE(manager_user_id, id), nickname);

CREATE INDEX users_nickname_lookup_idx
ON users (nickname, status);

ALTER TABLE conversations
  DROP CONSTRAINT conversations_type_check,
  DROP CONSTRAINT conversations_check,
  ADD COLUMN name_encrypted BYTEA,
  ADD COLUMN created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  ADD CONSTRAINT conversations_type_check CHECK (type IN ('DIRECT', 'GROUP')),
  ADD CONSTRAINT conversations_direct_shape_check CHECK (
    (type = 'DIRECT' AND direct_key IS NOT NULL AND name_encrypted IS NULL)
    OR
    (type = 'GROUP' AND direct_key IS NULL AND name_encrypted IS NOT NULL
      AND created_by_user_id IS NOT NULL)
  );

CREATE INDEX conversations_creator_type_idx
ON conversations (created_by_user_id, type, created_at DESC)
WHERE created_by_user_id IS NOT NULL;
