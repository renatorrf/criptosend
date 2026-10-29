ALTER TABLE users
  ADD COLUMN message_retention_seconds INTEGER
  CHECK (
    message_retention_seconds IS NULL
    OR message_retention_seconds BETWEEN 60 AND 2592000
  );

