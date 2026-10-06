CREATE TABLE message_events (
  id UUID PRIMARY KEY,
  message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  actor_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  event_type VARCHAR(32) NOT NULL CHECK (event_type IN ('DELETED_FOR_ALL')),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX message_events_message_time_idx
ON message_events (message_id, occurred_at DESC);

CREATE INDEX messages_conversation_active_idx
ON messages (conversation_id, created_at DESC, id)
WHERE deleted_at IS NULL;

