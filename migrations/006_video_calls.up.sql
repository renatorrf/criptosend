CREATE TABLE call_sessions (
  id UUID PRIMARY KEY,
  conversation_id UUID NOT NULL,
  initiated_by_user_id UUID NOT NULL,
  media_type VARCHAR(16) NOT NULL DEFAULT 'VIDEO' CHECK (media_type IN ('VIDEO')),
  status VARCHAR(16) NOT NULL DEFAULT 'RINGING'
    CHECK (status IN ('RINGING', 'ACTIVE', 'DECLINED', 'ENDED', 'MISSED', 'FAILED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  answered_at TIMESTAMPTZ,
  ended_at TIMESTAMPTZ,
  FOREIGN KEY (conversation_id, initiated_by_user_id)
    REFERENCES conversation_members(conversation_id, user_id) ON DELETE CASCADE,
  CHECK (answered_at IS NULL OR answered_at >= created_at),
  CHECK (ended_at IS NULL OR ended_at >= created_at),
  CHECK ((status = 'ACTIVE') = (answered_at IS NOT NULL AND ended_at IS NULL)),
  CHECK ((status IN ('DECLINED', 'ENDED', 'MISSED', 'FAILED')) = (ended_at IS NOT NULL))
);

CREATE UNIQUE INDEX call_sessions_conversation_live_idx
ON call_sessions (conversation_id)
WHERE status IN ('RINGING', 'ACTIVE');

CREATE INDEX call_sessions_conversation_created_idx
ON call_sessions (conversation_id, created_at DESC, id);

CREATE INDEX call_sessions_ringing_timeout_idx
ON call_sessions (created_at)
WHERE status = 'RINGING';

CREATE TABLE call_participants (
  call_id UUID NOT NULL REFERENCES call_sessions(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  joined_at TIMESTAMPTZ,
  left_at TIMESTAMPTZ,
  PRIMARY KEY (call_id, user_id),
  CHECK (left_at IS NULL OR joined_at IS NOT NULL),
  CHECK (left_at IS NULL OR left_at >= joined_at)
);

CREATE INDEX call_participants_user_idx
ON call_participants (user_id, call_id);

CREATE TABLE call_events (
  id UUID PRIMARY KEY,
  call_id UUID NOT NULL REFERENCES call_sessions(id) ON DELETE CASCADE,
  actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  event_type VARCHAR(16) NOT NULL
    CHECK (event_type IN ('STARTED', 'ACCEPTED', 'DECLINED', 'ENDED', 'MISSED', 'FAILED')),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX call_events_call_time_idx
ON call_events (call_id, occurred_at, id);
