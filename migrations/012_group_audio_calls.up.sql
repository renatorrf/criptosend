ALTER TABLE call_sessions
  DROP CONSTRAINT call_sessions_media_type_check;

ALTER TABLE call_sessions
  ADD CONSTRAINT call_sessions_media_type_check
  CHECK (media_type IN ('AUDIO', 'VIDEO'));

ALTER TABLE call_participants
  ADD COLUMN invited_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN invited_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

UPDATE call_participants participant
SET invited_by_user_id = session.initiated_by_user_id,
    invited_at = session.created_at
FROM call_sessions session
WHERE session.id = participant.call_id;

ALTER TABLE call_events
  DROP CONSTRAINT call_events_event_type_check;

ALTER TABLE call_events
  ADD CONSTRAINT call_events_event_type_check
  CHECK (event_type IN (
    'STARTED', 'ACCEPTED', 'DECLINED', 'ENDED', 'MISSED', 'FAILED', 'INVITED'
  ));

