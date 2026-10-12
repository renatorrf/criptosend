ALTER TABLE call_events
  DROP CONSTRAINT call_events_event_type_check;

ALTER TABLE call_events
  ADD CONSTRAINT call_events_event_type_check
  CHECK (event_type IN ('STARTED', 'ACCEPTED', 'DECLINED', 'ENDED', 'MISSED', 'FAILED'));

ALTER TABLE call_participants
  DROP COLUMN invited_at,
  DROP COLUMN invited_by_user_id;

ALTER TABLE call_sessions
  DROP CONSTRAINT call_sessions_media_type_check;

ALTER TABLE call_sessions
  ADD CONSTRAINT call_sessions_media_type_check
  CHECK (media_type IN ('VIDEO'));
