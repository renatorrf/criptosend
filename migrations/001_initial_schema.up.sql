CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$;

CREATE TABLE users (
  id UUID PRIMARY KEY,
  phone_encrypted BYTEA NOT NULL CHECK (octet_length(phone_encrypted) > 0),
  phone_lookup_hash CHAR(64) NOT NULL UNIQUE CHECK (phone_lookup_hash ~ '^[a-f0-9]{64}$'),
  name_encrypted BYTEA NOT NULL CHECK (octet_length(name_encrypted) > 0),
  discoverable BOOLEAN NOT NULL DEFAULT TRUE,
  read_receipts_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  typing_indicators_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED', 'DELETED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER users_set_updated_at
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE PROCEDURE set_updated_at();

CREATE TABLE devices (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_name_encrypted BYTEA,
  identity_public_key BYTEA NOT NULL CHECK (octet_length(identity_public_key) > 0),
  registration_id INTEGER NOT NULL CHECK (registration_id >= 0),
  status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  UNIQUE (id, user_id),
  CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL))
);

CREATE INDEX devices_user_status_idx ON devices (user_id, status);

CREATE TABLE device_prekeys (
  id UUID PRIMARY KEY,
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  prekey_id INTEGER NOT NULL CHECK (prekey_id >= 0),
  public_key BYTEA NOT NULL CHECK (octet_length(public_key) > 0),
  is_signed BOOLEAN NOT NULL DEFAULT FALSE,
  signature BYTEA,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (device_id, prekey_id),
  CHECK ((NOT is_signed) OR signature IS NOT NULL)
);

CREATE INDEX device_prekeys_available_idx
ON device_prekeys (device_id, is_signed, prekey_id)
WHERE used_at IS NULL;

CREATE TABLE auth_sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL,
  device_id UUID NOT NULL,
  refresh_token_hash CHAR(64) NOT NULL UNIQUE CHECK (refresh_token_hash ~ '^[a-f0-9]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  FOREIGN KEY (device_id, user_id) REFERENCES devices(id, user_id) ON DELETE CASCADE,
  CHECK (expires_at > created_at)
);

CREATE INDEX auth_sessions_active_idx
ON auth_sessions (user_id, expires_at)
WHERE revoked_at IS NULL;

CREATE TABLE conversations (
  id UUID PRIMARY KEY,
  type VARCHAR(16) NOT NULL DEFAULT 'DIRECT' CHECK (type IN ('DIRECT')),
  direct_key CHAR(64) UNIQUE CHECK (direct_key IS NULL OR direct_key ~ '^[a-f0-9]{64}$'),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (type <> 'DIRECT' OR direct_key IS NOT NULL)
);

CREATE TABLE conversation_members (
  conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'LEFT')),
  PRIMARY KEY (conversation_id, user_id)
);

CREATE INDEX conversation_members_user_status_idx
ON conversation_members (user_id, status, joined_at DESC);

CREATE TABLE messages (
  id UUID PRIMARY KEY,
  conversation_id UUID NOT NULL,
  sender_user_id UUID NOT NULL,
  sender_device_id UUID NOT NULL,
  client_message_id UUID NOT NULL,
  ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) > 0),
  crypto_header BYTEA,
  reply_to_message_id UUID REFERENCES messages(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  deleted_at TIMESTAMPTZ,
  FOREIGN KEY (conversation_id, sender_user_id)
    REFERENCES conversation_members(conversation_id, user_id),
  FOREIGN KEY (sender_device_id, sender_user_id)
    REFERENCES devices(id, user_id),
  UNIQUE (sender_device_id, client_message_id),
  CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE INDEX messages_conversation_created_idx
ON messages (conversation_id, created_at DESC, id);

CREATE INDEX messages_expiration_idx
ON messages (expires_at)
WHERE expires_at IS NOT NULL AND deleted_at IS NULL;

CREATE TABLE message_receipts (
  message_id UUID NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id UUID,
  delivered_at TIMESTAMPTZ,
  read_at TIMESTAMPTZ,
  PRIMARY KEY (message_id, user_id),
  FOREIGN KEY (device_id, user_id) REFERENCES devices(id, user_id) ON DELETE CASCADE,
  CHECK (read_at IS NULL OR delivered_at IS NOT NULL),
  CHECK (read_at IS NULL OR read_at >= delivered_at)
);

CREATE INDEX message_receipts_user_pending_idx
ON message_receipts (user_id, message_id)
WHERE delivered_at IS NULL;

CREATE TABLE push_subscriptions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL,
  device_id UUID NOT NULL,
  endpoint_encrypted BYTEA NOT NULL CHECK (octet_length(endpoint_encrypted) > 0),
  endpoint_lookup_hash CHAR(64) NOT NULL UNIQUE CHECK (endpoint_lookup_hash ~ '^[a-f0-9]{64}$'),
  p256dh_encrypted BYTEA NOT NULL CHECK (octet_length(p256dh_encrypted) > 0),
  auth_encrypted BYTEA NOT NULL CHECK (octet_length(auth_encrypted) > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ,
  FOREIGN KEY (device_id, user_id) REFERENCES devices(id, user_id) ON DELETE CASCADE
);

CREATE TRIGGER push_subscriptions_set_updated_at
BEFORE UPDATE ON push_subscriptions
FOR EACH ROW EXECUTE PROCEDURE set_updated_at();

CREATE INDEX push_subscriptions_device_active_idx
ON push_subscriptions (device_id)
WHERE revoked_at IS NULL;

CREATE TABLE security_events (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
  event_type VARCHAR(64) NOT NULL,
  outcome VARCHAR(16) NOT NULL CHECK (outcome IN ('SUCCESS', 'FAILURE', 'BLOCKED')),
  request_id VARCHAR(128),
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX security_events_user_time_idx
ON security_events (user_id, occurred_at DESC);

CREATE INDEX security_events_type_time_idx
ON security_events (event_type, occurred_at DESC);
