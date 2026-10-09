CREATE TABLE manager_invitation_balances (
  manager_user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  available_credits INTEGER NOT NULL DEFAULT 10 CHECK (available_credits >= 0),
  consumed_credits INTEGER NOT NULL DEFAULT 0 CHECK (consumed_credits >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER manager_invitation_balances_set_updated_at
BEFORE UPDATE ON manager_invitation_balances
FOR EACH ROW EXECUTE PROCEDURE set_updated_at();

INSERT INTO manager_invitation_balances
  (manager_user_id, available_credits, consumed_credits)
SELECT u.id,
       GREATEST(0, 10 - COUNT(i.id)::INTEGER),
       COUNT(i.id)::INTEGER
FROM users u
LEFT JOIN invitation_codes i
  ON i.created_by_user_id = u.id
 AND i.role = 'USER'
 AND i.used_at IS NOT NULL
WHERE u.role = 'MANAGER'
GROUP BY u.id;

CREATE TABLE manager_invitation_grants (
  id UUID PRIMARY KEY,
  manager_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  granted_by_user_id UUID NOT NULL REFERENCES users(id),
  amount INTEGER NOT NULL CHECK (amount BETWEEN 1 AND 1000),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX manager_invitation_grants_manager_time_idx
ON manager_invitation_grants (manager_user_id, created_at DESC);

CREATE TABLE manager_network_requests (
  id UUID PRIMARY KEY,
  requester_manager_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_manager_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status VARCHAR(16) NOT NULL DEFAULT 'PENDING'
    CHECK (status IN ('PENDING', 'ACCEPTED', 'DECLINED', 'CANCELLED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  responded_at TIMESTAMPTZ,
  CHECK (requester_manager_id <> target_manager_id),
  CHECK (expires_at > created_at),
  CHECK ((status = 'PENDING') = (responded_at IS NULL))
);

CREATE UNIQUE INDEX manager_network_requests_pending_pair_idx
ON manager_network_requests (
  LEAST(requester_manager_id, target_manager_id),
  GREATEST(requester_manager_id, target_manager_id)
)
WHERE status = 'PENDING';

CREATE INDEX manager_network_requests_target_status_idx
ON manager_network_requests (target_manager_id, status, created_at DESC);

CREATE INDEX manager_network_requests_requester_status_idx
ON manager_network_requests (requester_manager_id, status, created_at DESC);

CREATE TABLE manager_network_links (
  manager_low_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  manager_high_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_by_user_id UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (manager_low_id, manager_high_id),
  CHECK (manager_low_id < manager_high_id)
);

CREATE INDEX manager_network_links_high_idx
ON manager_network_links (manager_high_id, created_at DESC);
