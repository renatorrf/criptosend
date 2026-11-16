CREATE TABLE user_network_memberships (
  manager_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (manager_user_id, user_id),
  CHECK (manager_user_id <> user_id)
);

CREATE INDEX user_network_memberships_user_idx
ON user_network_memberships (user_id, manager_user_id);

CREATE VIEW network_members AS
SELECT manager_user_id, id AS user_id
FROM users
WHERE role = 'USER' AND manager_user_id IS NOT NULL
UNION
SELECT manager_user_id, user_id FROM user_network_memberships;

CREATE VIEW active_network_members AS
SELECT membership.manager_user_id, membership.user_id
FROM network_members membership
JOIN users member ON member.id = membership.user_id AND member.role = 'USER' AND member.status = 'ACTIVE'
JOIN users manager ON manager.id = membership.manager_user_id AND manager.role = 'MANAGER' AND manager.status = 'ACTIVE'
UNION ALL
SELECT id, id FROM users WHERE role = 'MANAGER' AND status = 'ACTIVE';
