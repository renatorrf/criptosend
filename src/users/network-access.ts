import { env } from '../config/env.js';
import { quoteIdentifier } from '../database/identifier.js';

const schema = quoteIdentifier(env.SCHEMA);

// The callers use actor and target as aliases for the two user rows.
export const sharedNetworksSql = `
  SELECT mine.manager_user_id
  FROM ${schema}.active_network_members mine
  JOIN ${schema}.active_network_members theirs USING (manager_user_id)
  WHERE mine.user_id = actor.id AND theirs.user_id = target.id`;

export const linkedManagersSql = `
  actor.role = 'MANAGER' AND target.role = 'MANAGER' AND EXISTS (
    SELECT 1 FROM ${schema}.manager_network_links link
    WHERE link.manager_low_id = LEAST(actor.id, target.id)
      AND link.manager_high_id = GREATEST(actor.id, target.id)
  )`;
