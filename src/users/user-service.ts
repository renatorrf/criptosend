import { randomUUID } from 'node:crypto';

import { env } from '../config/env.js';
import { quoteIdentifier } from '../database/identifier.js';
import { databasePool } from '../database/pool.js';
import { AppError } from '../http/app-error.js';
import { decryptField } from '../security/field-crypto.js';

const schema = quoteIdentifier(env.SCHEMA);
const LOOKUP_LIMIT_PER_HOUR = 30;

export class UserService {
  async exactNicknameLookup(
    userId: string,
    deviceId: string,
    nicknameInput: string,
    requestId: string,
  ): Promise<{ id: string; name: string; nickname: string } | null> {
    const recent = await databasePool.query<{ count: string }>(
      `SELECT COUNT(*)::text AS count
       FROM ${schema}.security_events
       WHERE user_id = $1
         AND event_type = 'USER_LOOKUP'
         AND occurred_at > NOW() - INTERVAL '1 hour'`,
      [userId],
    );
    if (Number(recent.rows[0]?.count ?? 0) >= LOOKUP_LIMIT_PER_HOUR) {
      throw new AppError(429, 'RATE_LIMITED');
    }

    const nickname = nicknameInput.trim().normalize('NFKC').toLowerCase();
    const result = await databasePool.query<{
      id: string;
      name_encrypted: Buffer;
      nickname: string;
    }>(
      `SELECT target.id, target.name_encrypted, target.nickname
       FROM ${schema}.users target
       JOIN ${schema}.users actor ON actor.id = $2
       WHERE target.nickname = $1
         AND target.id <> $2
         AND target.status = 'ACTIVE'
         AND (
           COALESCE(target.manager_user_id, target.id) =
             COALESCE(actor.manager_user_id, actor.id)
           OR (
             actor.role = 'MANAGER'
             AND target.role = 'MANAGER'
             AND EXISTS (
               SELECT 1 FROM ${schema}.manager_network_links link
               WHERE link.manager_low_id = LEAST(actor.id, target.id)
                 AND link.manager_high_id = GREATEST(actor.id, target.id)
             )
           )
         )
       LIMIT 1`,
      [nickname, userId],
    );
    await databasePool.query(
      `INSERT INTO ${schema}.security_events
         (id, user_id, device_id, event_type, outcome, request_id)
       VALUES ($1, $2, $3, 'USER_LOOKUP', 'SUCCESS', $4)`,
      [randomUUID(), userId, deviceId, requestId],
    );
    const found = result.rows[0];
    return found
      ? {
          id: found.id,
          name: decryptField(found.name_encrypted, 'user-name'),
          nickname: found.nickname,
        }
      : null;
  }
}
