import { randomUUID } from 'node:crypto';

import { env } from '../config/env.js';
import { quoteIdentifier } from '../database/identifier.js';
import { databasePool } from '../database/pool.js';
import { normalizePhone } from '../identity/phone.js';
import { AppError } from '../http/app-error.js';
import { createPhoneLookupHash } from '../security/hashes.js';

const schema = quoteIdentifier(env.SCHEMA);
const LOOKUP_LIMIT_PER_HOUR = 30;

export class UserService {
  async exactPhoneLookup(
    userId: string,
    deviceId: string,
    phoneInput: string,
    requestId: string,
  ): Promise<boolean> {
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

    const normalized = normalizePhone(phoneInput);
    const result = await databasePool.query(
      `SELECT 1
       FROM ${schema}.users target
       JOIN ${schema}.users actor ON actor.id = $2
       WHERE target.phone_lookup_hash = $1
         AND target.id <> $2
         AND target.discoverable = TRUE
         AND target.status = 'ACTIVE'
         AND (
           actor.role <> 'MANAGER'
           OR target.manager_user_id = actor.id
           OR (
             target.role = 'MANAGER'
             AND EXISTS (
               SELECT 1 FROM ${schema}.manager_network_links link
               WHERE link.manager_low_id = LEAST(actor.id, target.id)
                 AND link.manager_high_id = GREATEST(actor.id, target.id)
             )
           )
         )
       LIMIT 1`,
      [createPhoneLookupHash(normalized), userId],
    );
    await databasePool.query(
      `INSERT INTO ${schema}.security_events
         (id, user_id, device_id, event_type, outcome, request_id)
       VALUES ($1, $2, $3, 'USER_LOOKUP', 'SUCCESS', $4)`,
      [randomUUID(), userId, deviceId, requestId],
    );
    return result.rowCount === 1;
  }
}
