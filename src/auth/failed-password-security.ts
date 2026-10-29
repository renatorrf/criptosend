import { randomUUID } from 'node:crypto';

import type { PoolClient } from 'pg';

import { env } from '../config/env.js';
import { quoteIdentifier } from '../database/identifier.js';

const schema = quoteIdentifier(env.SCHEMA);

export const FAILED_PASSWORD_WIPE_THRESHOLD = 3;

export function shouldWipeAfterFailedPassword(
  previousFailedAttempts: number,
  wipeEligible: boolean,
): boolean {
  return wipeEligible && previousFailedAttempts + 1 === FAILED_PASSWORD_WIPE_THRESHOLD;
}

interface FailedPasswordAttemptInput {
  userId: string;
  requestId: string;
  wipeEligible: boolean;
  deviceId?: string | undefined;
  eventType?: string | undefined;
}

export async function registerFailedPasswordAttempt(
  client: PoolClient,
  input: FailedPasswordAttemptInput,
): Promise<{ failedAttempts: number; wiped: boolean }> {
  const updated = await client.query<{ failed_attempts: number }>(
    `UPDATE ${schema}.user_credentials
     SET failed_attempts = failed_attempts + 1,
         locked_until = NULL
     WHERE user_id = $1
     RETURNING failed_attempts`,
    [input.userId],
  );
  const failedAttempts = updated.rows[0]?.failed_attempts ?? 0;
  const wiped = shouldWipeAfterFailedPassword(failedAttempts - 1, input.wipeEligible);

  await client.query(
    `INSERT INTO ${schema}.security_events
       (id, user_id, device_id, event_type, outcome, request_id)
     VALUES ($1, $2, $3, $4, 'FAILURE', $5)`,
    [
      randomUUID(),
      input.userId,
      input.deviceId ?? null,
      input.eventType ?? 'LOGIN',
      input.requestId,
    ],
  );

  if (wiped) {
    await wipeUserPrivateData(client, input.userId, input.requestId);
  }

  return { failedAttempts, wiped };
}

async function wipeUserPrivateData(
  client: PoolClient,
  userId: string,
  requestId: string,
): Promise<void> {
  // End active calls before removing this user from their participant lists.
  await client.query(
    `UPDATE ${schema}.call_sessions call
     SET status = 'ENDED', ended_at = NOW()
     WHERE call.status IN ('RINGING', 'ACTIVE')
       AND EXISTS (
         SELECT 1 FROM ${schema}.call_participants participant
         WHERE participant.call_id = call.id AND participant.user_id = $1
       )`,
    [userId],
  );
  await client.query(
    `UPDATE ${schema}.call_participants participant
     SET left_at = COALESCE(
       participant.left_at,
       CASE WHEN participant.joined_at IS NULL THEN NULL ELSE NOW() END
     )
     WHERE participant.call_id IN (
       SELECT call_id FROM ${schema}.call_participants WHERE user_id = $1
     )`,
    [userId],
  );
  await client.query(
    `DELETE FROM ${schema}.call_sessions WHERE initiated_by_user_id = $1`,
    [userId],
  );
  await client.query(
    `DELETE FROM ${schema}.call_participants WHERE user_id = $1`,
    [userId],
  );
  await client.query(
    `UPDATE ${schema}.call_events SET actor_user_id = NULL WHERE actor_user_id = $1`,
    [userId],
  );

  // Delete content created by the user and remove delivery/read metadata owned by them.
  await client.query(
    `DELETE FROM ${schema}.message_receipts WHERE user_id = $1`,
    [userId],
  );
  await client.query(
    `DELETE FROM ${schema}.messages WHERE sender_user_id = $1`,
    [userId],
  );
  await client.query(
    `UPDATE ${schema}.conversation_members
     SET status = 'LEFT'
     WHERE user_id = $1`,
    [userId],
  );

  // Recovery material, push endpoints, keys and sessions are private device state.
  // Device registrations remain so a later correct password can still create a session;
  // the endpoint intentionally has no account lockout.
  await client.query(
    `DELETE FROM ${schema}.account_recovery_credentials WHERE user_id = $1`,
    [userId],
  );
  await client.query(
    `DELETE FROM ${schema}.account_reset_requests WHERE user_id = $1`,
    [userId],
  );
  await client.query(
    `DELETE FROM ${schema}.username_recovery_challenges WHERE user_id = $1`,
    [userId],
  );
  await client.query(`DELETE FROM ${schema}.auth_sessions WHERE user_id = $1`, [userId]);
  await client.query(`DELETE FROM ${schema}.push_subscriptions WHERE user_id = $1`, [userId]);
  await client.query(`DELETE FROM ${schema}.device_media_keys WHERE user_id = $1`, [userId]);
  await client.query(
    `DELETE FROM ${schema}.device_prekeys
     WHERE device_id IN (SELECT id FROM ${schema}.devices WHERE user_id = $1)`,
    [userId],
  );

  await client.query(
    `UPDATE ${schema}.users
     SET security_wiped_at = NOW()
     WHERE id = $1`,
    [userId],
  );
  await client.query(
    `INSERT INTO ${schema}.security_events
       (id, user_id, device_id, event_type, outcome, request_id)
     VALUES ($1, $2, NULL, 'FAILED_PASSWORD_DATA_WIPE', 'SUCCESS', $3)`,
    [randomUUID(), userId, requestId],
  );
}
