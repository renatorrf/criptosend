import { randomUUID } from 'node:crypto';

import type { PoolClient } from 'pg';

import { env } from '../config/env.js';
import type { ConversationService } from '../conversations/conversation-service.js';
import { quoteIdentifier } from '../database/identifier.js';
import { databasePool } from '../database/pool.js';
import { AppError } from '../http/app-error.js';

const schema = quoteIdentifier(env.SCHEMA);

export type CallStatus =
  | 'RINGING'
  | 'ACTIVE'
  | 'DECLINED'
  | 'ENDED'
  | 'MISSED'
  | 'FAILED';

interface CallRow {
  id: string;
  conversation_id: string;
  initiated_by_user_id: string;
  status: CallStatus;
  created_at: Date;
  answered_at: Date | null;
  ended_at: Date | null;
}

export interface CallView {
  id: string;
  conversationId: string;
  initiatedByUserId: string;
  status: CallStatus;
  createdAt: Date;
  answeredAt: Date | null;
  endedAt: Date | null;
  participantUserIds: string[];
}

async function beginTransaction(): Promise<PoolClient> {
  const client = await databasePool.connect();
  await client.query('BEGIN');
  return client;
}

function mapCall(row: CallRow, participantUserIds: string[]): CallView {
  return {
    id: row.id,
    conversationId: row.conversation_id,
    initiatedByUserId: row.initiated_by_user_id,
    status: row.status,
    createdAt: row.created_at,
    answeredAt: row.answered_at,
    endedAt: row.ended_at,
    participantUserIds,
  };
}

async function listParticipants(
  client: Pick<PoolClient, 'query'>,
  callId: string,
): Promise<string[]> {
  const result = await client.query<{ user_id: string }>(
    `SELECT user_id FROM ${schema}.call_participants
     WHERE call_id = $1 ORDER BY user_id`,
    [callId],
  );
  return result.rows.map(({ user_id }) => user_id);
}

async function addEvent(
  client: Pick<PoolClient, 'query'>,
  callId: string,
  actorUserId: string | null,
  eventType: 'STARTED' | 'ACCEPTED' | 'DECLINED' | 'ENDED' | 'MISSED' | 'FAILED',
): Promise<void> {
  await client.query(
    `INSERT INTO ${schema}.call_events (id, call_id, actor_user_id, event_type)
     VALUES ($1, $2, $3, $4)`,
    [randomUUID(), callId, actorUserId, eventType],
  );
}

export class CallService {
  constructor(private readonly conversations: ConversationService) {}

  async start(userId: string, conversationId: string): Promise<CallView> {
    const client = await beginTransaction();
    try {
      await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [
        `criptsend:call:${conversationId}`,
      ]);
      const conversation = await client.query<{ user_id: string }>(
        `SELECT cm.user_id
         FROM ${schema}.conversations c
         JOIN ${schema}.conversation_members cm ON cm.conversation_id = c.id
         JOIN ${schema}.users u ON u.id = cm.user_id AND u.status = 'ACTIVE'
         WHERE c.id = $1 AND c.type = 'DIRECT' AND cm.status = 'ACTIVE'
         ORDER BY cm.user_id
         FOR UPDATE OF c`,
        [conversationId],
      );
      const participantUserIds = conversation.rows.map(({ user_id }) => user_id);
      if (participantUserIds.length !== 2 || !participantUserIds.includes(userId)) {
        throw new AppError(404, 'CONVERSATION_NOT_FOUND');
      }
      for (const participantUserId of participantUserIds) {
        await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [
          `criptsend:call-user:${participantUserId}`,
        ]);
      }
      const busyParticipant = await client.query(
        `SELECT 1
         FROM ${schema}.call_participants p
         JOIN ${schema}.call_sessions c ON c.id = p.call_id
         WHERE p.user_id = ANY($1::uuid[]) AND c.status IN ('RINGING', 'ACTIVE')
         LIMIT 1`,
        [participantUserIds],
      );
      if (busyParticipant.rowCount !== 0) {
        throw new AppError(409, 'CALL_PARTICIPANT_BUSY');
      }

      const inserted = await client.query<CallRow>(
        `INSERT INTO ${schema}.call_sessions
           (id, conversation_id, initiated_by_user_id)
         VALUES ($1, $2, $3)
         RETURNING id, conversation_id, initiated_by_user_id, status,
                   created_at, answered_at, ended_at`,
        [randomUUID(), conversationId, userId],
      );
      const call = inserted.rows[0];
      if (!call) {
        throw new Error('Call insert returned no identifier.');
      }
      await client.query(
        `INSERT INTO ${schema}.call_participants (call_id, user_id, joined_at)
         SELECT $1, member_id, CASE WHEN member_id = $2 THEN NOW() ELSE NULL END
         FROM unnest($3::uuid[]) AS member_id`,
        [call.id, userId, participantUserIds],
      );
      await addEvent(client, call.id, userId, 'STARTED');
      await client.query('COMMIT');
      return mapCall(call, participantUserIds);
    } catch (error) {
      await client.query('ROLLBACK');
      if (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        error.code === '23505'
      ) {
        throw new AppError(409, 'CALL_ALREADY_ACTIVE');
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async accept(userId: string, callId: string): Promise<CallView> {
    return this.transition(callId, userId, 'ACCEPT');
  }

  async decline(userId: string, callId: string): Promise<CallView> {
    return this.transition(callId, userId, 'DECLINE');
  }

  async end(userId: string, callId: string): Promise<CallView> {
    return this.transition(callId, userId, 'END');
  }

  async getRelayRecipients(userId: string, callId: string): Promise<string[]> {
    const result = await databasePool.query<{ user_id: string }>(
      `SELECT target.user_id
       FROM ${schema}.call_sessions c
       JOIN ${schema}.call_participants sender
         ON sender.call_id = c.id AND sender.user_id = $2
       JOIN ${schema}.call_participants target
         ON target.call_id = c.id AND target.user_id <> $2
       WHERE c.id = $1 AND c.status = 'ACTIVE'`,
      [callId, userId],
    );
    return result.rows.map(({ user_id }) => user_id);
  }

  async list(
    userId: string,
    conversationId: string,
    limit: number,
  ): Promise<CallView[]> {
    await this.conversations.assertMember(userId, conversationId);
    const result = await databasePool.query<CallRow & { participant_user_ids: string[] }>(
      `SELECT c.id, c.conversation_id, c.initiated_by_user_id, c.status,
              c.created_at, c.answered_at, c.ended_at,
              array_agg(p.user_id ORDER BY p.user_id) AS participant_user_ids
       FROM ${schema}.call_sessions c
       JOIN ${schema}.call_participants p ON p.call_id = c.id
       WHERE c.conversation_id = $1
       GROUP BY c.id
       ORDER BY c.created_at DESC, c.id DESC
       LIMIT $2`,
      [conversationId, limit],
    );
    return result.rows.map((row) => mapCall(row, row.participant_user_ids));
  }

  async expireRinging(): Promise<CallView[]> {
    const client = await beginTransaction();
    try {
      const expired = await client.query<CallRow>(
        `UPDATE ${schema}.call_sessions
         SET status = 'MISSED', ended_at = NOW()
         WHERE id IN (
           SELECT id FROM ${schema}.call_sessions
           WHERE status = 'RINGING'
             AND created_at <= NOW() - ($1::text || ' seconds')::interval
           ORDER BY created_at
           FOR UPDATE SKIP LOCKED
           LIMIT 100
         )
         RETURNING id, conversation_id, initiated_by_user_id, status,
                   created_at, answered_at, ended_at`,
        [env.RTC_RING_TIMEOUT_SECONDS],
      );
      const calls: CallView[] = [];
      for (const row of expired.rows) {
        await addEvent(client, row.id, null, 'MISSED');
        calls.push(mapCall(row, await listParticipants(client, row.id)));
      }
      await client.query('COMMIT');
      return calls;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  private async transition(
    callId: string,
    userId: string,
    action: 'ACCEPT' | 'DECLINE' | 'END',
  ): Promise<CallView> {
    const client = await beginTransaction();
    try {
      const result = await client.query<CallRow>(
        `SELECT c.id, c.conversation_id, c.initiated_by_user_id, c.status,
                c.created_at, c.answered_at, c.ended_at
         FROM ${schema}.call_sessions c
         JOIN ${schema}.call_participants p ON p.call_id = c.id
         WHERE c.id = $1 AND p.user_id = $2
         FOR UPDATE OF c`,
        [callId, userId],
      );
      const call = result.rows[0];
      if (!call) {
        throw new AppError(404, 'CALL_NOT_FOUND');
      }

      let updated: CallRow | undefined;
      if (action === 'ACCEPT') {
        if (call.status !== 'RINGING' || call.initiated_by_user_id === userId) {
          throw new AppError(409, 'CALL_STATE_CONFLICT');
        }
        updated = (
          await client.query<CallRow>(
            `UPDATE ${schema}.call_sessions
             SET status = 'ACTIVE', answered_at = NOW()
             WHERE id = $1
             RETURNING id, conversation_id, initiated_by_user_id, status,
                       created_at, answered_at, ended_at`,
            [callId],
          )
        ).rows[0];
        await client.query(
          `UPDATE ${schema}.call_participants
           SET joined_at = COALESCE(joined_at, NOW())
           WHERE call_id = $1 AND user_id = $2`,
          [callId, userId],
        );
        await addEvent(client, callId, userId, 'ACCEPTED');
      } else if (action === 'DECLINE') {
        if (call.status !== 'RINGING' || call.initiated_by_user_id === userId) {
          throw new AppError(409, 'CALL_STATE_CONFLICT');
        }
        updated = (
          await client.query<CallRow>(
            `UPDATE ${schema}.call_sessions
             SET status = 'DECLINED', ended_at = NOW()
             WHERE id = $1
             RETURNING id, conversation_id, initiated_by_user_id, status,
                       created_at, answered_at, ended_at`,
            [callId],
          )
        ).rows[0];
        await addEvent(client, callId, userId, 'DECLINED');
      } else {
        if (call.status !== 'RINGING' && call.status !== 'ACTIVE') {
          throw new AppError(409, 'CALL_STATE_CONFLICT');
        }
        updated = (
          await client.query<CallRow>(
            `UPDATE ${schema}.call_sessions
             SET status = 'ENDED', ended_at = NOW()
             WHERE id = $1
             RETURNING id, conversation_id, initiated_by_user_id, status,
                       created_at, answered_at, ended_at`,
            [callId],
          )
        ).rows[0];
        await client.query(
          `UPDATE ${schema}.call_participants
           SET left_at = CASE WHEN joined_at IS NULL THEN left_at ELSE COALESCE(left_at, NOW()) END
           WHERE call_id = $1`,
          [callId],
        );
        await addEvent(client, callId, userId, 'ENDED');
      }

      if (!updated) {
        throw new Error('Call transition returned no row.');
      }
      const participantUserIds = await listParticipants(client, callId);
      await client.query('COMMIT');
      return mapCall(updated, participantUserIds);
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}
