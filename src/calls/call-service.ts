import { randomUUID } from 'node:crypto';

import type { PoolClient } from 'pg';

import { env } from '../config/env.js';
import type { ConversationService } from '../conversations/conversation-service.js';
import { quoteIdentifier } from '../database/identifier.js';
import { databasePool } from '../database/pool.js';
import { normalizePhone } from '../identity/phone.js';
import { AppError } from '../http/app-error.js';
import { decryptField } from '../security/field-crypto.js';
import { createPhoneLookupHash } from '../security/hashes.js';

const schema = quoteIdentifier(env.SCHEMA);
const MAX_CALL_PARTICIPANTS = 4;

export type CallStatus = 'RINGING' | 'ACTIVE' | 'DECLINED' | 'ENDED' | 'MISSED' | 'FAILED';
export type CallMediaType = 'AUDIO' | 'VIDEO';

interface CallRow {
  id: string;
  conversation_id: string;
  initiated_by_user_id: string;
  media_type: CallMediaType;
  status: CallStatus;
  created_at: Date;
  answered_at: Date | null;
  ended_at: Date | null;
}

interface ParticipantRow {
  user_id: string;
  name_encrypted: Buffer;
  joined_at: Date | null;
  left_at: Date | null;
}

export interface CallParticipantView {
  userId: string;
  name: string;
  joinedAt: Date | null;
  leftAt: Date | null;
}

export interface CallView {
  id: string;
  conversationId: string;
  initiatedByUserId: string;
  mediaType: CallMediaType;
  status: CallStatus;
  createdAt: Date;
  answeredAt: Date | null;
  endedAt: Date | null;
  participantUserIds: string[];
  participants: CallParticipantView[];
}

async function beginTransaction(): Promise<PoolClient> {
  const client = await databasePool.connect();
  await client.query('BEGIN');
  return client;
}

async function listParticipants(client: Pick<PoolClient, 'query'>, callId: string): Promise<CallParticipantView[]> {
  const result = await client.query<ParticipantRow>(
    `SELECT participant.user_id, users.name_encrypted,
            participant.joined_at, participant.left_at
     FROM ${schema}.call_participants participant
     JOIN ${schema}.users users ON users.id = participant.user_id
     WHERE participant.call_id = $1
     ORDER BY participant.invited_at, participant.user_id`,
    [callId],
  );
  return result.rows.map((row) => ({
    userId: row.user_id,
    name: decryptField(row.name_encrypted, 'user-name'),
    joinedAt: row.joined_at,
    leftAt: row.left_at,
  }));
}

async function mapCall(client: Pick<PoolClient, 'query'>, row: CallRow): Promise<CallView> {
  const participants = await listParticipants(client, row.id);
  return {
    id: row.id,
    conversationId: row.conversation_id,
    initiatedByUserId: row.initiated_by_user_id,
    mediaType: row.media_type,
    status: row.status,
    createdAt: row.created_at,
    answeredAt: row.answered_at,
    endedAt: row.ended_at,
    participantUserIds: participants.map(({ userId }) => userId),
    participants,
  };
}

async function addEvent(
  client: Pick<PoolClient, 'query'>,
  callId: string,
  actorUserId: string | null,
  eventType: 'STARTED' | 'ACCEPTED' | 'DECLINED' | 'ENDED' | 'MISSED' | 'FAILED' | 'INVITED',
): Promise<void> {
  await client.query(
    `INSERT INTO ${schema}.call_events (id, call_id, actor_user_id, event_type)
     VALUES ($1, $2, $3, $4)`,
    [randomUUID(), callId, actorUserId, eventType],
  );
}

const callColumns = `c.id, c.conversation_id, c.initiated_by_user_id, c.media_type,
                     c.status, c.created_at, c.answered_at, c.ended_at`;

export class CallService {
  constructor(private readonly conversations: ConversationService) {}

  async start(userId: string, conversationId: string, mediaType: CallMediaType): Promise<CallView> {
    const client = await beginTransaction();
    try {
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`criptsend:call:${conversationId}`]);
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
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`criptsend:call-user:${participantUserId}`]);
      }
      const busyParticipant = await client.query(
        `SELECT 1 FROM ${schema}.call_participants participant
         JOIN ${schema}.call_sessions call ON call.id = participant.call_id
         WHERE participant.user_id = ANY($1::uuid[])
           AND participant.left_at IS NULL AND call.status IN ('RINGING', 'ACTIVE')
         LIMIT 1`,
        [participantUserIds],
      );
      if (busyParticipant.rowCount !== 0) throw new AppError(409, 'CALL_PARTICIPANT_BUSY');

      const inserted = await client.query<CallRow>(
        `INSERT INTO ${schema}.call_sessions (id, conversation_id, initiated_by_user_id, media_type)
         VALUES ($1, $2, $3, $4)
         RETURNING id, conversation_id, initiated_by_user_id, media_type, status,
                   created_at, answered_at, ended_at`,
        [randomUUID(), conversationId, userId, mediaType],
      );
      const call = inserted.rows[0];
      if (!call) throw new Error('Call insert returned no identifier.');
      await client.query(
        `INSERT INTO ${schema}.call_participants (call_id, user_id, joined_at, invited_by_user_id)
         SELECT $1, member_id, CASE WHEN member_id = $2 THEN NOW() ELSE NULL END, $2
         FROM unnest($3::uuid[]) AS member_id`,
        [call.id, userId, participantUserIds],
      );
      await addEvent(client, call.id, userId, 'STARTED');
      const view = await mapCall(client, call);
      await client.query('COMMIT');
      return view;
    } catch (error) {
      await client.query('ROLLBACK');
      if (typeof error === 'object' && error !== null && 'code' in error && error.code === '23505') {
        throw new AppError(409, 'CALL_ALREADY_ACTIVE');
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async invite(userId: string, callId: string, phoneInput: string): Promise<CallView> {
    const client = await beginTransaction();
    try {
      const callResult = await client.query<CallRow>(
        `SELECT ${callColumns}
         FROM ${schema}.call_sessions c
         JOIN ${schema}.call_participants actor ON actor.call_id = c.id AND actor.user_id = $2
         WHERE c.id = $1 AND c.status = 'ACTIVE'
           AND actor.joined_at IS NOT NULL AND actor.left_at IS NULL
         FOR UPDATE OF c`,
        [callId, userId],
      );
      const call = callResult.rows[0];
      if (!call) throw new AppError(404, 'CALL_NOT_FOUND');

      const count = await client.query<{ count: string }>(
        `SELECT COUNT(*)::text AS count FROM ${schema}.call_participants
         WHERE call_id = $1 AND left_at IS NULL`,
        [callId],
      );
      if (Number(count.rows[0]?.count ?? 0) >= MAX_CALL_PARTICIPANTS) {
        throw new AppError(409, 'CALL_PARTICIPANT_LIMIT');
      }

      const targetResult = await client.query<{ id: string }>(
        `SELECT target.id FROM ${schema}.users target
         JOIN ${schema}.users actor ON actor.id = $2
         WHERE target.phone_lookup_hash = $1 AND target.id <> $2
           AND target.discoverable = TRUE AND target.status = 'ACTIVE'
           AND (
             actor.role <> 'MANAGER' OR target.manager_user_id = actor.id
             OR (target.role = 'MANAGER' AND EXISTS (
               SELECT 1 FROM ${schema}.manager_network_links link
               WHERE link.manager_low_id = LEAST(actor.id, target.id)
                 AND link.manager_high_id = GREATEST(actor.id, target.id)
             ))
           )`,
        [createPhoneLookupHash(normalizePhone(phoneInput)), userId],
      );
      const targetUserId = targetResult.rows[0]?.id;
      if (!targetUserId) throw new AppError(404, 'CONTACT_NOT_FOUND');

      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`criptsend:call-user:${targetUserId}`]);
      const busy = await client.query(
        `SELECT 1 FROM ${schema}.call_participants participant
         JOIN ${schema}.call_sessions live_call ON live_call.id = participant.call_id
         WHERE participant.user_id = $1 AND participant.left_at IS NULL
           AND live_call.status IN ('RINGING', 'ACTIVE') LIMIT 1`,
        [targetUserId],
      );
      if (busy.rowCount !== 0) throw new AppError(409, 'CALL_PARTICIPANT_BUSY');

      await client.query(
        `INSERT INTO ${schema}.call_participants (call_id, user_id, invited_by_user_id)
         VALUES ($1, $2, $3)`,
        [callId, targetUserId, userId],
      );
      await addEvent(client, callId, userId, 'INVITED');
      const view = await mapCall(client, call);
      await client.query('COMMIT');
      return view;
    } catch (error) {
      await client.query('ROLLBACK');
      if (typeof error === 'object' && error !== null && 'code' in error && error.code === '23505') {
        throw new AppError(409, 'CALL_PARTICIPANT_EXISTS');
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async accept(userId: string, callId: string): Promise<CallView> { return this.transition(callId, userId, 'ACCEPT'); }
  async decline(userId: string, callId: string): Promise<CallView> { return this.transition(callId, userId, 'DECLINE'); }
  async end(userId: string, callId: string): Promise<CallView> { return this.transition(callId, userId, 'END'); }

  async get(userId: string, callId: string): Promise<CallView> {
    const result = await databasePool.query<CallRow>(
      `SELECT ${callColumns} FROM ${schema}.call_sessions c
       JOIN ${schema}.call_participants participant ON participant.call_id = c.id AND participant.user_id = $2
       WHERE c.id = $1`,
      [callId, userId],
    );
    const call = result.rows[0];
    if (!call) throw new AppError(404, 'CALL_NOT_FOUND');
    return mapCall(databasePool, call);
  }

  async pending(userId: string): Promise<CallView | null> {
    const result = await databasePool.query<CallRow>(
      `SELECT ${callColumns} FROM ${schema}.call_sessions c
       JOIN ${schema}.call_participants participant ON participant.call_id = c.id AND participant.user_id = $1
       WHERE c.status IN ('RINGING', 'ACTIVE') AND participant.left_at IS NULL
       ORDER BY c.created_at DESC LIMIT 1`,
      [userId],
    );
    return result.rows[0] ? mapCall(databasePool, result.rows[0]) : null;
  }

  async getRelayRecipient(userId: string, callId: string, targetUserId: string): Promise<string | null> {
    const result = await databasePool.query<{ user_id: string }>(
      `SELECT target.user_id FROM ${schema}.call_sessions call
       JOIN ${schema}.call_participants sender ON sender.call_id = call.id AND sender.user_id = $2
       JOIN ${schema}.call_participants target ON target.call_id = call.id AND target.user_id = $3
       WHERE call.id = $1 AND call.status = 'ACTIVE'
         AND sender.joined_at IS NOT NULL AND sender.left_at IS NULL
         AND target.joined_at IS NOT NULL AND target.left_at IS NULL`,
      [callId, userId, targetUserId],
    );
    return result.rows[0]?.user_id ?? null;
  }

  async list(userId: string, conversationId: string, limit: number): Promise<CallView[]> {
    await this.conversations.assertMember(userId, conversationId);
    const result = await databasePool.query<CallRow>(
      `SELECT ${callColumns} FROM ${schema}.call_sessions c
       WHERE c.conversation_id = $1 ORDER BY c.created_at DESC, c.id DESC LIMIT $2`,
      [conversationId, limit],
    );
    return Promise.all(result.rows.map((row) => mapCall(databasePool, row)));
  }

  async expireRinging(): Promise<CallView[]> {
    const client = await beginTransaction();
    try {
      const expired = await client.query<CallRow>(
        `UPDATE ${schema}.call_sessions SET status = 'MISSED', ended_at = NOW()
         WHERE id IN (
           SELECT id FROM ${schema}.call_sessions WHERE status = 'RINGING'
             AND created_at <= NOW() - ($1::text || ' seconds')::interval
           ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 100
         )
         RETURNING id, conversation_id, initiated_by_user_id, media_type, status,
                   created_at, answered_at, ended_at`,
        [env.RTC_RING_TIMEOUT_SECONDS],
      );
      const calls: CallView[] = [];
      for (const row of expired.rows) {
        await addEvent(client, row.id, null, 'MISSED');
        calls.push(await mapCall(client, row));
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

  private async transition(callId: string, userId: string, action: 'ACCEPT' | 'DECLINE' | 'END'): Promise<CallView> {
    const client = await beginTransaction();
    try {
      const result = await client.query<CallRow & { joined_at: Date | null }>(
        `SELECT ${callColumns}, participant.joined_at FROM ${schema}.call_sessions c
         JOIN ${schema}.call_participants participant ON participant.call_id = c.id AND participant.user_id = $2
         WHERE c.id = $1 AND participant.left_at IS NULL FOR UPDATE OF c, participant`,
        [callId, userId],
      );
      const call = result.rows[0];
      if (!call) throw new AppError(404, 'CALL_NOT_FOUND');

      let updated: CallRow = call;
      if (action === 'ACCEPT') {
        if (!['RINGING', 'ACTIVE'].includes(call.status) || call.joined_at) throw new AppError(409, 'CALL_STATE_CONFLICT');
        await client.query(`UPDATE ${schema}.call_participants SET joined_at = NOW() WHERE call_id = $1 AND user_id = $2`, [callId, userId]);
        if (call.status === 'RINGING') {
          const changed = await client.query<CallRow>(
            `UPDATE ${schema}.call_sessions SET status = 'ACTIVE', answered_at = NOW() WHERE id = $1
             RETURNING id, conversation_id, initiated_by_user_id, media_type, status, created_at, answered_at, ended_at`,
            [callId],
          );
          updated = changed.rows[0] ?? call;
        }
        await addEvent(client, callId, userId, 'ACCEPTED');
      } else if (action === 'DECLINE') {
        if (!['RINGING', 'ACTIVE'].includes(call.status) || call.initiated_by_user_id === userId) throw new AppError(409, 'CALL_STATE_CONFLICT');
        await client.query(`UPDATE ${schema}.call_participants SET left_at = NOW() WHERE call_id = $1 AND user_id = $2`, [callId, userId]);
        if (call.status === 'RINGING') {
          const changed = await client.query<CallRow>(
            `UPDATE ${schema}.call_sessions SET status = 'DECLINED', ended_at = NOW() WHERE id = $1
             RETURNING id, conversation_id, initiated_by_user_id, media_type, status, created_at, answered_at, ended_at`,
            [callId],
          );
          updated = changed.rows[0] ?? call;
        }
        await addEvent(client, callId, userId, 'DECLINED');
      } else {
        if (!['RINGING', 'ACTIVE'].includes(call.status)) throw new AppError(409, 'CALL_STATE_CONFLICT');
        const changed = await client.query<CallRow>(
          `UPDATE ${schema}.call_sessions SET status = 'ENDED', ended_at = NOW() WHERE id = $1
           RETURNING id, conversation_id, initiated_by_user_id, media_type, status, created_at, answered_at, ended_at`,
          [callId],
        );
        updated = changed.rows[0] ?? call;
        await client.query(
          `UPDATE ${schema}.call_participants
           SET left_at = CASE WHEN joined_at IS NULL THEN left_at ELSE COALESCE(left_at, NOW()) END WHERE call_id = $1`,
          [callId],
        );
        await addEvent(client, callId, userId, 'ENDED');
      }

      const view = await mapCall(client, updated);
      await client.query('COMMIT');
      return view;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}
