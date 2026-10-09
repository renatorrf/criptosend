import { createHmac, randomUUID } from 'node:crypto';

import type { PoolClient } from 'pg';

import { env } from '../config/env.js';
import { quoteIdentifier } from '../database/identifier.js';
import { databasePool } from '../database/pool.js';
import { AppError } from '../http/app-error.js';
import { normalizePhone } from '../identity/phone.js';
import { decryptField } from '../security/field-crypto.js';
import { createPhoneLookupHash } from '../security/hashes.js';

const schema = quoteIdentifier(env.SCHEMA);

interface ConversationRow {
  id: string;
  created_at: Date;
  peer_user_id: string;
  peer_name_encrypted: Buffer;
  peer_phone_encrypted: Buffer | null;
  last_message_id: string | null;
  last_message_at: Date | null;
  last_message_deleted_at: Date | null;
  unread_count: number;
}

type ConversationSearchMatch = 'NAME' | 'PHONE';

async function beginTransaction(): Promise<PoolClient> {
  const client = await databasePool.connect();
  await client.query('BEGIN');
  return client;
}

export function createDirectConversationKey(
  firstUserId: string,
  secondUserId: string,
): string {
  return createHmac('sha256', env.CONVERSATION_KEY_SECRET)
    .update([firstUserId, secondUserId].sort().join(':'), 'utf8')
    .digest('hex');
}

function mapConversation(
  row: ConversationRow,
  searchMatch?: ConversationSearchMatch,
): Record<string, unknown> {
  return {
    id: row.id,
    type: 'DIRECT',
    createdAt: row.created_at,
    peer: {
      id: row.peer_user_id,
      name: decryptField(row.peer_name_encrypted, 'user-name'),
    },
    lastMessage: row.last_message_id
      ? {
          id: row.last_message_id,
          createdAt: row.last_message_at,
          deleted: row.last_message_deleted_at !== null,
        }
      : null,
    unreadCount: row.unread_count,
    ...(searchMatch ? { searchMatch } : {}),
  };
}

function normalizeNameSearch(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLocaleLowerCase('pt-BR');
}

function conversationSearchMatch(
  row: ConversationRow,
  search: string,
): ConversationSearchMatch | null {
  const normalizedSearch = normalizeNameSearch(search.trim());
  if (!normalizedSearch) return null;

  const peerName = normalizeNameSearch(decryptField(row.peer_name_encrypted, 'user-name'));
  if (peerName.includes(normalizedSearch)) return 'NAME';

  const searchedDigits = search.replace(/\D/g, '');
  if (!searchedDigits || !row.peer_phone_encrypted) return null;
  const peerDigits = decryptField(row.peer_phone_encrypted, 'phone').replace(/\D/g, '');
  return peerDigits.includes(searchedDigits) ? 'PHONE' : null;
}

export class ConversationService {
  async isMember(userId: string, conversationId: string): Promise<boolean> {
    const result = await databasePool.query(
      `SELECT 1 FROM ${schema}.conversation_members
       WHERE conversation_id = $1 AND user_id = $2 AND status = 'ACTIVE'`,
      [conversationId, userId],
    );
    return result.rowCount === 1;
  }

  async assertMember(userId: string, conversationId: string): Promise<void> {
    if (!(await this.isMember(userId, conversationId))) {
      throw new AppError(404, 'CONVERSATION_NOT_FOUND');
    }
  }

  async createDirect(userId: string, phoneInput: string): Promise<{ id: string }> {
    const phoneHash = createPhoneLookupHash(normalizePhone(phoneInput));
    const targetResult = await databasePool.query<{ id: string }>(
      `SELECT target.id
       FROM ${schema}.users target
       JOIN ${schema}.users actor ON actor.id = $2
       WHERE target.phone_lookup_hash = $1
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
         )`,
      [phoneHash, userId],
    );
    const targetUserId = targetResult.rows[0]?.id;
    if (!targetUserId || targetUserId === userId) {
      throw new AppError(404, 'CONTACT_NOT_FOUND');
    }

    const client = await beginTransaction();
    try {
      const conversationId = randomUUID();
      const directKey = createDirectConversationKey(userId, targetUserId);
      const conversation = await client.query<{ id: string }>(
        `INSERT INTO ${schema}.conversations (id, type, direct_key)
         VALUES ($1, 'DIRECT', $2)
         ON CONFLICT (direct_key)
         DO UPDATE SET direct_key = EXCLUDED.direct_key
         RETURNING id`,
        [conversationId, directKey],
      );
      const id = conversation.rows[0]?.id;
      if (!id) {
        throw new Error('Conversation insert returned no identifier.');
      }
      await client.query(
        `INSERT INTO ${schema}.conversation_members (conversation_id, user_id)
         VALUES ($1, $2), ($1, $3)
         ON CONFLICT (conversation_id, user_id) DO NOTHING`,
        [id, userId, targetUserId],
      );
      await client.query('COMMIT');
      return { id };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async list(userId: string, search?: string): Promise<Record<string, unknown>[]> {
    const result = await databasePool.query<ConversationRow>(
      `SELECT c.id, c.created_at,
              peer.user_id AS peer_user_id,
              u.name_encrypted AS peer_name_encrypted,
              u.phone_encrypted AS peer_phone_encrypted,
              last_message.id AS last_message_id,
              last_message.created_at AS last_message_at,
              last_message.deleted_at AS last_message_deleted_at,
              (SELECT COUNT(*)::int
               FROM ${schema}.message_receipts receipt
               JOIN ${schema}.messages unread_message ON unread_message.id = receipt.message_id
               WHERE receipt.user_id = $1 AND receipt.read_at IS NULL
                 AND unread_message.conversation_id = c.id
                 AND unread_message.deleted_at IS NULL) AS unread_count
       FROM ${schema}.conversations c
       JOIN ${schema}.conversation_members mine
         ON mine.conversation_id = c.id AND mine.user_id = $1 AND mine.status = 'ACTIVE'
       JOIN ${schema}.conversation_members peer
         ON peer.conversation_id = c.id AND peer.user_id <> $1 AND peer.status = 'ACTIVE'
       JOIN ${schema}.users u ON u.id = peer.user_id AND u.status = 'ACTIVE'
       LEFT JOIN LATERAL (
         SELECT id, created_at, deleted_at
         FROM ${schema}.messages
         WHERE conversation_id = c.id
         ORDER BY created_at DESC, id DESC
         LIMIT 1
       ) last_message ON TRUE
       WHERE c.type = 'DIRECT'
       ORDER BY COALESCE(last_message.created_at, c.created_at) DESC`,
      [userId],
    );
    const normalizedSearch = search?.trim();
    if (!normalizedSearch) return result.rows.map((row) => mapConversation(row));

    return result.rows.flatMap((row) => {
      const match = conversationSearchMatch(row, normalizedSearch);
      return match ? [mapConversation(row, match)] : [];
    });
  }

  async get(userId: string, conversationId: string): Promise<Record<string, unknown>> {
    const result = await databasePool.query<ConversationRow>(
      `SELECT c.id, c.created_at,
              peer.user_id AS peer_user_id,
              u.name_encrypted AS peer_name_encrypted,
              u.phone_encrypted AS peer_phone_encrypted,
              last_message.id AS last_message_id,
              last_message.created_at AS last_message_at,
              last_message.deleted_at AS last_message_deleted_at,
              (SELECT COUNT(*)::int
               FROM ${schema}.message_receipts receipt
               JOIN ${schema}.messages unread_message ON unread_message.id = receipt.message_id
               WHERE receipt.user_id = $1 AND receipt.read_at IS NULL
                 AND unread_message.conversation_id = c.id
                 AND unread_message.deleted_at IS NULL) AS unread_count
       FROM ${schema}.conversations c
       JOIN ${schema}.conversation_members mine
         ON mine.conversation_id = c.id AND mine.user_id = $1 AND mine.status = 'ACTIVE'
       JOIN ${schema}.conversation_members peer
         ON peer.conversation_id = c.id AND peer.user_id <> $1 AND peer.status = 'ACTIVE'
       JOIN ${schema}.users u ON u.id = peer.user_id AND u.status = 'ACTIVE'
       LEFT JOIN LATERAL (
         SELECT id, created_at, deleted_at FROM ${schema}.messages
         WHERE conversation_id = c.id ORDER BY created_at DESC, id DESC LIMIT 1
       ) last_message ON TRUE
       WHERE c.id = $2 AND c.type = 'DIRECT'`,
      [userId, conversationId],
    );
    const conversation = result.rows[0];
    if (!conversation) {
      throw new AppError(404, 'CONVERSATION_NOT_FOUND');
    }
    return mapConversation(conversation);
  }

  async listMemberUserIds(conversationId: string): Promise<string[]> {
    const result = await databasePool.query<{ user_id: string }>(
      `SELECT user_id FROM ${schema}.conversation_members
       WHERE conversation_id = $1 AND status = 'ACTIVE'`,
      [conversationId],
    );
    return result.rows.map(({ user_id }) => user_id);
  }

  async listTypingRecipients(
    senderUserId: string,
    conversationId: string,
  ): Promise<string[]> {
    const sender = await databasePool.query(
      `SELECT 1
       FROM ${schema}.conversation_members cm
       JOIN ${schema}.users u ON u.id = cm.user_id
       WHERE cm.conversation_id = $1 AND cm.user_id = $2
         AND cm.status = 'ACTIVE' AND u.typing_indicators_enabled = TRUE`,
      [conversationId, senderUserId],
    );
    if (sender.rowCount !== 1) {
      return [];
    }
    const recipients = await databasePool.query<{ user_id: string }>(
      `SELECT cm.user_id
       FROM ${schema}.conversation_members cm
       JOIN ${schema}.users u ON u.id = cm.user_id
       WHERE cm.conversation_id = $1 AND cm.user_id <> $2
         AND cm.status = 'ACTIVE' AND u.typing_indicators_enabled = TRUE`,
      [conversationId, senderUserId],
    );
    return recipients.rows.map(({ user_id }) => user_id);
  }
}
