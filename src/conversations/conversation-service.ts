import { createHmac, randomUUID } from 'node:crypto';

import type { PoolClient } from 'pg';

import { env } from '../config/env.js';
import { quoteIdentifier } from '../database/identifier.js';
import { databasePool } from '../database/pool.js';
import { AppError } from '../http/app-error.js';
import { decryptField, encryptField } from '../security/field-crypto.js';

const schema = quoteIdentifier(env.SCHEMA);
const MAXIMUM_GROUP_MEMBERS = 50;

interface ConversationBaseRow {
  id: string;
  created_at: Date;
  last_message_id: string | null;
  last_message_at: Date | null;
  last_message_deleted_at: Date | null;
  unread_count: number;
}

interface DirectConversationRow extends ConversationBaseRow {
  peer_user_id: string;
  peer_name_encrypted: Buffer;
  peer_nickname: string;
}

interface GroupConversationRow extends ConversationBaseRow {
  group_name_encrypted: Buffer;
  created_by_user_id: string;
  member_user_ids: string[];
  member_names_encrypted: Buffer[];
  member_nicknames: string[];
}

type ConversationSearchMatch = 'NAME' | 'NICKNAME';

async function beginTransaction(): Promise<PoolClient> {
  const client = await databasePool.connect();
  await client.query('BEGIN');
  return client;
}

function normalizeNickname(value: string): string {
  const nickname = value.trim().normalize('NFKC').toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{2,39}$/.test(nickname)) {
    throw new AppError(400, 'INVALID_NICKNAME');
  }
  return nickname;
}

function normalizeSearch(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLocaleLowerCase('pt-BR');
}

export function createDirectConversationKey(firstUserId: string, secondUserId: string): string {
  return createHmac('sha256', env.CONVERSATION_KEY_SECRET)
    .update([firstUserId, secondUserId].sort().join(':'), 'utf8')
    .digest('hex');
}

function lastMessage(row: ConversationBaseRow): Record<string, unknown> | null {
  return row.last_message_id
    ? {
        id: row.last_message_id,
        createdAt: row.last_message_at,
        deleted: row.last_message_deleted_at !== null,
      }
    : null;
}

function mapDirect(
  row: DirectConversationRow,
  searchMatch?: ConversationSearchMatch,
): Record<string, unknown> {
  return {
    id: row.id,
    type: 'DIRECT',
    createdAt: row.created_at,
    peer: {
      id: row.peer_user_id,
      name: decryptField(row.peer_name_encrypted, 'user-name'),
      nickname: row.peer_nickname,
    },
    lastMessage: lastMessage(row),
    unreadCount: row.unread_count,
    ...(searchMatch ? { searchMatch } : {}),
  };
}

function groupMembers(row: GroupConversationRow): Array<Record<string, string>> {
  return row.member_user_ids.map((id, index) => ({
    id,
    name: decryptField(row.member_names_encrypted[index] as Buffer, 'user-name'),
    nickname: row.member_nicknames[index] as string,
  }));
}

function mapGroup(
  row: GroupConversationRow,
  searchMatch?: ConversationSearchMatch,
): Record<string, unknown> {
  return {
    id: row.id,
    type: 'GROUP',
    createdAt: row.created_at,
    name: decryptField(row.group_name_encrypted, 'group-name'),
    createdByUserId: row.created_by_user_id,
    members: groupMembers(row),
    lastMessage: lastMessage(row),
    unreadCount: row.unread_count,
    ...(searchMatch ? { searchMatch } : {}),
  };
}

function directSearchMatch(
  row: DirectConversationRow,
  search: string,
): ConversationSearchMatch | null {
  const normalized = normalizeSearch(search.trim().replace(/^@/, ''));
  if (!normalized) return null;
  const name = normalizeSearch(decryptField(row.peer_name_encrypted, 'user-name'));
  if (name.includes(normalized)) return 'NAME';
  return row.peer_nickname.includes(normalized) ? 'NICKNAME' : null;
}

function groupSearchMatch(
  row: GroupConversationRow,
  search: string,
): ConversationSearchMatch | null {
  const normalized = normalizeSearch(search.trim().replace(/^@/, ''));
  if (!normalized) return null;
  const name = normalizeSearch(decryptField(row.group_name_encrypted, 'group-name'));
  if (name.includes(normalized)) return 'NAME';
  return row.member_nicknames.some((nickname) => nickname.includes(normalized))
    ? 'NICKNAME'
    : null;
}

const lastMessageSql = `
  LEFT JOIN LATERAL (
    SELECT id, created_at, deleted_at
    FROM ${schema}.messages
    WHERE conversation_id = c.id
      AND created_at > COALESCE(actor.security_wiped_at, '-infinity'::timestamptz)
    ORDER BY created_at DESC, id DESC
    LIMIT 1
  ) last_message ON TRUE`;

const unreadSql = `
  (SELECT COUNT(*)::int
   FROM ${schema}.message_receipts receipt
   JOIN ${schema}.messages unread_message ON unread_message.id = receipt.message_id
   WHERE receipt.user_id = $1 AND receipt.read_at IS NULL
     AND unread_message.conversation_id = c.id
     AND unread_message.deleted_at IS NULL) AS unread_count`;

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

  async createDirect(userId: string, nicknameInput: string): Promise<{ id: string }> {
    const nickname = normalizeNickname(nicknameInput);
    const targetResult = await databasePool.query<{ id: string }>(
      `SELECT target.id
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
    const targetUserId = targetResult.rows[0]?.id;
    if (!targetUserId) throw new AppError(404, 'CONTACT_NOT_FOUND');

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
      if (!id) throw new Error('Conversation insert returned no identifier.');
      await client.query(
        `INSERT INTO ${schema}.conversation_members (conversation_id, user_id)
         VALUES ($1, $2), ($1, $3)
         ON CONFLICT (conversation_id, user_id)
         DO UPDATE SET status = 'ACTIVE', joined_at = NOW()`,
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

  async createGroup(
    userId: string,
    nameInput: string,
    nicknameInputs: string[],
  ): Promise<{ id: string }> {
    const name = nameInput.trim();
    const nicknames = [...new Set(nicknameInputs.map(normalizeNickname))];
    if (!name || nicknames.length === 0 || nicknames.length >= MAXIMUM_GROUP_MEMBERS) {
      throw new AppError(400, 'INVALID_GROUP');
    }
    const actor = await databasePool.query<{ role: string }>(
      `SELECT role FROM ${schema}.users WHERE id = $1 AND status = 'ACTIVE'`,
      [userId],
    );
    if (actor.rows[0]?.role !== 'MANAGER') throw new AppError(403, 'FORBIDDEN');

    const members = await databasePool.query<{ id: string }>(
      `SELECT id
       FROM ${schema}.users
       WHERE manager_user_id = $1
         AND nickname = ANY($2::text[])
         AND status = 'ACTIVE'`,
      [userId, nicknames],
    );
    if (members.rowCount !== nicknames.length) {
      throw new AppError(400, 'GROUP_MEMBER_OUTSIDE_NETWORK');
    }

    const id = randomUUID();
    const client = await beginTransaction();
    try {
      await client.query(
        `INSERT INTO ${schema}.conversations
           (id, type, direct_key, name_encrypted, created_by_user_id)
         VALUES ($1, 'GROUP', NULL, $2, $3)`,
        [id, encryptField(name, 'group-name'), userId],
      );
      await client.query(
        `INSERT INTO ${schema}.conversation_members (conversation_id, user_id)
         SELECT $1, member_id
         FROM UNNEST($2::uuid[]) AS member_id`,
        [id, [userId, ...members.rows.map(({ id: memberId }) => memberId)]],
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
    const [directResult, groupResult] = await Promise.all([
      databasePool.query<DirectConversationRow>(
        `SELECT c.id, c.created_at, peer.user_id AS peer_user_id,
                u.name_encrypted AS peer_name_encrypted, u.nickname AS peer_nickname,
                last_message.id AS last_message_id,
                last_message.created_at AS last_message_at,
                last_message.deleted_at AS last_message_deleted_at,
                ${unreadSql}
         FROM ${schema}.conversations c
         JOIN ${schema}.conversation_members mine
           ON mine.conversation_id = c.id AND mine.user_id = $1 AND mine.status = 'ACTIVE'
         JOIN ${schema}.conversation_members peer
           ON peer.conversation_id = c.id AND peer.user_id <> $1 AND peer.status = 'ACTIVE'
         JOIN ${schema}.users u ON u.id = peer.user_id AND u.status = 'ACTIVE'
         JOIN ${schema}.users actor ON actor.id = $1
         ${lastMessageSql}
         WHERE c.type = 'DIRECT'`,
        [userId],
      ),
      databasePool.query<GroupConversationRow>(
        `SELECT c.id, c.created_at, c.name_encrypted AS group_name_encrypted,
                c.created_by_user_id,
                ARRAY_AGG(u.id ORDER BY cm.joined_at) AS member_user_ids,
                ARRAY_AGG(u.name_encrypted ORDER BY cm.joined_at) AS member_names_encrypted,
                ARRAY_AGG(u.nickname ORDER BY cm.joined_at) AS member_nicknames,
                last_message.id AS last_message_id,
                last_message.created_at AS last_message_at,
                last_message.deleted_at AS last_message_deleted_at,
                ${unreadSql}
         FROM ${schema}.conversations c
         JOIN ${schema}.conversation_members mine
           ON mine.conversation_id = c.id AND mine.user_id = $1 AND mine.status = 'ACTIVE'
         JOIN ${schema}.conversation_members cm
           ON cm.conversation_id = c.id AND cm.status = 'ACTIVE'
         JOIN ${schema}.users u ON u.id = cm.user_id AND u.status = 'ACTIVE'
         JOIN ${schema}.users actor ON actor.id = $1
         ${lastMessageSql}
         WHERE c.type = 'GROUP'
         GROUP BY c.id, last_message.id, last_message.created_at,
                  last_message.deleted_at, actor.security_wiped_at`,
        [userId],
      ),
    ]);
    const normalizedSearch = search?.trim();
    const conversations = [
      ...directResult.rows.flatMap((row) => {
        if (!normalizedSearch) return [mapDirect(row)];
        const match = directSearchMatch(row, normalizedSearch);
        return match ? [mapDirect(row, match)] : [];
      }),
      ...groupResult.rows.flatMap((row) => {
        if (!normalizedSearch) return [mapGroup(row)];
        const match = groupSearchMatch(row, normalizedSearch);
        return match ? [mapGroup(row, match)] : [];
      }),
    ];
    return conversations.sort((left, right) => {
      const leftAt = (left.lastMessage as { createdAt?: Date } | null)?.createdAt ?? left.createdAt;
      const rightAt = (right.lastMessage as { createdAt?: Date } | null)?.createdAt ?? right.createdAt;
      return new Date(String(rightAt)).getTime() - new Date(String(leftAt)).getTime();
    });
  }

  async get(userId: string, conversationId: string): Promise<Record<string, unknown>> {
    const conversations = await this.list(userId);
    const conversation = conversations.find(({ id }) => id === conversationId);
    if (!conversation) throw new AppError(404, 'CONVERSATION_NOT_FOUND');
    return conversation;
  }

  async listMemberUserIds(conversationId: string): Promise<string[]> {
    const result = await databasePool.query<{ user_id: string }>(
      `SELECT user_id FROM ${schema}.conversation_members
       WHERE conversation_id = $1 AND status = 'ACTIVE'`,
      [conversationId],
    );
    return result.rows.map(({ user_id }) => user_id);
  }

  async listTypingRecipients(senderUserId: string, conversationId: string): Promise<string[]> {
    const sender = await databasePool.query(
      `SELECT 1
       FROM ${schema}.conversation_members cm
       JOIN ${schema}.users u ON u.id = cm.user_id
       WHERE cm.conversation_id = $1 AND cm.user_id = $2
         AND cm.status = 'ACTIVE' AND u.typing_indicators_enabled = TRUE`,
      [conversationId, senderUserId],
    );
    if (sender.rowCount !== 1) return [];
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
