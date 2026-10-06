import { randomUUID } from 'node:crypto';

import type { PoolClient } from 'pg';
import { z } from 'zod';

import { env } from '../config/env.js';
import { quoteIdentifier } from '../database/identifier.js';
import { databasePool } from '../database/pool.js';
import { AppError } from '../http/app-error.js';
import type { ConversationService } from '../conversations/conversation-service.js';

const schema = quoteIdentifier(env.SCHEMA);
const cursorSchema = z.object({ createdAt: z.iso.datetime(), id: z.uuid() }).strict();

interface MessageRow {
  id: string;
  conversation_id: string;
  sender_user_id: string;
  sender_device_id: string;
  client_message_id: string;
  ciphertext: Buffer;
  crypto_header: Buffer | null;
  reply_to_message_id: string | null;
  created_at: Date;
  expires_at: Date | null;
  deleted_at: Date | null;
  deletion_reason: 'USER' | 'EXPIRED' | null;
}

export interface CreateMessageInput {
  clientMessageId: string;
  ciphertext: Buffer;
  cryptoHeader: Buffer | null;
  replyToMessageId: string | null;
  expiresAt: Date | null;
}

async function beginTransaction(): Promise<PoolClient> {
  const client = await databasePool.connect();
  await client.query('BEGIN');
  return client;
}

function mapMessage(row: MessageRow): Record<string, unknown> {
  return {
    id: row.id,
    conversationId: row.conversation_id,
    senderUserId: row.sender_user_id,
    senderDeviceId: row.sender_device_id,
    clientMessageId: row.client_message_id,
    ciphertext: row.deleted_at ? null : row.ciphertext.toString('base64'),
    cryptoHeader: row.deleted_at ? null : row.crypto_header?.toString('base64') ?? null,
    replyToMessageId: row.reply_to_message_id,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    deletedAt: row.deleted_at,
    deletionReason: row.deletion_reason,
  };
}

function decodeCursor(cursor: string | undefined): { createdAt: Date; id: string } | null {
  if (!cursor) {
    return null;
  }
  try {
    const parsed = cursorSchema.parse(
      JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')),
    );
    return { createdAt: new Date(parsed.createdAt), id: parsed.id };
  } catch {
    throw new AppError(400, 'INVALID_CURSOR');
  }
}

function encodeCursor(row: MessageRow): string {
  return Buffer.from(
    JSON.stringify({ createdAt: row.created_at.toISOString(), id: row.id }),
    'utf8',
  ).toString('base64url');
}

export class MessageService {
  constructor(private readonly conversations: ConversationService) {}

  async list(
    userId: string,
    conversationId: string,
    limit: number,
    cursorValue?: string,
  ): Promise<{ messages: Record<string, unknown>[]; nextCursor: string | null }> {
    await this.conversations.assertMember(userId, conversationId);
    const cursor = decodeCursor(cursorValue);
    const result = await databasePool.query<MessageRow>(
      `SELECT id, conversation_id, sender_user_id, sender_device_id,
              client_message_id, ciphertext, crypto_header, reply_to_message_id,
              created_at, expires_at, deleted_at, deletion_reason
       FROM ${schema}.messages
       WHERE conversation_id = $1
         AND (expires_at IS NULL OR expires_at > NOW() OR deleted_at IS NOT NULL)
         AND ($2::timestamptz IS NULL OR (created_at, id) < ($2::timestamptz, $3::uuid))
       ORDER BY created_at DESC, id DESC
       LIMIT $4`,
      [conversationId, cursor?.createdAt ?? null, cursor?.id ?? null, limit + 1],
    );
    const hasMore = result.rows.length > limit;
    const page = result.rows.slice(0, limit);
    const last = page.at(-1);
    return {
      messages: page.map(mapMessage),
      nextCursor: hasMore && last ? encodeCursor(last) : null,
    };
  }

  async create(
    userId: string,
    deviceId: string,
    conversationId: string,
    input: CreateMessageInput,
  ): Promise<{ message: Record<string, unknown>; created: boolean }> {
    const client = await beginTransaction();
    try {
      const membership = await client.query(
        `SELECT 1 FROM ${schema}.conversation_members
         WHERE conversation_id = $1 AND user_id = $2 AND status = 'ACTIVE'
         FOR UPDATE`,
        [conversationId, userId],
      );
      if (membership.rowCount !== 1) {
        throw new AppError(404, 'CONVERSATION_NOT_FOUND');
      }
      if (input.replyToMessageId) {
        const reply = await client.query(
          `SELECT 1 FROM ${schema}.messages
           WHERE id = $1 AND conversation_id = $2`,
          [input.replyToMessageId, conversationId],
        );
        if (reply.rowCount !== 1) {
          throw new AppError(400, 'INVALID_REPLY_TARGET');
        }
      }

      const id = randomUUID();
      const inserted = await client.query<MessageRow>(
        `INSERT INTO ${schema}.messages
           (id, conversation_id, sender_user_id, sender_device_id,
            client_message_id, ciphertext, crypto_header, reply_to_message_id, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (sender_device_id, client_message_id) DO NOTHING
         RETURNING id, conversation_id, sender_user_id, sender_device_id,
                   client_message_id, ciphertext, crypto_header, reply_to_message_id,
                   created_at, expires_at, deleted_at, deletion_reason`,
        [
          id,
          conversationId,
          userId,
          deviceId,
          input.clientMessageId,
          input.ciphertext,
          input.cryptoHeader,
          input.replyToMessageId,
          input.expiresAt,
        ],
      );
      let row = inserted.rows[0];
      let created = true;
      if (!row) {
        created = false;
        const existing = await client.query<MessageRow>(
          `SELECT id, conversation_id, sender_user_id, sender_device_id,
                  client_message_id, ciphertext, crypto_header, reply_to_message_id,
                  created_at, expires_at, deleted_at, deletion_reason
           FROM ${schema}.messages
           WHERE sender_device_id = $1 AND client_message_id = $2`,
          [deviceId, input.clientMessageId],
        );
        row = existing.rows[0];
      }
      if (!row || row.conversation_id !== conversationId) {
        throw new AppError(409, 'CLIENT_MESSAGE_ID_CONFLICT');
      }
      if (created) {
        await client.query(
          `INSERT INTO ${schema}.message_receipts (message_id, user_id)
           SELECT $1, user_id
           FROM ${schema}.conversation_members
           WHERE conversation_id = $2 AND user_id <> $3 AND status = 'ACTIVE'
           ON CONFLICT (message_id, user_id) DO NOTHING`,
          [row.id, conversationId, userId],
        );
      }
      await client.query('COMMIT');
      return { message: mapMessage(row), created };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async deleteForAll(
    userId: string,
    messageId: string,
  ): Promise<{ conversationId: string }> {
    const client = await beginTransaction();
    try {
      const result = await client.query<{ conversation_id: string }>(
        `UPDATE ${schema}.messages
         SET ciphertext = decode('00', 'hex'), crypto_header = NULL,
             deleted_at = NOW(), deletion_reason = 'USER'
         WHERE id = $1 AND sender_user_id = $2 AND deleted_at IS NULL
         RETURNING conversation_id`,
        [messageId, userId],
      );
      const conversationId = result.rows[0]?.conversation_id;
      if (!conversationId) {
        throw new AppError(404, 'MESSAGE_NOT_FOUND');
      }
      await client.query(
        `INSERT INTO ${schema}.message_events
           (id, message_id, actor_user_id, event_type)
         VALUES ($1, $2, $3, 'DELETED_FOR_ALL')`,
        [randomUUID(), messageId, userId],
      );
      await client.query('COMMIT');
      return { conversationId };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async markDelivered(
    userId: string,
    deviceId: string,
    messageId: string,
  ): Promise<{ senderUserId: string; conversationId: string; deliveredAt: Date }> {
    const result = await databasePool.query<{
      sender_user_id: string;
      conversation_id: string;
      delivered_at: Date;
    }>(
      `UPDATE ${schema}.message_receipts r
       SET delivered_at = COALESCE(r.delivered_at, NOW()), device_id = COALESCE(r.device_id, $2)
       FROM ${schema}.messages m
       WHERE r.message_id = $1 AND r.user_id = $3
         AND m.id = r.message_id AND m.sender_user_id <> $3
       RETURNING m.sender_user_id, m.conversation_id, r.delivered_at`,
      [messageId, deviceId, userId],
    );
    const receipt = result.rows[0];
    if (!receipt) {
      throw new AppError(404, 'MESSAGE_NOT_FOUND');
    }
    return {
      senderUserId: receipt.sender_user_id,
      conversationId: receipt.conversation_id,
      deliveredAt: receipt.delivered_at,
    };
  }

  async markRead(
    userId: string,
    deviceId: string,
    messageId: string,
  ): Promise<{
    shared: boolean;
    senderUserId?: string;
    conversationId?: string;
    readAt?: Date;
  }> {
    const preference = await databasePool.query<{ read_receipts_enabled: boolean }>(
      `SELECT read_receipts_enabled FROM ${schema}.users
       WHERE id = $1 AND status = 'ACTIVE'`,
      [userId],
    );
    if (!preference.rows[0]?.read_receipts_enabled) {
      return { shared: false };
    }
    const result = await databasePool.query<{
      sender_user_id: string;
      conversation_id: string;
      read_at: Date;
    }>(
      `UPDATE ${schema}.message_receipts r
       SET delivered_at = COALESCE(r.delivered_at, NOW()),
           read_at = COALESCE(r.read_at, NOW()),
           device_id = COALESCE(r.device_id, $2)
       FROM ${schema}.messages m
       WHERE r.message_id = $1 AND r.user_id = $3
         AND m.id = r.message_id AND m.sender_user_id <> $3
       RETURNING m.sender_user_id, m.conversation_id, r.read_at`,
      [messageId, deviceId, userId],
    );
    const receipt = result.rows[0];
    if (!receipt) {
      throw new AppError(404, 'MESSAGE_NOT_FOUND');
    }
    return {
      shared: true,
      senderUserId: receipt.sender_user_id,
      conversationId: receipt.conversation_id,
      readAt: receipt.read_at,
    };
  }

  async getReceipts(
    userId: string,
    messageId: string,
  ): Promise<Record<string, unknown>[]> {
    const message = await databasePool.query(
      `SELECT 1 FROM ${schema}.messages
       WHERE id = $1 AND sender_user_id = $2`,
      [messageId, userId],
    );
    if (message.rowCount !== 1) {
      throw new AppError(404, 'MESSAGE_NOT_FOUND');
    }
    const result = await databasePool.query<{
      user_id: string;
      delivered_at: Date | null;
      read_at: Date | null;
    }>(
      `SELECT user_id, delivered_at, read_at
       FROM ${schema}.message_receipts
       WHERE message_id = $1`,
      [messageId],
    );
    return result.rows.map((receipt) => ({
      userId: receipt.user_id,
      deliveredAt: receipt.delivered_at,
      readAt: receipt.read_at,
    }));
  }

  async expireDue(limit = 500): Promise<
    { id: string; conversationId: string }[]
  > {
    const client = await beginTransaction();
    try {
      const due = await client.query<{ id: string; conversation_id: string }>(
        `SELECT id, conversation_id
         FROM ${schema}.messages
         WHERE expires_at IS NOT NULL AND expires_at <= NOW() AND deleted_at IS NULL
         ORDER BY expires_at
         FOR UPDATE SKIP LOCKED
         LIMIT $1`,
        [limit],
      );
      for (const message of due.rows) {
        await client.query(
          `UPDATE ${schema}.messages
           SET ciphertext = decode('00', 'hex'), crypto_header = NULL,
               deleted_at = NOW(), deletion_reason = 'EXPIRED'
           WHERE id = $1`,
          [message.id],
        );
        await client.query(
          `INSERT INTO ${schema}.message_events
             (id, message_id, actor_user_id, event_type)
           SELECT $1, $2, sender_user_id, 'EXPIRED'
           FROM ${schema}.messages WHERE id = $2`,
          [randomUUID(), message.id],
        );
      }
      await client.query('COMMIT');
      return due.rows.map(({ id, conversation_id }) => ({
        id,
        conversationId: conversation_id,
      }));
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}
