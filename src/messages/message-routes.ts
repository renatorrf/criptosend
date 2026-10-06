import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import type { AuthService } from '../auth/auth-service.js';
import type { ConversationService } from '../conversations/conversation-service.js';
import { AppError } from '../http/app-error.js';
import type { RealtimeHub } from '../realtime/realtime-hub.js';
import type { MessageService } from './message-service.js';

const idParamsSchema = z.object({ id: z.uuid() }).strict();
const messagesQuerySchema = z
  .object({
    cursor: z.string().min(1).max(512).optional(),
    limit: z.coerce.number().int().min(1).max(100).default(30),
  })
  .strict();
const base64Schema = z
  .string()
  .min(4)
  .max(350_000)
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
const createMessageSchema = z
  .object({
    clientMessageId: z.uuid(),
    ciphertext: base64Schema,
    cryptoHeader: base64Schema.nullable().optional(),
    replyToMessageId: z.uuid().nullable().optional(),
    expiresInSeconds: z.number().int().min(60).max(2_592_000).nullable().optional(),
  })
  .strict();

function decodeCiphertext(value: string): Buffer {
  const buffer = Buffer.from(value, 'base64');
  if (buffer.length === 0 || buffer.length > 262_144) {
    throw new AppError(400, 'INVALID_REQUEST');
  }
  return buffer;
}

export function registerMessageRoutes(
  app: FastifyInstance,
  authService: AuthService,
  conversations: ConversationService,
  realtime: RealtimeHub,
  service: MessageService,
): void {
  app.get('/conversations/:id/messages', async (request) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const params = idParamsSchema.safeParse(request.params);
    const query = messagesQuerySchema.safeParse(request.query);
    if (!params.success || !query.success) {
      throw new AppError(400, 'INVALID_REQUEST');
    }
    return service.list(
      auth.userId,
      params.data.id,
      query.data.limit,
      query.data.cursor,
    );
  });

  app.post('/conversations/:id/messages', async (request, reply) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const params = idParamsSchema.safeParse(request.params);
    const body = createMessageSchema.safeParse(request.body);
    if (!params.success || !body.success) {
      throw new AppError(400, 'INVALID_REQUEST');
    }
    const result = await service.create(auth.userId, auth.deviceId, params.data.id, {
      clientMessageId: body.data.clientMessageId,
      ciphertext: decodeCiphertext(body.data.ciphertext),
      cryptoHeader: body.data.cryptoHeader
        ? decodeCiphertext(body.data.cryptoHeader)
        : null,
      replyToMessageId: body.data.replyToMessageId ?? null,
      expiresAt: body.data.expiresInSeconds
        ? new Date(Date.now() + body.data.expiresInSeconds * 1_000)
        : null,
    });
    if (result.created) {
      const memberIds = await conversations.listMemberUserIds(params.data.id);
      realtime.emitToUsers(memberIds, 'message:received', result.message);
    }
    return reply.code(result.created ? 201 : 200).send(result.message);
  });

  app.post('/messages/:id/delivered', async (request) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const params = idParamsSchema.safeParse(request.params);
    if (!params.success) {
      throw new AppError(400, 'INVALID_REQUEST');
    }
    const receipt = await service.markDelivered(
      auth.userId,
      auth.deviceId,
      params.data.id,
    );
    realtime.emitToUsers([receipt.senderUserId], 'message:delivered', {
      id: params.data.id,
      conversationId: receipt.conversationId,
      deliveredAt: receipt.deliveredAt,
    });
    return { deliveredAt: receipt.deliveredAt };
  });

  app.post('/messages/:id/read', async (request) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const params = idParamsSchema.safeParse(request.params);
    if (!params.success) {
      throw new AppError(400, 'INVALID_REQUEST');
    }
    const receipt = await service.markRead(auth.userId, auth.deviceId, params.data.id);
    if (
      receipt.shared &&
      receipt.senderUserId &&
      receipt.conversationId &&
      receipt.readAt
    ) {
      realtime.emitToUsers([receipt.senderUserId], 'message:read', {
        id: params.data.id,
        conversationId: receipt.conversationId,
        readAt: receipt.readAt,
      });
    }
    return { shared: receipt.shared, readAt: receipt.readAt ?? null };
  });

  app.get('/messages/:id/receipts', async (request) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const params = idParamsSchema.safeParse(request.params);
    if (!params.success) {
      throw new AppError(400, 'INVALID_REQUEST');
    }
    return { receipts: await service.getReceipts(auth.userId, params.data.id) };
  });

  app.delete('/messages/:id', async (request, reply) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const params = idParamsSchema.safeParse(request.params);
    if (!params.success) {
      throw new AppError(400, 'INVALID_REQUEST');
    }
    const result = await service.deleteForAll(auth.userId, params.data.id);
    const memberIds = await conversations.listMemberUserIds(result.conversationId);
    realtime.emitToUsers(memberIds, 'message:deleted', {
      id: params.data.id,
      conversationId: result.conversationId,
    });
    return reply.code(204).send();
  });
}
