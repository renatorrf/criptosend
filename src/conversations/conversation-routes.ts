import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import type { AuthService } from '../auth/auth-service.js';
import { AppError } from '../http/app-error.js';
import type { RealtimeHub } from '../realtime/realtime-hub.js';
import { ConversationService } from './conversation-service.js';

const idParamsSchema = z.object({ id: z.uuid() }).strict();
const directSchema = z.object({ phone: z.string().trim().min(8).max(30) }).strict();

export function registerConversationRoutes(
  app: FastifyInstance,
  authService: AuthService,
  conversations: ConversationService,
  realtime: RealtimeHub,
): void {
  app.get('/conversations', async (request) => {
    const auth = await authService.authenticate(request.headers.authorization);
    return { conversations: await conversations.list(auth.userId) };
  });

  app.post('/conversations/direct', async (request, reply) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const parsed = directSchema.safeParse(request.body);
    if (!parsed.success) {
      throw new AppError(400, 'INVALID_REQUEST');
    }
    const conversation = await conversations.createDirect(auth.userId, parsed.data.phone);
    const memberIds = await conversations.listMemberUserIds(conversation.id);
    realtime.emitToUsers(memberIds, 'conversation:created', conversation);
    return reply.code(201).send(conversation);
  });

  app.get('/conversations/:id', async (request) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const parsed = idParamsSchema.safeParse(request.params);
    if (!parsed.success) {
      throw new AppError(400, 'INVALID_REQUEST');
    }
    return conversations.get(auth.userId, parsed.data.id);
  });
}

