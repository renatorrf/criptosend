import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import type { AuthService } from '../auth/auth-service.js';
import { AppError } from '../http/app-error.js';
import type { RealtimeHub } from '../realtime/realtime-hub.js';
import { ConversationService } from './conversation-service.js';

const idParamsSchema = z.object({ id: z.uuid() }).strict();
const nickname = z.string().trim().min(3).max(40);
const directSchema = z.object({ nickname }).strict();
const groupSchema = z.object({
  name: z.string().trim().min(2).max(80),
  nicknames: z.array(nickname).min(1).max(49),
}).strict();
const listQuerySchema = z.object({ search: z.string().trim().max(80).optional() }).strict();

export function registerConversationRoutes(
  app: FastifyInstance,
  authService: AuthService,
  conversations: ConversationService,
  realtime: RealtimeHub,
): void {
  app.get('/conversations', async (request) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const parsed = listQuerySchema.safeParse(request.query);
    if (!parsed.success) {
      throw new AppError(400, 'INVALID_REQUEST');
    }
    return {
      conversations: await conversations.list(auth.userId, parsed.data.search),
    };
  });

  app.post('/conversations/direct', async (request, reply) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const parsed = directSchema.safeParse(request.body);
    if (!parsed.success) {
      throw new AppError(400, 'INVALID_REQUEST');
    }
    const conversation = await conversations.createDirect(auth.userId, parsed.data.nickname);
    const memberIds = await conversations.listMemberUserIds(conversation.id);
    realtime.emitToUsers(memberIds, 'conversation:created', conversation);
    return reply.code(201).send(conversation);
  });

  app.post('/conversations/groups', async (request, reply) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const parsed = groupSchema.safeParse(request.body);
    if (!parsed.success) throw new AppError(400, 'INVALID_REQUEST');
    const conversation = await conversations.createGroup(
      auth.userId,
      parsed.data.name,
      parsed.data.nicknames,
    );
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
