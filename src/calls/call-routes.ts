import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import type { AuthService } from '../auth/auth-service.js';
import { AppError } from '../http/app-error.js';
import type { CallService } from './call-service.js';
import { createIceServers } from './turn-credentials.js';

const conversationParamsSchema = z.object({ id: z.uuid() }).strict();
const listQuerySchema = z
  .object({ limit: z.coerce.number().int().min(1).max(100).default(30) })
  .strict();

export function registerCallRoutes(
  app: FastifyInstance,
  authService: AuthService,
  calls: CallService,
): void {
  app.get('/calls/ice-config', async (request) => {
    const auth = await authService.authenticate(request.headers.authorization);
    return { iceServers: createIceServers(auth.userId) };
  });

  app.get('/conversations/:id/calls', async (request) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const params = conversationParamsSchema.safeParse(request.params);
    const query = listQuerySchema.safeParse(request.query);
    if (!params.success || !query.success) {
      throw new AppError(400, 'INVALID_REQUEST');
    }
    return {
      calls: await calls.list(auth.userId, params.data.id, query.data.limit),
    };
  });
}
