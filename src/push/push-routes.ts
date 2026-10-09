import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import type { AuthService } from '../auth/auth-service.js';
import { AppError } from '../http/app-error.js';
import type { PushService } from './push-service.js';

const subscriptionSchema = z.object({
  endpoint: z.url().max(2048),
  expirationTime: z.number().nullable(),
  keys: z.object({
    p256dh: z.string().min(20).max(512),
    auth: z.string().min(8).max(256),
  }).strict(),
}).strict();

const revokeSchema = z.object({ endpoint: z.url().max(2048) }).strict();

export function registerPushRoutes(
  app: FastifyInstance,
  authService: AuthService,
  push: PushService,
): void {
  app.post('/push/subscriptions', async (request, reply) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const parsed = subscriptionSchema.safeParse(request.body);
    if (!parsed.success || !push.configured) {
      throw new AppError(push.configured ? 400 : 503, push.configured ? 'INVALID_REQUEST' : 'PUSH_UNAVAILABLE');
    }
    await push.register(auth.userId, auth.deviceId, parsed.data);
    return reply.code(204).send();
  });

  app.delete('/push/subscriptions', async (request, reply) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const parsed = revokeSchema.safeParse(request.body);
    if (!parsed.success) throw new AppError(400, 'INVALID_REQUEST');
    await push.revoke(auth.userId, auth.deviceId, parsed.data.endpoint);
    return reply.code(204).send();
  });
}
