import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import type { AuthService } from '../auth/auth-service.js';
import { AppError } from '../http/app-error.js';
import type { PushService } from './push-service.js';

export const subscriptionSchema = z.object({
  endpoint: z.url().max(2048),
  // Safari/iOS may omit expirationTime from PushSubscription.toJSON().
  expirationTime: z.number().nullable().optional().transform((value) => value ?? null),
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
  app.get('/push/status', async (request) => {
    const auth = await authService.authenticate(request.headers.authorization);
    return push.status(auth.userId);
  });

  app.post('/push/subscriptions', async (request, reply) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const parsed = subscriptionSchema.safeParse(request.body);
    if (!parsed.success || !push.configured) {
      throw new AppError(push.configured ? 400 : 503, push.configured ? 'INVALID_REQUEST' : 'PUSH_UNAVAILABLE');
    }
    await push.register(auth.userId, auth.deviceId, parsed.data);
    return reply.code(204).send();
  });

  app.post('/push/subscriptions/status', async (request) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const parsed = revokeSchema.safeParse(request.body);
    if (!parsed.success) throw new AppError(400, 'INVALID_REQUEST');
    return push.subscriptionStatus(auth.userId, auth.deviceId, parsed.data.endpoint);
  });

  app.post('/push/test', async (request, reply) => {
    const auth = await authService.authenticate(request.headers.authorization);
    if (!push.configured) throw new AppError(503, 'PUSH_UNAVAILABLE');
    const result = await push.notifyTest(auth.userId);
    if (result.attempted === 0) {
      throw new AppError(409, 'PUSH_SUBSCRIPTION_REQUIRED');
    }
    if (result.delivered === 0) {
      throw new AppError(503, 'PUSH_DELIVERY_FAILED');
    }
    return reply.code(202).send({ queued: true, ...result });
  });

  app.delete('/push/subscriptions', async (request, reply) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const parsed = revokeSchema.safeParse(request.body);
    if (!parsed.success) throw new AppError(400, 'INVALID_REQUEST');
    await push.revoke(auth.userId, auth.deviceId, parsed.data.endpoint);
    return reply.code(204).send();
  });
}
