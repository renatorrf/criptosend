import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import type { AuthService } from '../auth/auth-service.js';
import { AppError } from '../http/app-error.js';
import { UserService } from './user-service.js';

const lookupSchema = z.object({ nickname: z.string().trim().min(3).max(40) }).strict();
const directorySchema = z.object({
  search: z.string().trim().max(80).default(''),
  limit: z.coerce.number().int().min(1).max(50).default(50),
  scope: z.enum(['network', 'managed']).default('network'),
}).strict();

export function registerUserRoutes(
  app: FastifyInstance,
  authService: AuthService,
): void {
  const service = new UserService();

  app.get(
    '/users',
    { config: { rateLimit: { max: 600, timeWindow: '1 hour' } } },
    async (request) => {
      const auth = await authService.authenticate(request.headers.authorization);
      const parsed = directorySchema.safeParse(request.query);
      if (!parsed.success) throw new AppError(400, 'INVALID_REQUEST');
      return {
        users: await service.searchNetwork(
          auth.userId,
          parsed.data.search,
          parsed.data.limit,
          parsed.data.scope,
        ),
      };
    },
  );

  app.post(
    '/users/lookup',
    { config: { rateLimit: { max: 40, timeWindow: '1 hour' } } },
    async (request) => {
      const auth = await authService.authenticate(request.headers.authorization);
      const parsed = lookupSchema.safeParse(request.body);
      if (!parsed.success) {
        throw new AppError(400, 'INVALID_REQUEST');
      }
      return {
        user: await service.exactNicknameLookup(
          auth.userId,
          auth.deviceId,
          parsed.data.nickname,
          request.id,
        ),
      };
    },
  );
}

