import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import type { AuthService } from '../auth/auth-service.js';
import { AppError } from '../http/app-error.js';
import { UserService } from './user-service.js';

const lookupSchema = z.object({ phone: z.string().trim().min(8).max(30) }).strict();

export function registerUserRoutes(
  app: FastifyInstance,
  authService: AuthService,
): void {
  const service = new UserService();

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
        exists: await service.exactPhoneLookup(
          auth.userId,
          auth.deviceId,
          parsed.data.phone,
          request.id,
        ),
      };
    },
  );
}

