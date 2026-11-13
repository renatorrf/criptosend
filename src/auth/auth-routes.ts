import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { env } from '../config/env.js';
import { AppError } from '../http/app-error.js';
import { AuthService } from './auth-service.js';
import type { VerificationProvider } from './verification-provider.js';

const uuidSchema = z.uuid();
const deviceParamsSchema = z.object({ id: uuidSchema }).strict();
const privacyPreferencesSchema = z
  .object({
    readReceiptsEnabled: z.boolean().optional(),
    typingIndicatorsEnabled: z.boolean().optional(),
    messageRetentionSeconds: z.number().int().min(60).max(2_592_000).nullable().optional(),
  })
  .strict()
  .refine(
    (value) =>
      value.readReceiptsEnabled !== undefined ||
      value.typingIndicatorsEnabled !== undefined ||
      value.messageRetentionSeconds !== undefined,
  );

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    throw new AppError(400, 'INVALID_REQUEST');
  }
  return parsed.data;
}

function assertTrustedOrigin(request: FastifyRequest): void {
  const origin = request.headers.origin;
  if (origin && !env.APP_ORIGINS.includes(origin)) {
    throw new AppError(403, 'ORIGIN_NOT_ALLOWED');
  }
}

function sessionResponse(tokens: {
  accessToken: string;
  refreshToken: string;
  accessExpiresInSeconds: number;
}): Record<string, unknown> {
  return {
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    tokenType: 'Bearer',
    expiresInSeconds: tokens.accessExpiresInSeconds,
  };
}

function requestRefreshToken(request: FastifyRequest): string | undefined {
  const authorization = request.headers.authorization;
  if (authorization?.startsWith('Bearer ')) {
    return authorization.slice(7);
  }
  return request.cookies[env.AUTH_COOKIE_NAME];
}

export async function registerAuthRoutes(
  app: FastifyInstance,
  verificationProvider: VerificationProvider,
): Promise<AuthService> {
  await app.register(cookie);
  await app.register(rateLimit, {
    global: false,
    hook: 'preHandler',
    keyGenerator: (request) => request.ip,
    errorResponseBuilder: () => ({ error: 'RATE_LIMITED' }),
  });

  const service = new AuthService(verificationProvider);
  const cookieOptions = {
    path: '/auth',
    httpOnly: true,
    secure: env.AUTH_COOKIE_SECURE,
    sameSite: env.NODE_ENV === 'production' ? ('none' as const) : ('lax' as const),
    partitioned: env.NODE_ENV === 'production',
    maxAge: env.AUTH_REFRESH_TTL_SECONDS,
  };

  app.post(
    '/auth/session/refresh',
    { config: { rateLimit: { max: 30, timeWindow: '15 minutes' } } },
    async (request, reply) => {
      assertTrustedOrigin(request);
      const authorization = request.headers.authorization;
      const refreshToken = authorization?.startsWith('Bearer ') ? authorization.slice(7) : undefined;
      if (!refreshToken) {
        throw new AppError(401, 'INVALID_REFRESH_TOKEN');
      }
      const tokens = await service.refresh(refreshToken, request.id);
      return reply.send(sessionResponse(tokens));
    },
  );

  app.post('/auth/logout', async (request, reply) => {
    assertTrustedOrigin(request);
    await service.logout(requestRefreshToken(request));
    reply.clearCookie(env.AUTH_COOKIE_NAME, cookieOptions);
    return reply.code(204).send();
  });

  app.get('/me', async (request) => {
    const auth = await service.authenticate(request.headers.authorization);
    return {
      ...(await service.getMe(auth.userId)),
      deviceId: auth.deviceId,
    };
  });

  app.patch('/me', async (request) => {
    const auth = await service.authenticate(request.headers.authorization);
    const preferences = parse(privacyPreferencesSchema, request.body);
    return service.updatePrivacyPreferences(auth.userId, preferences);
  });

  app.get('/devices', async (request) => {
    const auth = await service.authenticate(request.headers.authorization);
    return { devices: await service.listDevices(auth.userId) };
  });

  app.delete('/devices/:id', async (request, reply) => {
    const auth = await service.authenticate(request.headers.authorization);
    const params = parse(deviceParamsSchema, request.params);
    await service.revokeDevice(auth.userId, params.id);
    if (params.id === auth.deviceId) {
      reply.clearCookie(env.AUTH_COOKIE_NAME, cookieOptions);
    }
    return reply.code(204).send();
  });

  return service;
}
