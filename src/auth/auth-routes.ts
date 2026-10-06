import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import { env } from '../config/env.js';
import { AppError } from '../http/app-error.js';
import { AuthService } from './auth-service.js';
import type { VerificationProvider } from './verification-provider.js';

const phoneSchema = z.string().trim().min(8).max(30);
const pinSchema = z.string().min(6).max(64);
const uuidSchema = z.uuid();
const base64Schema = z
  .string()
  .min(40)
  .max(1_024)
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);

const registerSchema = z.object({ phone: phoneSchema }).strict();
const verifySchema = z
  .object({
    verificationId: uuidSchema,
    code: z.string().regex(/^\d{6}$/),
    name: z.string().trim().min(1).max(100),
    pin: pinSchema,
    deviceName: z.string().trim().min(1).max(100),
    identityPublicKey: base64Schema,
    registrationId: z.number().int().min(0).max(2_147_483_647),
  })
  .strict();
const loginSchema = z
  .object({
    phone: phoneSchema,
    pin: pinSchema,
    deviceId: uuidSchema,
  })
  .strict();
const deviceParamsSchema = z.object({ id: uuidSchema }).strict();
const privacyPreferencesSchema = z
  .object({
    readReceiptsEnabled: z.boolean().optional(),
    typingIndicatorsEnabled: z.boolean().optional(),
  })
  .strict()
  .refine(
    (value) =>
      value.readReceiptsEnabled !== undefined ||
      value.typingIndicatorsEnabled !== undefined,
  );

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    throw new AppError(400, 'INVALID_REQUEST');
  }
  return parsed.data;
}

function sessionResponse(tokens: {
  accessToken: string;
  accessExpiresInSeconds: number;
}): Record<string, unknown> {
  return {
    accessToken: tokens.accessToken,
    tokenType: 'Bearer',
    expiresInSeconds: tokens.accessExpiresInSeconds,
  };
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
    sameSite: 'strict' as const,
    maxAge: env.AUTH_REFRESH_TTL_SECONDS,
  };

  app.post(
    '/auth/register',
    { config: { rateLimit: { max: 5, timeWindow: '15 minutes' } } },
    async (request, reply) => {
      const body = parse(registerSchema, request.body);
      const result = await service.startRegistration(body.phone);
      return reply.code(202).send(result);
    },
  );

  app.post(
    '/auth/verify',
    { config: { rateLimit: { max: 10, timeWindow: '15 minutes' } } },
    async (request, reply) => {
      const body = parse(verifySchema, request.body);
      const identityPublicKey = Buffer.from(body.identityPublicKey, 'base64');
      if (identityPublicKey.length < 32 || identityPublicKey.length > 256) {
        throw new AppError(400, 'INVALID_REQUEST');
      }
      const tokens = await service.verifyRegistration(
        { ...body, identityPublicKey },
        request.id,
      );
      reply.setCookie(env.AUTH_COOKIE_NAME, tokens.refreshToken, cookieOptions);
      return reply.code(201).send(sessionResponse(tokens));
    },
  );

  app.post(
    '/auth/login',
    { config: { rateLimit: { max: 10, timeWindow: '15 minutes' } } },
    async (request, reply) => {
      const body = parse(loginSchema, request.body);
      const tokens = await service.login(
        body.phone,
        body.pin,
        body.deviceId,
        request.id,
      );
      reply.setCookie(env.AUTH_COOKIE_NAME, tokens.refreshToken, cookieOptions);
      return sessionResponse(tokens);
    },
  );

  app.post(
    '/auth/refresh',
    { config: { rateLimit: { max: 30, timeWindow: '15 minutes' } } },
    async (request, reply) => {
      const refreshToken = request.cookies[env.AUTH_COOKIE_NAME];
      if (!refreshToken) {
        throw new AppError(401, 'INVALID_REFRESH_TOKEN');
      }
      const tokens = await service.refresh(refreshToken, request.id);
      reply.setCookie(env.AUTH_COOKIE_NAME, tokens.refreshToken, cookieOptions);
      return sessionResponse(tokens);
    },
  );

  app.post('/auth/logout', async (request, reply) => {
    await service.logout(request.cookies[env.AUTH_COOKIE_NAME]);
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
