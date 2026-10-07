import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';

import { env } from '../config/env.js';
import { AppError } from '../http/app-error.js';
import type { AuthService } from './auth-service.js';
import type {
  DeviceInput,
  RecoveryCredentialInput,
} from './account-access-service.js';
import { PlatformAccessService } from './platform-access-service.js';

const uuid = z.uuid();
const password = z.string().min(10).max(128);
const username = z.string().trim().min(3).max(40);
const base64 = z
  .string()
  .min(16)
  .max(16_384)
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
const deviceSchema = z
  .object({
    deviceId: uuid.optional(),
    deviceName: z.string().trim().min(1).max(100).optional(),
    identityPublicKey: base64.optional(),
    registrationId: z.number().int().min(0).max(2_147_483_647).optional(),
  })
  .strict();
const recoverySchema = z
  .object({
    keyId: uuid,
    publicKey: base64,
    wrappedPrivateKey: base64,
    wrappingIv: base64,
    kdfSalt: base64,
    kdfParameters: z
      .object({
        memorySize: z.number().int().min(19_456).max(262_144),
        iterations: z.number().int().min(2).max(10),
        parallelism: z.number().int().min(1).max(8),
        hashLength: z.literal(32),
      })
      .strict(),
  })
  .strict();
const loginSchema = z
  .object({ username, password: z.string().min(1).max(128), device: deviceSchema })
  .strict();
const redeemSchema = z
  .object({
    invitationCode: z.string().trim().min(20).max(128),
    name: z.string().trim().min(2).max(100),
    username,
    password,
    device: deviceSchema,
    recovery: recoverySchema,
  })
  .strict();
const invitationSchema = z
  .object({
    role: z.enum(['MANAGER', 'USER']),
    expiresInHours: z.number().int().min(1).max(24 * 30).default(72),
  })
  .strict();
const statusSchema = z.object({ status: z.enum(['ACTIVE', 'SUSPENDED']) }).strict();
const phoneSchema = z
  .object({ phone: z.string().trim().min(8).max(30).nullable() })
  .strict();
const changePasswordSchema = z
  .object({ currentPassword: z.string().min(1).max(128), newPassword: password })
  .strict();

function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new AppError(400, 'INVALID_REQUEST');
  return parsed.data;
}

function decode(value: string, min: number, max: number): Buffer {
  const result = Buffer.from(value, 'base64');
  if (result.length < min || result.length > max) {
    throw new AppError(400, 'INVALID_REQUEST');
  }
  return result;
}

function mapDevice(input: z.infer<typeof deviceSchema>): DeviceInput {
  return {
    ...(input.deviceId ? { deviceId: input.deviceId } : {}),
    ...(input.deviceName ? { deviceName: input.deviceName } : {}),
    ...(input.identityPublicKey
      ? { identityPublicKey: decode(input.identityPublicKey, 64, 256) }
      : {}),
    ...(input.registrationId !== undefined
      ? { registrationId: input.registrationId }
      : {}),
  };
}

function mapRecovery(input: z.infer<typeof recoverySchema>): RecoveryCredentialInput {
  return {
    keyId: input.keyId,
    publicKey: decode(input.publicKey, 64, 256),
    wrappedPrivateKey: decode(input.wrappedPrivateKey, 48, 16_384),
    wrappingIv: decode(input.wrappingIv, 12, 12),
    kdfSalt: decode(input.kdfSalt, 16, 64),
    kdfParameters: input.kdfParameters,
  };
}

export function registerPlatformAccessRoutes(
  app: FastifyInstance,
  authService: AuthService,
): void {
  const service = new PlatformAccessService();
  const cookieOptions = {
    path: '/auth',
    httpOnly: true,
    secure: env.AUTH_COOKIE_SECURE,
    sameSite: env.NODE_ENV === 'production' ? ('none' as const) : ('lax' as const),
    partitioned: env.NODE_ENV === 'production',
    maxAge: env.AUTH_REFRESH_TTL_SECONDS,
  };
  const respondWithSession = (
    reply: FastifyReply,
    session: Awaited<ReturnType<PlatformAccessService['login']>>,
  ): unknown => {
    reply.setCookie(env.AUTH_COOKIE_NAME, session.refreshToken, cookieOptions);
    return reply.send({
      accessToken: session.accessToken,
      tokenType: 'Bearer',
      expiresInSeconds: session.accessExpiresInSeconds,
      userId: session.userId,
      deviceId: session.deviceId,
    });
  };

  app.post(
    '/auth/username/login',
    { config: { rateLimit: { max: 10, timeWindow: '15 minutes' } } },
    async (request, reply) => {
      const body = parse(loginSchema, request.body);
      return respondWithSession(
        reply,
        await service.login(body.username, body.password, mapDevice(body.device), request.id),
      );
    },
  );

  app.post(
    '/auth/invitations/redeem',
    { config: { rateLimit: { max: 5, timeWindow: '1 hour' } } },
    async (request, reply) => {
      const body = parse(redeemSchema, request.body);
      reply.code(201);
      return respondWithSession(
        reply,
        await service.redeemInvitation(
          body.invitationCode,
          body.name,
          body.username,
          body.password,
          mapDevice(body.device),
          mapRecovery(body.recovery),
          request.id,
        ),
      );
    },
  );

  app.post('/management/invitations', async (request, reply) => {
    const actor = await authService.authenticate(request.headers.authorization);
    const body = parse(invitationSchema, request.body);
    return reply
      .code(201)
      .send(await service.createInvitation(actor, body.role, body.expiresInHours, request.id));
  });

  app.get('/management/invitations', async (request) => {
    const actor = await authService.authenticate(request.headers.authorization);
    return { invitations: await service.listInvitations(actor) };
  });

  app.delete('/management/invitations/:id', async (request, reply) => {
    const actor = await authService.authenticate(request.headers.authorization);
    const params = parse(z.object({ id: uuid }).strict(), request.params);
    await service.revokeInvitation(actor, params.id);
    return reply.code(204).send();
  });

  app.get('/management/users', async (request) => {
    const actor = await authService.authenticate(request.headers.authorization);
    return { users: await service.listManagedUsers(actor) };
  });

  app.patch('/management/users/:id/status', async (request, reply) => {
    const actor = await authService.authenticate(request.headers.authorization);
    const params = parse(z.object({ id: uuid }).strict(), request.params);
    const body = parse(statusSchema, request.body);
    await service.setManagedUserStatus(actor, params.id, body.status);
    return reply.code(204).send();
  });

  app.patch('/me/phone', async (request) => {
    const actor = await authService.authenticate(request.headers.authorization);
    const body = parse(phoneSchema, request.body);
    return service.updatePhone(actor, body.phone, request.id);
  });

  app.patch('/me/password', async (request, reply) => {
    const actor = await authService.authenticate(request.headers.authorization);
    const body = parse(changePasswordSchema, request.body);
    await service.changePassword(actor, body.currentPassword, body.newPassword, request.id);
    return reply.code(204).send();
  });
}
