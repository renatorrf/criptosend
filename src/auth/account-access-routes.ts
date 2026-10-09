import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';

import { env } from '../config/env.js';
import { AppError } from '../http/app-error.js';
import {
  AccountAccessService,
  type DeviceInput,
  type RecoveryCredentialInput,
} from './account-access-service.js';
import type { VerificationProvider } from './verification-provider.js';

const uuid = z.uuid();
const password = z.string().min(8).max(128);
const base64 = z
  .string()
  .min(16)
  .max(16_384)
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
const flow = {
  verificationId: uuid,
  flowToken: z.string().min(40).max(128),
};
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
const startSchema = z
  .object({
    phone: z.string().trim().min(8).max(30),
    name: z.string().trim().min(1).max(100),
    purpose: z.enum(['ACCESS', 'PASSWORD_RECOVERY', 'ADMIN_RESET']).default('ACCESS'),
  })
  .strict();
const verifySchema = z
  .object({ verificationId: uuid, code: z.string().regex(/^\d{6}$/) })
  .strict();
const registrationSchema = z
  .object({
    ...flow,
    name: z.string().trim().min(2).max(100),
    password,
    device: deviceSchema,
    recovery: recoverySchema,
  })
  .strict();
const loginSchema = z
  .object({ ...flow, password: z.string().min(6).max(128), device: deviceSchema })
  .strict();
const passwordRecoverySchema = z
  .object({ ...flow, signature: base64, newPassword: password })
  .strict();
const adminRequestSchema = z.object(flow).strict();
const adminStatusSchema = z
  .object({ requestId: uuid, claimToken: z.string().min(40).max(128) })
  .strict();
const adminCompleteSchema = z
  .object({
    requestId: uuid,
    claimToken: z.string().min(40).max(128),
    password,
    device: deviceSchema,
    recovery: recoverySchema,
  })
  .strict();

function parse<T>(schema: z.ZodType<T>, input: unknown): T {
  const result = schema.safeParse(input);
  if (!result.success) throw new AppError(400, 'INVALID_REQUEST');
  return result.data;
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

export function registerAccountAccessRoutes(
  app: FastifyInstance,
  verificationProvider: VerificationProvider,
): void {
  const service = new AccountAccessService(verificationProvider);
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
    session: Awaited<ReturnType<AccountAccessService['register']>>,
  ): unknown => {
    reply.setCookie(env.AUTH_COOKIE_NAME, session.refreshToken, cookieOptions);
    return reply.send({
      accessToken: session.accessToken,
      refreshToken: session.refreshToken,
      tokenType: 'Bearer',
      expiresInSeconds: session.accessExpiresInSeconds,
      userId: session.userId,
      deviceId: session.deviceId,
    });
  };

  app.post(
    '/auth/access/start',
    { config: { rateLimit: { max: 5, timeWindow: '15 minutes' } } },
    async (request, reply) => {
      const body = parse(startSchema, request.body);
      return reply.code(202).send(await service.start(body.phone, body.name, body.purpose));
    },
  );

  app.post(
    '/auth/access/verify',
    { config: { rateLimit: { max: 10, timeWindow: '15 minutes' } } },
    async (request) => {
      const body = parse(verifySchema, request.body);
      return service.verifyPhone(body.verificationId, body.code, request.id);
    },
  );

  app.post('/auth/access/register', { config: { rateLimit: { max: 5, timeWindow: '15 minutes' } } }, async (request, reply) => {
    const body = parse(registrationSchema, request.body);
    const session = await service.register(
      body.verificationId,
      body.flowToken,
      body.name,
      body.password,
      mapDevice(body.device),
      mapRecovery(body.recovery),
      request.id,
    );
    reply.code(201);
    return respondWithSession(reply, session);
  });

  app.post('/auth/access/login', { config: { rateLimit: { max: 10, timeWindow: '15 minutes' } } }, async (request, reply) => {
    const body = parse(loginSchema, request.body);
    return respondWithSession(
      reply,
      await service.login(
        body.verificationId,
        body.flowToken,
        body.password,
        mapDevice(body.device),
        request.id,
      ),
    );
  });

  app.post('/auth/recovery/password', { config: { rateLimit: { max: 5, timeWindow: '15 minutes' } } }, async (request, reply) => {
    const body = parse(passwordRecoverySchema, request.body);
    await service.recoverPassword(
      body.verificationId,
      body.flowToken,
      decode(body.signature, 64, 144),
      body.newPassword,
      request.id,
    );
    return reply.code(204).send();
  });

  app.post('/auth/recovery/admin-request', { config: { rateLimit: { max: 3, timeWindow: '1 hour' } } }, async (request, reply) => {
    const body = parse(adminRequestSchema, request.body);
    return reply.code(202).send(
      await service.requestAdminReset(body.verificationId, body.flowToken, request.id),
    );
  });

  app.post('/auth/recovery/admin-status', async (request) => {
    const body = parse(adminStatusSchema, request.body);
    return service.adminResetStatus(body.requestId, body.claimToken);
  });

  app.post('/auth/recovery/admin-complete', { config: { rateLimit: { max: 5, timeWindow: '1 hour' } } }, async (request, reply) => {
    const body = parse(adminCompleteSchema, request.body);
    return respondWithSession(
      reply,
      await service.completeAdminReset(
        body.requestId,
        body.claimToken,
        body.password,
        mapDevice(body.device),
        mapRecovery(body.recovery),
        request.id,
      ),
    );
  });
}
