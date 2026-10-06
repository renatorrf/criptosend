import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import type { AuthService } from '../auth/auth-service.js';
import { AppError } from '../http/app-error.js';
import { KeyService } from './key-service.js';

const uuidSchema = z.uuid();
const base64Schema = z
  .string()
  .min(40)
  .max(1_024)
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
const publicPrekeySchema = z.object({
  prekeyId: z.number().int().min(0).max(2_147_483_647),
  publicKey: base64Schema,
});
const uploadSchema = z
  .object({
    signedPrekey: publicPrekeySchema.extend({ signature: base64Schema }),
    oneTimePrekeys: z.array(publicPrekeySchema).min(1).max(100),
  })
  .strict();
const bundleParamsSchema = z.object({ userId: uuidSchema }).strict();
const mediaIdentitySchema = z.object({ publicKey: base64Schema }).strict();

function decodePublicValue(value: string): Buffer {
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length < 32 || decoded.length > 256) {
    throw new AppError(400, 'INVALID_REQUEST');
  }
  return decoded;
}

export function registerKeyRoutes(
  app: FastifyInstance,
  authService: AuthService,
): void {
  const service = new KeyService();

  app.put('/keys/media-identity', async (request, reply) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const parsed = mediaIdentitySchema.safeParse(request.body);
    if (!parsed.success) {
      throw new AppError(400, 'INVALID_REQUEST');
    }
    const publicKey = decodePublicValue(parsed.data.publicKey);
    if (publicKey.length < 64) {
      throw new AppError(400, 'INVALID_REQUEST');
    }
    const result = await service.registerMediaIdentity(
      auth.userId,
      auth.deviceId,
      publicKey,
    );
    return reply.code(result.created ? 201 : 200).send({ created: result.created });
  });

  app.get('/keys/users/:userId/media-identities', async (request, reply) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const parsed = bundleParamsSchema.safeParse(request.params);
    if (!parsed.success) {
      throw new AppError(400, 'INVALID_REQUEST');
    }
    reply.header('cache-control', 'no-store');
    return {
      identities: await service.listMediaIdentities(auth.userId, parsed.data.userId),
    };
  });

  app.post('/keys/prekeys', async (request, reply) => {
    const auth = await authService.authenticate(request.headers.authorization);
    const parsed = uploadSchema.safeParse(request.body);
    if (!parsed.success) {
      throw new AppError(400, 'INVALID_REQUEST');
    }

    const ids = [
      parsed.data.signedPrekey.prekeyId,
      ...parsed.data.oneTimePrekeys.map(({ prekeyId }) => prekeyId),
    ];
    if (new Set(ids).size !== ids.length) {
      throw new AppError(400, 'DUPLICATE_PREKEY_ID');
    }

    await service.uploadPrekeys(
      auth.userId,
      auth.deviceId,
      {
        prekeyId: parsed.data.signedPrekey.prekeyId,
        publicKey: decodePublicValue(parsed.data.signedPrekey.publicKey),
        signature: decodePublicValue(parsed.data.signedPrekey.signature),
      },
      parsed.data.oneTimePrekeys.map((prekey) => ({
        prekeyId: prekey.prekeyId,
        publicKey: decodePublicValue(prekey.publicKey),
      })),
    );
    return reply.code(204).send();
  });

  app.get(
    '/keys/:userId/bundle',
    { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const auth = await authService.authenticate(request.headers.authorization);
      const parsed = bundleParamsSchema.safeParse(request.params);
      if (!parsed.success) {
        throw new AppError(400, 'INVALID_REQUEST');
      }
      reply.header('cache-control', 'no-store');
      return {
        devices: await service.claimBundle(auth.deviceId, parsed.data.userId),
      };
    },
  );
}
