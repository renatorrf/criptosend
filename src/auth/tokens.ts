import { randomBytes } from 'node:crypto';

import { jwtVerify, SignJWT } from 'jose';

import { env } from '../config/env.js';
import { AppError } from '../http/app-error.js';

const issuer = 'criptsend';
const audience = 'criptsend-api';
const accessSecret = new TextEncoder().encode(env.JWT_ACCESS_SECRET);

export interface AuthContext {
  userId: string;
  deviceId: string;
  sessionId: string;
}

export async function createAccessToken(context: AuthContext): Promise<string> {
  return new SignJWT({
    deviceId: context.deviceId,
    sessionId: context.sessionId,
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(context.userId)
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime(`${String(env.AUTH_ACCESS_TTL_SECONDS)}s`)
    .sign(accessSecret);
}

export async function verifyAccessToken(token: string): Promise<AuthContext> {
  try {
    const { payload } = await jwtVerify(token, accessSecret, {
      issuer,
      audience,
      algorithms: ['HS256'],
    });

    if (
      typeof payload.sub !== 'string' ||
      typeof payload.deviceId !== 'string' ||
      typeof payload.sessionId !== 'string'
    ) {
      throw new Error('Missing token claims.');
    }

    return {
      userId: payload.sub,
      deviceId: payload.deviceId,
      sessionId: payload.sessionId,
    };
  } catch {
    throw new AppError(401, 'UNAUTHORIZED');
  }
}

export function createRefreshToken(): string {
  return randomBytes(32).toString('base64url');
}
