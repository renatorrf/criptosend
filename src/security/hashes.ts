import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import { env } from '../config/env.js';

export function createPhoneLookupHash(e164Phone: string): string {
  return createHmac('sha256', env.PHONE_LOOKUP_SECRET)
    .update(e164Phone, 'utf8')
    .digest('hex');
}

export function createVerificationCodeHash(
  challengeId: string,
  code: string,
): string {
  return createHmac('sha256', env.VERIFICATION_CODE_SECRET)
    .update(`${challengeId}:${code}`, 'utf8')
    .digest('hex');
}

export function constantTimeHexEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, 'hex');
  const rightBytes = Buffer.from(right, 'hex');
  return (
    leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes)
  );
}

export function hashRefreshToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

