import argon2 from 'argon2';

import { env } from '../config/env.js';

const DUMMY_PIN_HASH =
  '$argon2id$v=19$m=19456,p=1,t=2$wlzOjkz4cReTbQbDkF9DvA$NLjqPl9F/Qa5DBxARn9bFRsiiimlo2w3YTdXzvGtZRU';

export async function hashPin(pin: string): Promise<string> {
  return argon2.hash(pin, {
    type: argon2.argon2id,
    memoryCost: env.ARGON2_MEMORY_COST,
    timeCost: env.ARGON2_TIME_COST,
    parallelism: env.ARGON2_PARALLELISM,
  });
}

export async function verifyPin(
  pinHash: string | undefined,
  pin: string,
): Promise<boolean> {
  const valid = await argon2.verify(pinHash ?? DUMMY_PIN_HASH, pin);
  return pinHash === undefined ? false : valid;
}

export const hashPassword = hashPin;
export const verifyPassword = verifyPin;
