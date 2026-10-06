import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from 'node:crypto';

import { env } from '../config/env.js';

const FORMAT_VERSION = 1;
const NONCE_BYTES = 12;
const AUTH_TAG_BYTES = 16;

export function encryptField(value: string, context: string): Buffer {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', env.FIELD_ENCRYPTION_KEY, nonce);
  cipher.setAAD(Buffer.from(context, 'utf8'));
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);

  return Buffer.concat([
    Buffer.from([FORMAT_VERSION]),
    nonce,
    cipher.getAuthTag(),
    ciphertext,
  ]);
}

export function decryptField(payload: Buffer, context: string): string {
  if (
    payload.length <= 1 + NONCE_BYTES + AUTH_TAG_BYTES ||
    payload[0] !== FORMAT_VERSION
  ) {
    throw new Error('Unsupported encrypted field format.');
  }

  const nonceStart = 1;
  const tagStart = nonceStart + NONCE_BYTES;
  const ciphertextStart = tagStart + AUTH_TAG_BYTES;
  const decipher = createDecipheriv(
    'aes-256-gcm',
    env.FIELD_ENCRYPTION_KEY,
    payload.subarray(nonceStart, tagStart),
  );
  decipher.setAAD(Buffer.from(context, 'utf8'));
  decipher.setAuthTag(payload.subarray(tagStart, ciphertextStart));

  return Buffer.concat([
    decipher.update(payload.subarray(ciphertextStart)),
    decipher.final(),
  ]).toString('utf8');
}
