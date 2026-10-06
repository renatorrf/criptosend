import { describe, expect, it } from 'vitest';

import { normalizePhone } from '../src/identity/phone.js';
import { decryptField, encryptField } from '../src/security/field-crypto.js';
import {
  constantTimeHexEqual,
  createPhoneLookupHash,
  createVerificationCodeHash,
} from '../src/security/hashes.js';
import { hashPin, verifyPin } from '../src/security/pin.js';
import {
  createAccessToken,
  createRefreshToken,
  verifyAccessToken,
} from '../src/auth/tokens.js';
import { createDirectConversationKey } from '../src/conversations/conversation-service.js';
import { recoveryProofMessage, verifyRecoveryProof } from '../src/auth/recovery-proof.js';

describe('identity security primitives', () => {
  it('normalizes Brazilian phone numbers to one E.164 representation', () => {
    expect(normalizePhone('(34) 99862-2662')).toBe('+5534998622662');
    expect(normalizePhone('+55 34 99862-2662')).toBe('+5534998622662');
  });

  it('rejects an incomplete phone number', () => {
    expect(() => normalizePhone('3499')).toThrow('INVALID_PHONE');
  });

  it('encrypts fields with authenticated random nonces', () => {
    const first = encryptField('confidential', 'test-field');
    const second = encryptField('confidential', 'test-field');

    expect(first.equals(second)).toBe(false);
    expect(decryptField(first, 'test-field')).toBe('confidential');
    expect(decryptField(second, 'test-field')).toBe('confidential');
    expect(() => decryptField(first, 'different-field')).toThrow();
  });

  it('creates deterministic, context-bound blind indexes', () => {
    expect(createPhoneLookupHash('+5534998622662')).toHaveLength(64);
    expect(createPhoneLookupHash('+5534998622662')).toBe(
      createPhoneLookupHash('+5534998622662'),
    );
    expect(createVerificationCodeHash('challenge-a', '123456')).not.toBe(
      createVerificationCodeHash('challenge-b', '123456'),
    );
    expect(constantTimeHexEqual('aa'.repeat(32), 'aa'.repeat(32))).toBe(true);
    expect(constantTimeHexEqual('aa'.repeat(32), 'bb'.repeat(32))).toBe(false);
  });

  it('hashes PINs with Argon2id and rejects a different PIN', async () => {
    const hash = await hashPin('837291');

    expect(hash.startsWith('$argon2id$')).toBe(true);
    await expect(verifyPin(hash, '837291')).resolves.toBe(true);
    await expect(verifyPin(hash, '000000')).resolves.toBe(false);
  });

  it('signs scoped short-lived access tokens and creates opaque refresh tokens', async () => {
    const context = {
      userId: '1c39cf64-b652-4a5b-82b8-9dfec96b4695',
      deviceId: '52c913d8-1bfc-44c6-8445-ed255598f2c7',
      sessionId: '57657215-f8a0-43c6-80c5-48762f854a02',
    };

    const accessToken = await createAccessToken(context);
    await expect(verifyAccessToken(accessToken)).resolves.toEqual(context);
    expect(createRefreshToken()).toMatch(/^[A-Za-z0-9_-]{40,}$/);
  });

  it('derives the same opaque direct-conversation key regardless of user order', () => {
    const first = '1c39cf64-b652-4a5b-82b8-9dfec96b4695';
    const second = '52c913d8-1bfc-44c6-8445-ed255598f2c7';

    expect(createDirectConversationKey(first, second)).toBe(
      createDirectConversationKey(second, first),
    );
    expect(createDirectConversationKey(first, second)).toHaveLength(64);
  });

  it('verifies browser-compatible P-256 recovery proofs', async () => {
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const verificationId = '1c39cf64-b652-4a5b-82b8-9dfec96b4695';
    const challenge = Buffer.from('recovery-challenge');
    const signature = Buffer.from(
      await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        pair.privateKey,
        recoveryProofMessage(verificationId, challenge),
      ),
    );
    const publicKey = Buffer.from(await crypto.subtle.exportKey('spki', pair.publicKey));

    expect(verifyRecoveryProof(publicKey, verificationId, challenge, signature)).toBe(true);
    expect(
      verifyRecoveryProof(publicKey, verificationId, Buffer.from('other'), signature),
    ).toBe(false);
  });
});
