import { createPublicKey, verify as verifySignature } from 'node:crypto';

export function recoveryProofMessage(
  verificationId: string,
  challenge: Buffer,
): Buffer {
  return Buffer.from(
    `criptsend-password-recovery-v1:${verificationId}:${challenge.toString('base64')}`,
    'utf8',
  );
}

export function verifyRecoveryProof(
  publicKeyDer: Buffer,
  verificationId: string,
  challenge: Buffer,
  signature: Buffer,
): boolean {
  const publicKey = createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
  return verifySignature(
    'sha256',
    recoveryProofMessage(verificationId, challenge),
    { key: publicKey, dsaEncoding: 'ieee-p1363' },
    signature,
  );
}
