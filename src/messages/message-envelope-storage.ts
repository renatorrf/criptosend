import { decryptFieldBytes, encryptFieldBytes } from '../security/field-crypto.js';

export function sealMessageEnvelope(id: string, ciphertext: Buffer, header: Buffer | null): Buffer {
  const size = Buffer.alloc(4);
  size.writeUInt32BE(header?.length ?? 0);
  return encryptFieldBytes(
    Buffer.concat([size, ...(header ? [header] : []), ciphertext]),
    `message-envelope-v1:${id}`,
  );
}

export function openMessageEnvelope(id: string, envelope: Buffer): {
  ciphertext: Buffer;
  header: Buffer | null;
} {
  const data = decryptFieldBytes(envelope, `message-envelope-v1:${id}`);
  const headerEnd = 4 + data.readUInt32BE();
  if (headerEnd >= data.length) throw new Error('Invalid stored message envelope');
  return {
    ciphertext: data.subarray(headerEnd),
    header: headerEnd > 4 ? data.subarray(4, headerEnd) : null,
  };
}
