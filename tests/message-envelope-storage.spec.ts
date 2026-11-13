import { describe, expect, it } from 'vitest';

import { openMessageEnvelope, sealMessageEnvelope } from '../src/messages/message-envelope-storage.js';

describe('message envelope at rest', () => {
  it('protects both envelope and header and binds them to the stored message ID', () => {
    const ciphertext = Buffer.from('encrypted-payload-and-device-envelope');
    const header = Buffer.from('original-header');
    const sealed = sealMessageEnvelope('message-1', ciphertext, header);

    expect(sealed.includes(ciphertext)).toBe(false);
    expect(sealed.includes(header)).toBe(false);
    expect(sealMessageEnvelope('message-1', ciphertext, header)).not.toEqual(sealed);
    expect(openMessageEnvelope('message-1', sealed)).toEqual({ ciphertext, header });
    expect(() => openMessageEnvelope('message-2', sealed)).toThrow();
    sealed[sealed.length - 1] = (sealed[sealed.length - 1] ?? 0) ^ 1;
    expect(() => openMessageEnvelope('message-1', sealed)).toThrow();
  });

  it('preserves binary envelopes without a header', () => {
    const ciphertext = Buffer.from([0xff, 0x00, 0x87, 0xe3]);
    expect(openMessageEnvelope('message-1', sealMessageEnvelope('message-1', ciphertext, null)))
      .toEqual({ ciphertext, header: null });
  });
});
