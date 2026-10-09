import { describe, expect, it } from 'vitest';

import { subscriptionSchema } from './push-routes.js';

describe('push subscription payload', () => {
  it('normalizes Safari subscriptions that omit expirationTime', () => {
    expect(subscriptionSchema.parse({
      endpoint: 'https://web.push.apple.com/subscription-id',
      keys: {
        p256dh: 'p256dh-value-long-enough',
        auth: 'auth-value',
      },
    })).toEqual({
      endpoint: 'https://web.push.apple.com/subscription-id',
      expirationTime: null,
      keys: {
        p256dh: 'p256dh-value-long-enough',
        auth: 'auth-value',
      },
    });
  });
});
