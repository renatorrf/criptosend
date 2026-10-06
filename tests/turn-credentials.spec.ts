import { describe, expect, it } from 'vitest';

import { createTurnCredentials } from '../src/calls/turn-credentials.js';

describe('TURN REST credentials', () => {
  it('creates deterministic, expiring and user-scoped credentials', () => {
    const secret = 'a-private-turn-secret-with-more-than-32-characters';
    const first = createTurnCredentials('user-a', secret, 1_800_000_000);
    const repeated = createTurnCredentials('user-a', secret, 1_800_000_000);
    const otherUser = createTurnCredentials('user-b', secret, 1_800_000_000);

    expect(first).toEqual(repeated);
    expect(first.username).toMatch(/^1800000000:[A-Za-z0-9_-]{24}$/);
    expect(first.credential).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
    expect(otherUser).not.toEqual(first);
    expect(first.username).not.toContain('user-a');
  });
});
