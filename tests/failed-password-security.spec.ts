import type { PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';

import {
  assertLoginNotLocked,
  FAILED_PASSWORD_WIPE_THRESHOLD,
  registerUsernameLoginFailure,
  shouldWipeAfterFailedPassword,
} from '../src/auth/failed-password-security.js';

describe('failed password security wipe policy', () => {
  it('wipes exactly on the third consecutive eligible failure', () => {
    expect(FAILED_PASSWORD_WIPE_THRESHOLD).toBe(3);
    expect(shouldWipeAfterFailedPassword(0, true)).toBe(false);
    expect(shouldWipeAfterFailedPassword(1, true)).toBe(false);
    expect(shouldWipeAfterFailedPassword(2, true)).toBe(true);
    expect(shouldWipeAfterFailedPassword(3, true)).toBe(false);
    expect(shouldWipeAfterFailedPassword(9, true)).toBe(false);
  });

  it('does not let an untrusted username login trigger destructive cleanup', () => {
    expect(shouldWipeAfterFailedPassword(2, false)).toBe(false);
  });

  it('rejects access while locked and allows it after the deadline', () => {
    expect(() => { assertLoginNotLocked(new Date(Date.now() + 60_000)); })
      .toThrow(expect.objectContaining({ statusCode: 423, code: 'LOGIN_TEMPORARILY_LOCKED' }));
    expect(() => { assertLoginNotLocked(new Date(Date.now() - 1_000)); }).not.toThrow();
  });

  it('cleans conversation data and revokes sessions only when the failure starts a lock', async () => {
    const query = vi.fn().mockResolvedValue({ rows: [] });
    const client = { query } as unknown as PoolClient;

    query.mockResolvedValueOnce({ rows: [{ locked: false }] });
    await expect(registerUsernameLoginFailure(client, 'user-id', 'first-failure')).resolves.toBe(false);
    expect(query).toHaveBeenCalledTimes(2);

    query.mockClear();
    query.mockResolvedValueOnce({ rows: [{ locked: true }] });
    await expect(registerUsernameLoginFailure(client, 'user-id', 'third-failure')).resolves.toBe(true);
    const statements = query.mock.calls.map(([sql]: [string]) => sql).join('\n');
    expect(statements).toContain("INTERVAL '2 hours'");
    expect(statements).toMatch(/DELETE FROM .*\.messages WHERE sender_user_id = \$1/);
    expect(statements).toMatch(/DELETE FROM .*\.auth_sessions WHERE user_id = \$1/);
    expect(statements).not.toMatch(/DELETE FROM .*\.(users|devices|push_subscriptions|device_media_keys)\b/);
  });
});
