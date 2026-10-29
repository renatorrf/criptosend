import { describe, expect, it } from 'vitest';

import {
  FAILED_PASSWORD_WIPE_THRESHOLD,
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
});
