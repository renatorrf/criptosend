import { describe, expect, it } from 'vitest';

import { AppError } from '../src/http/app-error.js';
import {
  canCreateInvitation,
  normalizePlatformUsername,
} from '../src/auth/platform-access-service.js';

describe('platform access policy', () => {
  it('normalizes safe usernames consistently', () => {
    expect(normalizePlatformUsername('  Gestor.UM  ')).toBe('gestor.um');
    expect(normalizePlatformUsername('user_01')).toBe('user_01');
  });

  it('rejects usernames outside the public format', () => {
    for (const username of ['ab', '.admin', 'usuário', 'nome com espaço']) {
      expect(() => normalizePlatformUsername(username)).toThrow(AppError);
    }
  });

  it('enforces the invitation hierarchy', () => {
    expect(canCreateInvitation('PLATFORM_ADMIN', 'MANAGER')).toBe(true);
    expect(canCreateInvitation('PLATFORM_ADMIN', 'USER')).toBe(true);
    expect(canCreateInvitation('MANAGER', 'MANAGER')).toBe(false);
    expect(canCreateInvitation('MANAGER', 'USER')).toBe(true);
    expect(canCreateInvitation('USER', 'USER')).toBe(false);
  });
});
