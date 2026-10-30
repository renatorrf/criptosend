import { describe, expect, it } from 'vitest';

import { AppError } from '../src/http/app-error.js';
import {
  canCreateInvitation,
  managerPair,
  normalizePlatformUsername,
  requiresManagerRecoveryAfterFailures,
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

  it('normalizes manager links to a stable symmetric pair', () => {
    expect(managerPair('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')).toEqual([
      'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    ]);
  });

  it('requires the manager recovery token from the third failure onward', () => {
    expect(requiresManagerRecoveryAfterFailures('MANAGER', 1)).toBe(false);
    expect(requiresManagerRecoveryAfterFailures('MANAGER', 2)).toBe(false);
    expect(requiresManagerRecoveryAfterFailures('MANAGER', 3)).toBe(true);
    expect(requiresManagerRecoveryAfterFailures('MANAGER', 4)).toBe(true);
    expect(requiresManagerRecoveryAfterFailures('USER', 3)).toBe(false);
    expect(requiresManagerRecoveryAfterFailures('PLATFORM_ADMIN', 3)).toBe(false);
  });
});
