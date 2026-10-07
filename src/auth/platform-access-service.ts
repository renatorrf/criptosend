import { randomBytes, randomUUID } from 'node:crypto';

import type { PoolClient } from 'pg';

import { env } from '../config/env.js';
import { databasePool } from '../database/pool.js';
import { quoteIdentifier } from '../database/identifier.js';
import { normalizePhone } from '../identity/phone.js';
import { AppError } from '../http/app-error.js';
import { decryptField, encryptField } from '../security/field-crypto.js';
import { createPhoneLookupHash, hashRefreshToken } from '../security/hashes.js';
import { hashPassword, verifyPassword } from '../security/pin.js';
import {
  createAccessToken,
  createRefreshToken,
  type AuthContext,
} from './tokens.js';
import type {
  DeviceInput,
  RecoveryCredentialInput,
} from './account-access-service.js';

const schema = quoteIdentifier(env.SCHEMA);

export type PlatformRole = 'PLATFORM_ADMIN' | 'MANAGER' | 'USER';

export interface PlatformSession {
  userId: string;
  deviceId: string;
  accessToken: string;
  refreshToken: string;
  accessExpiresInSeconds: number;
}

interface CredentialRow {
  user_id: string;
  password_hash: string;
  failed_attempts: number;
  locked_until: Date | null;
}

interface ActorRow {
  id: string;
  role: PlatformRole;
  status: string;
}

export function normalizePlatformUsername(value: string): string {
  const username = value.trim().normalize('NFKC').toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{2,39}$/.test(username)) {
    throw new AppError(400, 'INVALID_USERNAME');
  }
  return username;
}

export function canCreateInvitation(
  actorRole: PlatformRole,
  targetRole: Exclude<PlatformRole, 'PLATFORM_ADMIN'>,
): boolean {
  return targetRole === 'MANAGER'
    ? actorRole === 'PLATFORM_ADMIN'
    : actorRole === 'PLATFORM_ADMIN' || actorRole === 'MANAGER';
}

async function beginTransaction(): Promise<PoolClient> {
  const client = await databasePool.connect();
  await client.query('BEGIN');
  return client;
}

async function insertDevice(
  client: PoolClient,
  userId: string,
  input: DeviceInput,
): Promise<string> {
  if (!input.deviceName || !input.identityPublicKey || input.registrationId === undefined) {
    throw new AppError(400, 'DEVICE_REGISTRATION_REQUIRED');
  }
  const deviceId = randomUUID();
  await client.query(
    `INSERT INTO ${schema}.devices
       (id, user_id, device_name_encrypted, identity_public_key, registration_id)
     VALUES ($1, $2, $3, $4, $5)`,
    [
      deviceId,
      userId,
      encryptField(input.deviceName.trim(), 'device-name'),
      input.identityPublicKey,
      input.registrationId,
    ],
  );
  return deviceId;
}

async function resolveDevice(
  client: PoolClient,
  userId: string,
  input: DeviceInput,
): Promise<string> {
  if (input.deviceId) {
    const existing = await client.query(
      `SELECT 1 FROM ${schema}.devices
       WHERE id = $1 AND user_id = $2 AND status = 'ACTIVE'`,
      [input.deviceId, userId],
    );
    if (existing.rowCount === 1) return input.deviceId;
  }
  return insertDevice(client, userId, input);
}

async function upsertRecovery(
  client: PoolClient,
  userId: string,
  recovery: RecoveryCredentialInput,
): Promise<void> {
  await client.query(
    `INSERT INTO ${schema}.account_recovery_credentials
       (user_id, key_id, public_key, wrapped_private_key, wrapping_iv,
        kdf_salt, kdf_parameters)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (user_id) DO UPDATE SET
       key_id = EXCLUDED.key_id,
       public_key = EXCLUDED.public_key,
       wrapped_private_key = EXCLUDED.wrapped_private_key,
       wrapping_iv = EXCLUDED.wrapping_iv,
       kdf_salt = EXCLUDED.kdf_salt,
       kdf_parameters = EXCLUDED.kdf_parameters`,
    [
      userId,
      recovery.keyId,
      recovery.publicKey,
      recovery.wrappedPrivateKey,
      recovery.wrappingIv,
      recovery.kdfSalt,
      JSON.stringify(recovery.kdfParameters),
    ],
  );
}

async function createSession(
  client: PoolClient,
  userId: string,
  deviceId: string,
): Promise<PlatformSession> {
  const sessionId = randomUUID();
  const refreshToken = createRefreshToken();
  await client.query(
    `INSERT INTO ${schema}.auth_sessions
       (id, user_id, device_id, refresh_token_hash, expires_at, session_family_id)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      sessionId,
      userId,
      deviceId,
      hashRefreshToken(refreshToken),
      new Date(Date.now() + env.AUTH_REFRESH_TTL_SECONDS * 1_000),
      randomUUID(),
    ],
  );
  return {
    userId,
    deviceId,
    accessToken: await createAccessToken({ userId, deviceId, sessionId }),
    refreshToken,
    accessExpiresInSeconds: env.AUTH_ACCESS_TTL_SECONDS,
  };
}

async function recordEvent(
  client: PoolClient,
  type: string,
  requestId: string,
  userId?: string,
  deviceId?: string,
): Promise<void> {
  await client.query(
    `INSERT INTO ${schema}.security_events
       (id, user_id, device_id, event_type, outcome, request_id)
     VALUES ($1, $2, $3, $4, 'SUCCESS', $5)`,
    [randomUUID(), userId ?? null, deviceId ?? null, type, requestId],
  );
}

export class PlatformAccessService {
  async login(
    usernameInput: string,
    password: string,
    device: DeviceInput,
    requestId: string,
  ): Promise<PlatformSession> {
    const username = normalizePlatformUsername(usernameInput);
    const client = await beginTransaction();
    let committed = false;
    try {
      const result = await client.query<CredentialRow>(
        `SELECT u.id AS user_id, c.password_hash, c.failed_attempts, c.locked_until
         FROM ${schema}.users u
         JOIN ${schema}.user_credentials c ON c.user_id = u.id
         WHERE u.username = $1 AND u.status = 'ACTIVE'
         FOR UPDATE OF c`,
        [username],
      );
      const credential = result.rows[0];
      const valid = await verifyPassword(credential?.password_hash, password);
      const locked = credential?.locked_until && credential.locked_until.getTime() > Date.now();
      if (!credential || !valid || locked) {
        if (credential) {
          await client.query(
            `UPDATE ${schema}.user_credentials
             SET failed_attempts = failed_attempts + 1,
                 locked_until = CASE WHEN failed_attempts + 1 >= 5
                   THEN NOW() + INTERVAL '15 minutes' ELSE locked_until END
             WHERE user_id = $1`,
            [credential.user_id],
          );
          await client.query('COMMIT');
          committed = true;
        }
        throw new AppError(401, 'INVALID_CREDENTIALS');
      }
      const deviceId = await resolveDevice(client, credential.user_id, device);
      await client.query(
        `UPDATE ${schema}.user_credentials
         SET failed_attempts = 0, locked_until = NULL WHERE user_id = $1`,
        [credential.user_id],
      );
      const session = await createSession(client, credential.user_id, deviceId);
      await recordEvent(client, 'USERNAME_LOGIN', requestId, credential.user_id, deviceId);
      await client.query('COMMIT');
      committed = true;
      return session;
    } catch (error) {
      if (!committed) await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async redeemInvitation(
    code: string,
    name: string,
    usernameInput: string,
    password: string,
    device: DeviceInput,
    recovery: RecoveryCredentialInput,
    requestId: string,
  ): Promise<PlatformSession> {
    const username = normalizePlatformUsername(usernameInput);
    const client = await beginTransaction();
    try {
      const inviteResult = await client.query<{
        id: string;
        role: Exclude<PlatformRole, 'PLATFORM_ADMIN'>;
        created_by_user_id: string;
        creator_role: PlatformRole;
        creator_status: string;
        expires_at: Date;
        used_at: Date | null;
        revoked_at: Date | null;
      }>(
        `SELECT i.id, i.role, i.created_by_user_id, i.expires_at,
                i.used_at, i.revoked_at, u.role AS creator_role,
                u.status AS creator_status
         FROM ${schema}.invitation_codes i
         JOIN ${schema}.users u ON u.id = i.created_by_user_id
         WHERE i.code_hash = $1
         FOR UPDATE OF i`,
        [hashRefreshToken(code.trim())],
      );
      const invite = inviteResult.rows[0];
      const creatorCanInvite =
        invite?.creator_status === 'ACTIVE' &&
        ((invite.role === 'MANAGER' && invite.creator_role === 'PLATFORM_ADMIN') ||
          (invite.role === 'USER' &&
            (invite.creator_role === 'PLATFORM_ADMIN' || invite.creator_role === 'MANAGER')));
      if (
        !invite ||
        invite.used_at ||
        invite.revoked_at ||
        invite.expires_at.getTime() <= Date.now() ||
        !creatorCanInvite
      ) {
        throw new AppError(400, 'INVALID_OR_EXPIRED_INVITATION');
      }
      const existing = await client.query(
        `SELECT 1 FROM ${schema}.users WHERE username = $1`,
        [username],
      );
      if (existing.rowCount !== 0) throw new AppError(409, 'USERNAME_ALREADY_EXISTS');

      const userId = randomUUID();
      await client.query(
        `INSERT INTO ${schema}.users
           (id, phone_encrypted, phone_lookup_hash, name_encrypted, username,
            role, manager_user_id, discoverable)
         VALUES ($1, NULL, NULL, $2, $3, $4, $5, FALSE)`,
        [
          userId,
          encryptField(name.trim(), 'user-name'),
          username,
          invite.role,
          invite.role === 'USER' && invite.creator_role === 'MANAGER'
            ? invite.created_by_user_id
            : null,
        ],
      );
      await client.query(
        `INSERT INTO ${schema}.user_credentials (user_id, password_hash)
         VALUES ($1, $2)`,
        [userId, await hashPassword(password)],
      );
      const deviceId = await insertDevice(client, userId, device);
      await upsertRecovery(client, userId, recovery);
      await client.query(
        `UPDATE ${schema}.invitation_codes
         SET used_by_user_id = $2, used_at = NOW() WHERE id = $1`,
        [invite.id, userId],
      );
      const session = await createSession(client, userId, deviceId);
      await recordEvent(client, 'INVITATION_REDEEMED', requestId, userId, deviceId);
      await client.query('COMMIT');
      return session;
    } catch (error) {
      await client.query('ROLLBACK');
      if (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        error.code === '23505'
      ) {
        throw new AppError(409, 'USERNAME_ALREADY_EXISTS');
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async createInvitation(
    actor: AuthContext,
    role: Exclude<PlatformRole, 'PLATFORM_ADMIN'>,
    expiresInHours: number,
    requestId: string,
  ): Promise<{ id: string; code: string; expiresAt: Date; role: string }> {
    const actorRow = await this.actor(actor.userId);
    if (!canCreateInvitation(actorRow.role, role)) {
      throw new AppError(403, 'FORBIDDEN');
    }
    const id = randomUUID();
    const code = `cs_${randomBytes(24).toString('base64url')}`;
    const expiresAt = new Date(Date.now() + expiresInHours * 60 * 60 * 1_000);
    const client = await beginTransaction();
    try {
      await client.query(
        `INSERT INTO ${schema}.invitation_codes
           (id, code_hash, role, created_by_user_id, expires_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [id, hashRefreshToken(code), role, actor.userId, expiresAt],
      );
      await recordEvent(client, 'INVITATION_CREATED', requestId, actor.userId, actor.deviceId);
      await client.query('COMMIT');
      return { id, code, expiresAt, role };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async listInvitations(actor: AuthContext): Promise<Array<Record<string, unknown>>> {
    await this.assertManagementRole(actor.userId);
    const result = await databasePool.query<{
      id: string;
      role: string;
      created_at: Date;
      expires_at: Date;
      used_at: Date | null;
      revoked_at: Date | null;
    }>(
      `SELECT id, role, created_at, expires_at, used_at, revoked_at
       FROM ${schema}.invitation_codes
       WHERE created_by_user_id = $1
       ORDER BY created_at DESC LIMIT 100`,
      [actor.userId],
    );
    return result.rows.map((invite) => ({
      id: invite.id,
      role: invite.role,
      createdAt: invite.created_at,
      expiresAt: invite.expires_at,
      status: invite.revoked_at
        ? 'REVOKED'
        : invite.used_at
          ? 'USED'
          : invite.expires_at.getTime() <= Date.now()
            ? 'EXPIRED'
            : 'ACTIVE',
    }));
  }

  async revokeInvitation(actor: AuthContext, invitationId: string): Promise<void> {
    await this.assertManagementRole(actor.userId);
    const result = await databasePool.query(
      `UPDATE ${schema}.invitation_codes
       SET revoked_at = NOW()
       WHERE id = $1 AND created_by_user_id = $2
         AND used_at IS NULL AND revoked_at IS NULL`,
      [invitationId, actor.userId],
    );
    if (result.rowCount !== 1) throw new AppError(404, 'INVITATION_NOT_FOUND');
  }

  async listManagedUsers(actor: AuthContext): Promise<Array<Record<string, unknown>>> {
    const actorRow = await this.assertManagementRole(actor.userId);
    const result = await databasePool.query<{
      id: string;
      username: string;
      name_encrypted: Buffer;
      role: PlatformRole;
      status: string;
      phone_encrypted: Buffer | null;
      created_at: Date;
    }>(
      actorRow.role === 'PLATFORM_ADMIN'
        ? `SELECT id, username, name_encrypted, role, status, phone_encrypted, created_at
           FROM ${schema}.users WHERE role = 'MANAGER' ORDER BY created_at DESC`
        : `SELECT id, username, name_encrypted, role, status, phone_encrypted, created_at
           FROM ${schema}.users WHERE manager_user_id = $1 ORDER BY created_at DESC`,
      actorRow.role === 'PLATFORM_ADMIN' ? [] : [actor.userId],
    );
    return result.rows.map((user) => ({
      id: user.id,
      username: user.username,
      name: decryptField(user.name_encrypted, 'user-name'),
      role: user.role,
      status: user.status,
      hasPhone: user.phone_encrypted !== null,
      createdAt: user.created_at,
    }));
  }

  async setManagedUserStatus(
    actor: AuthContext,
    targetUserId: string,
    status: 'ACTIVE' | 'SUSPENDED',
  ): Promise<void> {
    if (targetUserId === actor.userId) throw new AppError(403, 'FORBIDDEN');
    const actorRow = await this.assertManagementRole(actor.userId);
    const client = await beginTransaction();
    try {
      const result = await client.query(
        actorRow.role === 'PLATFORM_ADMIN'
          ? `UPDATE ${schema}.users SET status = $2
             WHERE id = $1 AND role = 'MANAGER'`
          : `UPDATE ${schema}.users SET status = $2
             WHERE id = $1 AND role = 'USER' AND manager_user_id = $3`,
        actorRow.role === 'PLATFORM_ADMIN'
          ? [targetUserId, status]
          : [targetUserId, status, actor.userId],
      );
      if (result.rowCount !== 1) throw new AppError(404, 'USER_NOT_FOUND');
      if (status === 'SUSPENDED') {
        await client.query(
          `UPDATE ${schema}.auth_sessions SET revoked_at = COALESCE(revoked_at, NOW())
           WHERE user_id = $1`,
          [targetUserId],
        );
        await client.query(
          `UPDATE ${schema}.devices
           SET status = 'REVOKED', revoked_at = COALESCE(revoked_at, NOW())
           WHERE user_id = $1 AND status = 'ACTIVE'`,
          [targetUserId],
        );
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async updatePhone(
    actor: AuthContext,
    phoneInput: string | null,
    requestId: string,
  ): Promise<{ phone: string | null; discoverable: boolean }> {
    const phone = phoneInput?.trim() ? normalizePhone(phoneInput) : null;
    const client = await beginTransaction();
    try {
      await client.query(
        `UPDATE ${schema}.users
         SET phone_encrypted = $2,
             phone_lookup_hash = $3,
             phone_updated_at = NOW(),
             discoverable = $4
         WHERE id = $1 AND status = 'ACTIVE'`,
        [
          actor.userId,
          phone ? encryptField(phone, 'phone') : null,
          phone ? createPhoneLookupHash(phone) : null,
          Boolean(phone),
        ],
      );
      await recordEvent(client, 'PHONE_UPDATED', requestId, actor.userId, actor.deviceId);
      await client.query('COMMIT');
      return { phone, discoverable: Boolean(phone) };
    } catch (error) {
      await client.query('ROLLBACK');
      if (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        error.code === '23505'
      ) {
        throw new AppError(409, 'PHONE_ALREADY_IN_USE');
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async changePassword(
    actor: AuthContext,
    currentPassword: string,
    newPassword: string,
    requestId: string,
  ): Promise<void> {
    const client = await beginTransaction();
    try {
      const result = await client.query<{ password_hash: string }>(
        `SELECT c.password_hash
         FROM ${schema}.user_credentials c
         JOIN ${schema}.users u ON u.id = c.user_id AND u.status = 'ACTIVE'
         WHERE c.user_id = $1
         FOR UPDATE OF c`,
        [actor.userId],
      );
      const valid = await verifyPassword(result.rows[0]?.password_hash, currentPassword);
      if (!valid) throw new AppError(401, 'INVALID_CREDENTIALS');
      await client.query(
        `UPDATE ${schema}.user_credentials
         SET password_hash = $2, failed_attempts = 0, locked_until = NULL
         WHERE user_id = $1`,
        [actor.userId, await hashPassword(newPassword)],
      );
      await client.query(
        `UPDATE ${schema}.auth_sessions
         SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE user_id = $1 AND id <> $2`,
        [actor.userId, actor.sessionId],
      );
      await recordEvent(client, 'PASSWORD_CHANGED', requestId, actor.userId, actor.deviceId);
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  private async actor(userId: string): Promise<ActorRow> {
    const result = await databasePool.query<ActorRow>(
      `SELECT id, role, status FROM ${schema}.users WHERE id = $1`,
      [userId],
    );
    const actor = result.rows[0];
    if (!actor || actor.status !== 'ACTIVE') throw new AppError(403, 'FORBIDDEN');
    return actor;
  }

  private async assertManagementRole(userId: string): Promise<ActorRow> {
    const actor = await this.actor(userId);
    if (!['PLATFORM_ADMIN', 'MANAGER'].includes(actor.role)) {
      throw new AppError(403, 'FORBIDDEN');
    }
    return actor;
  }
}
