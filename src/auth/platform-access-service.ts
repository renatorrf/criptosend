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
import type { DeviceInput } from './account-access-service.js';
import {
  assertLoginNotLocked,
  clearUserConversations,
  registerUsernameLoginFailure,
} from './failed-password-security.js';

const schema = quoteIdentifier(env.SCHEMA);
const ACCESS_RESET_TTL_SECONDS = 24 * 60 * 60;
const MANAGER_INVITATION_TTL_HOURS = 24;
const unassignedManagerInvitationPattern = /^cm_[A-Za-z0-9_-]{32}$/;
const accessResetTokenPattern = /^ar_([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})_[A-Za-z0-9_-]{43}$/;

export type PlatformRole = 'PLATFORM_ADMIN' | 'MANAGER' | 'USER';
export type ManagerLookupStatus =
  | 'NOT_FOUND'
  | 'SELF'
  | 'LINKED'
  | 'INCOMING_PENDING'
  | 'OUTGOING_PENDING'
  | 'AVAILABLE';

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
  locked_until: Date | null;
  role: PlatformRole;
  reset_required_at: Date | null;
}

interface ActorRow {
  id: string;
  role: PlatformRole;
  status: string;
}

export function normalizePlatformUsername(value: string): string {
  const username = value.trim().normalize('NFKC').replace(/^@/, '').toLowerCase();
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
    : actorRole === 'MANAGER';
}

export function managerPair(left: string, right: string): [string, string] {
  return left < right ? [left, right] : [right, left];
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
  outcome: 'SUCCESS' | 'FAILURE' = 'SUCCESS',
): Promise<void> {
  await client.query(
    `INSERT INTO ${schema}.security_events
       (id, user_id, device_id, event_type, outcome, request_id)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [randomUUID(), userId ?? null, deviceId ?? null, type, outcome, requestId],
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
        `SELECT u.id AS user_id, u.role, c.password_hash, c.locked_until,
                CASE WHEN c.reset_reason = 'MANAGER_REQUEST' THEN c.reset_required_at END
                  AS reset_required_at
         FROM ${schema}.users u
         JOIN ${schema}.user_credentials c ON c.user_id = u.id
         WHERE u.username = $1 AND u.status = 'ACTIVE'
         FOR UPDATE OF c`,
        [username],
      );
      const credential = result.rows[0];
      assertLoginNotLocked(credential?.locked_until);
      if (credential?.reset_required_at) {
        throw new AppError(
          403,
          credential.role === 'MANAGER'
            ? 'MANAGER_RECOVERY_TOKEN_REQUIRED'
            : 'CREDENTIAL_RESET_REQUIRED',
        );
      }
      const valid = await verifyPassword(credential?.password_hash, password);
      if (!credential || !valid) {
        if (credential) {
          const locked = await registerUsernameLoginFailure(client, credential.user_id, requestId);
          await client.query('COMMIT');
          committed = true;
          if (locked) throw new AppError(423, 'LOGIN_TEMPORARILY_LOCKED');
        }
        throw new AppError(401, 'INVALID_CREDENTIALS');
      }
      const deviceId = await resolveDevice(client, credential.user_id, device);
      await client.query(
        `UPDATE ${schema}.user_credentials
         SET failed_attempts = 0, locked_until = NULL,
             reset_required_at = NULL, reset_reason = NULL, reset_requested_by_user_id = NULL
         WHERE user_id = $1`,
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

  async verifyInvitation(code: string, usernameInput: string): Promise<void> {
    const username = normalizePlatformUsername(usernameInput);
    await this.findInvitation(databasePool, code, username);
  }

  async verifyAccessToken(code: string): Promise<
    { kind: 'INVITATION' | 'RESET' | 'ADMIN_SETUP' } | { kind: 'INVITATION'; chooseIdentity: true }
  > {
    const selector = accessResetTokenPattern.exec(code)?.[1];
    if (selector) {
      const result = await databasePool.query<{ token_hash: string; locked_until: Date | null; role: PlatformRole }>(
        `SELECT t.token_hash, c.locked_until, u.role
         FROM ${schema}.user_access_reset_tokens t
         JOIN ${schema}.users u ON u.id = t.user_id AND u.status = 'ACTIVE'
         JOIN ${schema}.user_credentials c ON c.user_id = u.id
         WHERE t.id = $1::uuid AND t.consumed_at IS NULL AND t.expires_at > NOW()
           AND c.reset_reason = 'MANAGER_REQUEST'
           AND (u.role <> 'PLATFORM_ADMIN' OR t.created_by_user_id = u.id)`,
        [selector],
      );
      const token = result.rows[0];
      if (!await verifyPassword(token?.token_hash, code)) {
        throw new AppError(400, 'INVALID_ACCESS_TOKEN');
      }
      assertLoginNotLocked(token?.locked_until);
      return { kind: token?.role === 'PLATFORM_ADMIN' ? 'ADMIN_SETUP' : 'RESET' };
    }
    try {
      const invite = await this.findInvitation(databasePool, code);
      if (invite.assigned_username === null) {
        return { kind: 'INVITATION', chooseIdentity: true };
      }
      return { kind: 'INVITATION' };
    } catch (error) {
      if (!(error instanceof AppError) || error.code !== 'INVALID_OR_EXPIRED_INVITATION') throw error;
      throw new AppError(400, 'INVALID_ACCESS_TOKEN');
    }
  }

  async redeemInvitation(
    code: string,
    usernameInput: string,
    password: string,
    device: DeviceInput,
    requestId: string,
  ): Promise<PlatformSession> {
    const username = normalizePlatformUsername(usernameInput);
    const client = await beginTransaction();
    try {
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)', [username]);
      const invite = await this.findInvitation(client, code, username, true);
      const existing = await client.query(
        `SELECT 1 FROM ${schema}.users WHERE username = $1
         UNION ALL
         SELECT 1 FROM ${schema}.invitation_codes
         WHERE $2::boolean AND assigned_username = $1 AND used_at IS NULL
           AND revoked_at IS NULL AND expires_at > clock_timestamp()`,
        [username, invite.assigned_username === null],
      );
      if (existing.rowCount !== 0) throw new AppError(409, 'USERNAME_ALREADY_EXISTS');

      const managerUserId = invite.role === 'USER' ? invite.created_by_user_id : null;
      if (managerUserId) {
        const existingNickname = await client.query(
          `SELECT 1
           FROM ${schema}.users
           WHERE COALESCE(manager_user_id, id) = $1
             AND nickname = $2`,
          [managerUserId, username],
        );
        if (existingNickname.rowCount !== 0) {
          throw new AppError(409, 'NICKNAME_ALREADY_EXISTS');
        }
      }

      const userId = randomUUID();
      await client.query(
        `INSERT INTO ${schema}.users
           (id, phone_encrypted, phone_lookup_hash, name_encrypted, username, nickname,
            role, manager_user_id, discoverable)
         VALUES ($1, NULL, NULL, $2, $3, $4, $5, $6, FALSE)`,
        [
          userId,
          encryptField(username, 'user-name'),
          username,
          username,
          invite.role,
          managerUserId,
        ],
      );
      if (invite.role === 'MANAGER') {
        await client.query(
          `INSERT INTO ${schema}.manager_invitation_balances (manager_user_id)
           VALUES ($1)
           ON CONFLICT (manager_user_id) DO NOTHING`,
          [userId],
        );
      } else if (invite.creator_role === 'MANAGER') {
        const balance = await client.query(
          `UPDATE ${schema}.manager_invitation_balances
           SET available_credits = available_credits - 1,
               consumed_credits = consumed_credits + 1
           WHERE manager_user_id = $1 AND available_credits > 0
           RETURNING manager_user_id`,
          [invite.created_by_user_id],
        );
        if (balance.rowCount !== 1) {
          throw new AppError(409, 'INVITATION_QUOTA_EXHAUSTED');
        }
      }
      await client.query(
        `INSERT INTO ${schema}.user_credentials (user_id, password_hash)
         VALUES ($1, $2)`,
        [userId, await hashPassword(password)],
      );
      const deviceId = await insertDevice(client, userId, device);
      const redeemed = await client.query(
        `UPDATE ${schema}.invitation_codes
         SET used_by_user_id = $2, used_at = clock_timestamp()
         WHERE id = $1 AND expires_at > clock_timestamp()`,
        [invite.id, userId],
      );
      if (redeemed.rowCount !== 1) throw new AppError(400, 'INVALID_OR_EXPIRED_INVITATION');
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
        const constraint = 'constraint' in error ? String(error.constraint) : '';
        throw new AppError(
          409,
          constraint === 'users_network_nickname_unique_idx'
            ? 'NICKNAME_ALREADY_EXISTS'
            : 'USERNAME_ALREADY_EXISTS',
        );
      }
      throw error;
    } finally {
      client.release();
    }
  }

  private async findInvitation(
    database: Pick<PoolClient, 'query'>,
    code: string,
    username?: string,
    lock = false,
  ) {
    const inviteResult = await database.query<{
      id: string;
      role: Exclude<PlatformRole, 'PLATFORM_ADMIN'>;
      assigned_username: string | null;
      created_by_user_id: string;
      creator_role: PlatformRole;
      creator_status: string;
      expired: boolean;
      used_at: Date | null;
      revoked_at: Date | null;
    }>(
      `SELECT i.id, i.role, i.assigned_username, i.created_by_user_id,
              i.expires_at <= clock_timestamp() AS expired,
              i.used_at, i.revoked_at, u.role AS creator_role,
              u.status AS creator_status
       FROM ${schema}.invitation_codes i
       JOIN ${schema}.users u ON u.id = i.created_by_user_id
       WHERE i.code_hash = $1
         AND (i.assigned_username IS NOT NULL OR i.allows_username_choice OR (i.role = 'MANAGER' AND $3))
         AND ($2::text IS NULL OR i.assigned_username = $2 OR i.assigned_username IS NULL)
       ${lock ? 'FOR UPDATE OF i' : ''}`,
      [hashRefreshToken(code.trim()), username ?? null, unassignedManagerInvitationPattern.test(code.trim())],
    );
    const invite = inviteResult.rows[0];
    const creatorCanInvite =
      invite?.creator_status === 'ACTIVE' &&
      canCreateInvitation(invite.creator_role, invite.role);
    if (
      !invite ||
      invite.used_at ||
      invite.revoked_at ||
      invite.expired ||
      !creatorCanInvite
    ) {
      throw new AppError(400, 'INVALID_OR_EXPIRED_INVITATION');
    }
    return invite;
  }

  async createInvitation(
    actor: AuthContext,
    role: Exclude<PlatformRole, 'PLATFORM_ADMIN'>,
    usernameInput: string | undefined,
    expiresInHours: number,
    requestId: string,
  ): Promise<{ id: string; code: string; username: string | null; expiresAt: Date; role: string }> {
    const actorRow = await this.actor(actor.userId);
    if (!canCreateInvitation(actorRow.role, role)) {
      throw new AppError(403, 'FORBIDDEN');
    }
    const username = usernameInput === undefined ? null : normalizePlatformUsername(usernameInput);
    const id = randomUUID();
    const code = `${username === null && role === 'MANAGER' ? 'cm' : 'cs'}_${randomBytes(24).toString('base64url')}`;
    const ttlHours = role === 'USER' ? MANAGER_INVITATION_TTL_HOURS : expiresInHours;
    const client = await beginTransaction();
    try {
      if (username !== null) {
        // Serialize username reservations and redemptions across networks.
        await client.query('SELECT pg_advisory_xact_lock(hashtext($1)::bigint)', [username]);
        const reservedUsername = await client.query(
          `SELECT 1 FROM ${schema}.users WHERE username = $1
           UNION ALL
           SELECT 1 FROM ${schema}.invitation_codes
           WHERE assigned_username = $1 AND used_at IS NULL
             AND revoked_at IS NULL AND expires_at > clock_timestamp()`,
          [username],
        );
        if (reservedUsername.rowCount) throw new AppError(409, 'USERNAME_ALREADY_EXISTS');
      }
      if (role === 'USER' && username !== null) {
        const existingNickname = await client.query(
          `SELECT 1 FROM ${schema}.users
           WHERE COALESCE(manager_user_id, id) = $1 AND nickname = $2`,
          [actor.userId, username],
        );
        if (existingNickname.rowCount) throw new AppError(409, 'NICKNAME_ALREADY_EXISTS');
      }

      if (actorRow.role === 'MANAGER' && role === 'USER') {
        const balance = await client.query<{ available_credits: number }>(
          `SELECT available_credits
           FROM ${schema}.manager_invitation_balances
           WHERE manager_user_id = $1
           FOR UPDATE`,
          [actor.userId],
        );
        const activeInvitations = await client.query<{ count: string }>(
          `SELECT COUNT(*)::TEXT AS count
           FROM ${schema}.invitation_codes
           WHERE created_by_user_id = $1
             AND role = 'USER'
             AND (assigned_username IS NOT NULL OR allows_username_choice)
             AND used_at IS NULL
             AND revoked_at IS NULL
             AND expires_at > clock_timestamp()`,
          [actor.userId],
        );
        const available = balance.rows[0]?.available_credits ?? 0;
        const reserved = Number(activeInvitations.rows[0]?.count ?? 0);
        if (reserved >= available) {
          throw new AppError(409, 'INVITATION_QUOTA_EXHAUSTED');
        }
      }
      const inserted = await client.query<{ expires_at: Date }>(
        `INSERT INTO ${schema}.invitation_codes
           (id, code_hash, role, created_by_user_id, expires_at, assigned_username, created_at, allows_username_choice)
         SELECT $1, $2, $3, $4, issued_at + $5 * INTERVAL '1 hour', $6, issued_at, $7
         FROM (SELECT clock_timestamp() AS issued_at) issuance
         RETURNING expires_at`,
        [id, hashRefreshToken(code), role, actor.userId, ttlHours, username, username === null],
      );
      const invitation = inserted.rows[0];
      if (!invitation) throw new Error('Invitation expiration was not returned.');
      await recordEvent(client, 'INVITATION_CREATED', requestId, actor.userId, actor.deviceId);
      await client.query('COMMIT');
      return { id, code, username, expiresAt: invitation.expires_at, role };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async listInvitations(actor: AuthContext): Promise<Array<Record<string, unknown>>> {
    const actorRow = await this.assertManagementRole(actor.userId);
    const result = await databasePool.query<{
      id: string;
      role: string;
      assigned_username: string | null;
      allows_username_choice: boolean;
      created_at: Date;
      expires_at: Date;
      used_at: Date | null;
      revoked_at: Date | null;
    }>(
      `SELECT i.id, i.role, COALESCE(i.assigned_username, u.username) AS assigned_username,
              i.created_at, i.expires_at, i.used_at, i.revoked_at, i.allows_username_choice
       FROM ${schema}.invitation_codes i
       LEFT JOIN ${schema}.users u ON u.id = i.used_by_user_id
       WHERE i.created_by_user_id = $1 AND i.role = $2
       ORDER BY i.created_at DESC LIMIT 100`,
      [actor.userId, actorRow.role === 'PLATFORM_ADMIN' ? 'MANAGER' : 'USER'],
    );
    return result.rows.map((invite) => ({
      id: invite.id,
      role: invite.role,
      username: invite.assigned_username,
      createdAt: invite.created_at,
      expiresAt: invite.expires_at,
      status: invite.revoked_at
        ? 'REVOKED'
        : invite.used_at
          ? 'USED'
          : (invite.role === 'USER' && !invite.assigned_username && !invite.allows_username_choice) || invite.expires_at.getTime() <= Date.now()
            ? 'EXPIRED'
            : 'ACTIVE',
    }));
  }

  async revokeInvitation(actor: AuthContext, invitationId: string): Promise<void> {
    const actorRow = await this.assertManagementRole(actor.userId);
    const result = await databasePool.query(
      `UPDATE ${schema}.invitation_codes
       SET revoked_at = NOW()
       WHERE id = $1 AND created_by_user_id = $2 AND role = $3
         AND used_at IS NULL AND revoked_at IS NULL`,
      [invitationId, actor.userId, actorRow.role === 'PLATFORM_ADMIN' ? 'MANAGER' : 'USER'],
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
      remaining_invitations: number | null;
      next_expiration_at: Date | null;
      reset_required_at: Date | null;
    }>(
      actorRow.role === 'PLATFORM_ADMIN'
        ? `SELECT u.id, u.username, u.name_encrypted, u.role, u.status,
                  c.reset_required_at,
                  GREATEST(0, COALESCE(b.available_credits, 0) - pending.count) AS remaining_invitations,
                  pending.next_expiration_at
           FROM ${schema}.users u
           JOIN ${schema}.user_credentials c ON c.user_id = u.id
           LEFT JOIN ${schema}.manager_invitation_balances b ON b.manager_user_id = u.id
           CROSS JOIN LATERAL (
             SELECT COUNT(*)::INTEGER AS count, MIN(i.expires_at) AS next_expiration_at
             FROM ${schema}.invitation_codes i
             WHERE i.created_by_user_id = u.id
               AND i.role = 'USER'
               AND (i.assigned_username IS NOT NULL OR i.allows_username_choice)
               AND i.used_at IS NULL
               AND i.revoked_at IS NULL
               AND i.expires_at > NOW()
           ) pending
           WHERE u.role = 'MANAGER' ORDER BY u.created_at DESC`
        : `SELECT u.id, u.username, u.name_encrypted, u.role, u.status,
                  c.reset_required_at,
                  NULL::INTEGER AS remaining_invitations,
                  NULL::TIMESTAMPTZ AS next_expiration_at
           FROM ${schema}.users u
           JOIN ${schema}.user_credentials c ON c.user_id = u.id
           WHERE u.manager_user_id = $1 AND u.role = 'USER' ORDER BY u.created_at DESC`,
      actorRow.role === 'PLATFORM_ADMIN' ? [] : [actor.userId],
    );
    return result.rows.map((user) => ({
      id: user.id,
      username: user.username,
      name: decryptField(user.name_encrypted, 'user-name'),
      role: user.role,
      status: user.status,
      resetRequired: user.reset_required_at !== null,
      ...(user.remaining_invitations !== null
        ? {
            remainingInvitations: user.remaining_invitations,
            nextExpirationAt: user.next_expiration_at,
          }
        : {}),
    }));
  }

  requestManagedUserAccessReset(
    actor: AuthContext,
    targetUserId: string,
    requestId: string,
  ): Promise<{ token: string; expiresAt: Date }> {
    return this.issueAccessReset(actor, targetUserId, 'USER', requestId);
  }

  rotateManagerRecoveryToken(
    actor: AuthContext,
    managerUserId: string,
    requestId: string,
  ): Promise<{ token: string; expiresAt: Date }> {
    return this.issueAccessReset(actor, managerUserId, 'MANAGER', requestId);
  }

  private async issueAccessReset(
    actor: AuthContext,
    targetUserId: string,
    targetRole: Exclude<PlatformRole, 'PLATFORM_ADMIN'>,
    requestId: string,
  ): Promise<{ token: string; expiresAt: Date }> {
    const actorRow = await this.actor(actor.userId);
    const requiredRole = targetRole === 'USER' ? 'MANAGER' : 'PLATFORM_ADMIN';
    if (actorRow.role !== requiredRole || targetUserId === actor.userId) {
      throw new AppError(403, 'FORBIDDEN');
    }
    const tokenId = randomUUID();
    const token = `ar_${tokenId}_${randomBytes(32).toString('base64url')}`;
    const tokenHash = await hashPassword(token);
    const expiresAt = new Date(Date.now() + ACCESS_RESET_TTL_SECONDS * 1_000);
    const client = await beginTransaction();
    try {
      const target = await client.query(
        `SELECT 1 FROM ${schema}.users u
         JOIN ${schema}.user_credentials c ON c.user_id = u.id
         WHERE u.id = $1 AND u.role = $2 AND u.status = 'ACTIVE'
           AND ($2 <> 'USER' OR u.manager_user_id = $3)
         FOR UPDATE OF c`,
        [targetUserId, targetRole, actor.userId],
      );
      if (target.rowCount !== 1) throw new AppError(404, 'USER_NOT_FOUND');

      await clearUserConversations(client, targetUserId, requestId, 'ACCESS_RESET_CONVERSATIONS_CLEARED');
      await client.query(
        `UPDATE ${schema}.user_credentials
         SET failed_attempts = 0,
             reset_required_at = NOW(),
             reset_reason = 'MANAGER_REQUEST',
             reset_requested_by_user_id = $2
         WHERE user_id = $1`,
        [targetUserId, actor.userId],
      );
      await client.query(
        `UPDATE ${schema}.user_access_reset_tokens
         SET consumed_at = NOW() WHERE user_id = $1 AND consumed_at IS NULL`,
        [targetUserId],
      );
      if (targetRole === 'MANAGER') {
        await client.query(
          `UPDATE ${schema}.manager_recovery_tokens
           SET consumed_at = NOW() WHERE manager_user_id = $1 AND consumed_at IS NULL`,
          [targetUserId],
        );
      }
      await client.query(
        `INSERT INTO ${schema}.user_access_reset_tokens
           (id, user_id, token_hash, created_by_user_id, expires_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [tokenId, targetUserId, tokenHash, actor.userId, expiresAt],
      );
      await recordEvent(client, 'ACCESS_RESET_REQUESTED', requestId, actor.userId, actor.deviceId);
      await client.query('COMMIT');
      return { token, expiresAt };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async completeCredentialReset(
    usernameInput: string,
    token: string,
    newPassword: string,
    device: DeviceInput,
    requestId: string,
  ): Promise<PlatformSession> {
    const username = normalizePlatformUsername(usernameInput);
    const client = await beginTransaction();
    let committed = false;
    try {
      const userResult = await client.query<{
        id: string;
        role: PlatformRole;
        reset_required_at: Date | null;
        locked_until: Date | null;
      }>(
        `SELECT u.id, u.role, c.reset_required_at, c.locked_until
         FROM ${schema}.users u
         JOIN ${schema}.user_credentials c ON c.user_id = u.id
         WHERE u.username = $1 AND u.status = 'ACTIVE'
         FOR UPDATE OF c`,
        [username],
      );
      const user = userResult.rows[0];
      assertLoginNotLocked(user?.locked_until);
      const selector = accessResetTokenPattern.exec(token)?.[1];
      const reset = user?.reset_required_at && (user.role !== 'PLATFORM_ADMIN' || selector)
        ? (await client.query<{ id: string; token_hash: string }>(
          `SELECT id, token_hash FROM ${schema}.user_access_reset_tokens
           WHERE user_id = $1 AND consumed_at IS NULL AND expires_at > NOW()
             AND ($2::uuid IS NULL OR id = $2)
             AND (NOT $3 OR created_by_user_id = user_id)
           FOR UPDATE`,
          [user.id, selector ?? null, user.role === 'PLATFORM_ADMIN'],
        )).rows[0] : undefined;
      const valid = await verifyPassword(reset?.token_hash, token.trim());
      if (!user || !reset || !valid) throw new AppError(401, 'INVALID_RESET_TOKEN');

      await client.query(
        `UPDATE ${schema}.user_credentials
         SET password_hash = $2,
             failed_attempts = 0,
             locked_until = NULL,
             reset_required_at = NULL,
             reset_reason = NULL,
             reset_requested_by_user_id = NULL
         WHERE user_id = $1`,
        [user.id, await hashPassword(newPassword)],
      );
      const deviceId = await resolveDevice(client, user.id, device);
      await client.query(
        `UPDATE ${schema}.user_access_reset_tokens SET consumed_at = NOW() WHERE id = $1`,
        [reset.id],
      );
      const session = await createSession(client, user.id, deviceId);
      await recordEvent(
        client,
        'CREDENTIAL_RESET_COMPLETED',
        requestId,
        user.id,
        deviceId,
      );
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

  async getInvitationBalance(actor: AuthContext): Promise<{
    availableCredits: number;
    consumedCredits: number;
    activeInvitations: number;
    nextExpirationAt: Date | null;
  }> {
    const actorRow = await this.actor(actor.userId);
    if (actorRow.role !== 'MANAGER') throw new AppError(403, 'FORBIDDEN');
    const result = await databasePool.query<{
      available_credits: number;
      consumed_credits: number;
      active_invitations: number;
      next_expiration_at: Date | null;
    }>(
      `SELECT b.available_credits, b.consumed_credits,
              COUNT(i.id)::INTEGER AS active_invitations, MIN(i.expires_at) AS next_expiration_at
       FROM ${schema}.manager_invitation_balances b
       LEFT JOIN ${schema}.invitation_codes i
         ON i.created_by_user_id = b.manager_user_id
        AND i.role = 'USER'
        AND (i.assigned_username IS NOT NULL OR i.allows_username_choice)
        AND i.used_at IS NULL
        AND i.revoked_at IS NULL
        AND i.expires_at > NOW()
       WHERE b.manager_user_id = $1
       GROUP BY b.available_credits, b.consumed_credits`,
      [actor.userId],
    );
    const balance = result.rows[0];
    if (!balance) throw new AppError(404, 'INVITATION_BALANCE_NOT_FOUND');
    return {
      availableCredits: balance.available_credits,
      consumedCredits: balance.consumed_credits,
      activeInvitations: balance.active_invitations,
      nextExpirationAt: balance.next_expiration_at,
    };
  }

  async grantInvitationCredits(
    actor: AuthContext,
    managerUserId: string,
    amount: number,
    requestId: string,
  ): Promise<{ availableCredits: number; consumedCredits: number }> {
    const actorRow = await this.actor(actor.userId);
    if (actorRow.role !== 'PLATFORM_ADMIN') throw new AppError(403, 'FORBIDDEN');
    const client = await beginTransaction();
    try {
      const manager = await client.query(
        `SELECT 1 FROM ${schema}.users
         WHERE id = $1 AND role = 'MANAGER'`,
        [managerUserId],
      );
      if (manager.rowCount !== 1) throw new AppError(404, 'MANAGER_NOT_FOUND');
      const grantId = randomUUID();
      await client.query(
        `INSERT INTO ${schema}.manager_invitation_grants
           (id, manager_user_id, granted_by_user_id, amount)
         VALUES ($1, $2, $3, $4)`,
        [grantId, managerUserId, actor.userId, amount],
      );
      const result = await client.query<{
        available_credits: number;
        consumed_credits: number;
      }>(
        `INSERT INTO ${schema}.manager_invitation_balances
           (manager_user_id, available_credits)
         VALUES ($1, $2)
         ON CONFLICT (manager_user_id) DO UPDATE
           SET available_credits = manager_invitation_balances.available_credits + EXCLUDED.available_credits
         RETURNING available_credits, consumed_credits`,
        [managerUserId, amount],
      );
      await recordEvent(
        client,
        'MANAGER_INVITATION_CREDITS_GRANTED',
        requestId,
        actor.userId,
        actor.deviceId,
      );
      const balance = result.rows[0];
      if (!balance) throw new Error('Invitation balance was not returned after grant.');
      await client.query('COMMIT');
      return {
        availableCredits: balance.available_credits,
        consumedCredits: balance.consumed_credits,
      };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async lookupManager(
    actor: AuthContext,
    usernameInput: string,
  ): Promise<{
    status: ManagerLookupStatus;
    manager?: { id: string; name: string; username: string; nickname: string };
  }> {
    const actorRow = await this.actor(actor.userId);
    if (actorRow.role !== 'MANAGER') throw new AppError(403, 'FORBIDDEN');
    const username = normalizePlatformUsername(usernameInput);
    const managerResult = await databasePool.query<{
      id: string;
      name_encrypted: Buffer;
      username: string;
      nickname: string;
    }>(
      `SELECT id, name_encrypted, username, nickname
       FROM ${schema}.users
       WHERE username = $1
         AND role = 'MANAGER'
         AND status = 'ACTIVE'
       LIMIT 1`,
      [username],
    );
    const manager = managerResult.rows[0];
    if (!manager) return { status: 'NOT_FOUND' };
    const summary = {
      id: manager.id,
      name: decryptField(manager.name_encrypted, 'user-name'),
      username: manager.username,
      nickname: manager.nickname,
    };
    if (manager.id === actor.userId) return { status: 'SELF', manager: summary };

    const [lowId, highId] = managerPair(actor.userId, manager.id);
    const linked = await databasePool.query(
      `SELECT 1 FROM ${schema}.manager_network_links
       WHERE manager_low_id = $1 AND manager_high_id = $2`,
      [lowId, highId],
    );
    if (linked.rowCount === 1) return { status: 'LINKED', manager: summary };

    const pending = await databasePool.query<{
      requester_manager_id: string;
    }>(
      `SELECT requester_manager_id
       FROM ${schema}.manager_network_requests
       WHERE LEAST(requester_manager_id, target_manager_id) = $1
         AND GREATEST(requester_manager_id, target_manager_id) = $2
         AND status = 'PENDING'
         AND expires_at > NOW()
       LIMIT 1`,
      [lowId, highId],
    );
    if (pending.rows[0]) {
      return {
        status:
          pending.rows[0].requester_manager_id === actor.userId
            ? 'OUTGOING_PENDING'
            : 'INCOMING_PENDING',
        manager: summary,
      };
    }
    return { status: 'AVAILABLE', manager: summary };
  }

  async createManagerNetworkRequest(
    actor: AuthContext,
    targetManagerId: string,
    requestId: string,
  ): Promise<{ id: string; expiresAt: Date }> {
    const actorRow = await this.actor(actor.userId);
    if (actorRow.role !== 'MANAGER' || targetManagerId === actor.userId) {
      throw new AppError(403, 'FORBIDDEN');
    }
    const [lowId, highId] = managerPair(actor.userId, targetManagerId);
    const client = await beginTransaction();
    try {
      const target = await client.query(
        `SELECT 1 FROM ${schema}.users
         WHERE id = $1 AND role = 'MANAGER' AND status = 'ACTIVE'`,
        [targetManagerId],
      );
      if (target.rowCount !== 1) throw new AppError(404, 'MANAGER_NOT_FOUND');
      const linked = await client.query(
        `SELECT 1 FROM ${schema}.manager_network_links
         WHERE manager_low_id = $1 AND manager_high_id = $2`,
        [lowId, highId],
      );
      if (linked.rowCount === 1) throw new AppError(409, 'MANAGERS_ALREADY_LINKED');
      await client.query(
        `UPDATE ${schema}.manager_network_requests
         SET status = 'CANCELLED', responded_at = NOW()
         WHERE LEAST(requester_manager_id, target_manager_id) = $1
           AND GREATEST(requester_manager_id, target_manager_id) = $2
           AND status = 'PENDING'
           AND expires_at <= NOW()`,
        [lowId, highId],
      );
      const id = randomUUID();
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1_000);
      await client.query(
        `INSERT INTO ${schema}.manager_network_requests
           (id, requester_manager_id, target_manager_id, expires_at)
         VALUES ($1, $2, $3, $4)`,
        [id, actor.userId, targetManagerId, expiresAt],
      );
      await recordEvent(client, 'MANAGER_NETWORK_REQUESTED', requestId, actor.userId, actor.deviceId);
      await client.query('COMMIT');
      return { id, expiresAt };
    } catch (error) {
      await client.query('ROLLBACK');
      if (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        error.code === '23505'
      ) {
        throw new AppError(409, 'NETWORK_REQUEST_ALREADY_EXISTS');
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async listManagerNetwork(actor: AuthContext): Promise<{
    links: Array<Record<string, unknown>>;
    requests: Array<Record<string, unknown>>;
  }> {
    const actorRow = await this.actor(actor.userId);
    if (actorRow.role !== 'MANAGER') throw new AppError(403, 'FORBIDDEN');
    const links = await databasePool.query<{
      id: string;
      name_encrypted: Buffer;
      username: string;
      created_at: Date;
    }>(
      `SELECT u.id, u.name_encrypted, u.username, l.created_at
       FROM ${schema}.manager_network_links l
       JOIN ${schema}.users u
         ON u.id = CASE
           WHEN l.manager_low_id = $1 THEN l.manager_high_id
           ELSE l.manager_low_id
         END
       WHERE l.manager_low_id = $1 OR l.manager_high_id = $1
       ORDER BY l.created_at DESC`,
      [actor.userId],
    );
    const requests = await databasePool.query<{
      id: string;
      requester_manager_id: string;
      target_manager_id: string;
      manager_id: string;
      name_encrypted: Buffer;
      username: string;
      created_at: Date;
      expires_at: Date;
    }>(
      `SELECT r.id, r.requester_manager_id, r.target_manager_id,
              u.id AS manager_id, u.name_encrypted, u.username,
              r.created_at, r.expires_at
       FROM ${schema}.manager_network_requests r
       JOIN ${schema}.users u
         ON u.id = CASE
           WHEN r.requester_manager_id = $1 THEN r.target_manager_id
           ELSE r.requester_manager_id
         END
       WHERE (r.requester_manager_id = $1 OR r.target_manager_id = $1)
         AND r.status = 'PENDING'
         AND r.expires_at > NOW()
       ORDER BY r.created_at DESC`,
      [actor.userId],
    );
    return {
      links: links.rows.map((link) => ({
        id: link.id,
        name: decryptField(link.name_encrypted, 'user-name'),
        username: link.username,
        createdAt: link.created_at,
      })),
      requests: requests.rows.map((request) => ({
        id: request.id,
        direction:
          request.requester_manager_id === actor.userId ? 'OUTGOING' : 'INCOMING',
        manager: {
          id: request.manager_id,
          name: decryptField(request.name_encrypted, 'user-name'),
          username: request.username,
        },
        createdAt: request.created_at,
        expiresAt: request.expires_at,
      })),
    };
  }

  async respondManagerNetworkRequest(
    actor: AuthContext,
    networkRequestId: string,
    decision: 'ACCEPT' | 'DECLINE',
    requestId: string,
  ): Promise<void> {
    const actorRow = await this.actor(actor.userId);
    if (actorRow.role !== 'MANAGER') throw new AppError(403, 'FORBIDDEN');
    const client = await beginTransaction();
    try {
      const result = await client.query<{
        requester_manager_id: string;
        target_manager_id: string;
        expires_at: Date;
      }>(
        `SELECT requester_manager_id, target_manager_id, expires_at
         FROM ${schema}.manager_network_requests
         WHERE id = $1 AND target_manager_id = $2 AND status = 'PENDING'
         FOR UPDATE`,
        [networkRequestId, actor.userId],
      );
      const networkRequest = result.rows[0];
      if (!networkRequest || networkRequest.expires_at.getTime() <= Date.now()) {
        throw new AppError(404, 'NETWORK_REQUEST_NOT_FOUND');
      }
      const status = decision === 'ACCEPT' ? 'ACCEPTED' : 'DECLINED';
      if (decision === 'ACCEPT') {
        const [lowId, highId] = managerPair(
          networkRequest.requester_manager_id,
          networkRequest.target_manager_id,
        );
        await client.query(
          `INSERT INTO ${schema}.manager_network_links
             (manager_low_id, manager_high_id, created_by_user_id)
           VALUES ($1, $2, $3)
           ON CONFLICT (manager_low_id, manager_high_id) DO NOTHING`,
          [lowId, highId, actor.userId],
        );
      }
      await client.query(
        `UPDATE ${schema}.manager_network_requests
         SET status = $2, responded_at = NOW()
         WHERE id = $1`,
        [networkRequestId, status],
      );
      await recordEvent(
        client,
        decision === 'ACCEPT'
          ? 'MANAGER_NETWORK_REQUEST_ACCEPTED'
          : 'MANAGER_NETWORK_REQUEST_DECLINED',
        requestId,
        actor.userId,
        actor.deviceId,
      );
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async setManagedUserStatus(
    actor: AuthContext,
    targetUserId: string,
    status: 'ACTIVE' | 'SUSPENDED',
  ): Promise<void> {
    if (targetUserId === actor.userId) throw new AppError(403, 'FORBIDDEN');
    const actorRow = await this.actor(actor.userId);
    if (actorRow.role !== 'MANAGER') throw new AppError(403, 'FORBIDDEN');
    const client = await beginTransaction();
    try {
      const result = await client.query(
        `UPDATE ${schema}.users SET status = $2
         WHERE id = $1 AND role = 'USER' AND manager_user_id = $3`,
        [targetUserId, status, actor.userId],
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
      const result = await client.query<{ password_hash: string; locked_until: Date | null }>(
        `SELECT c.password_hash, c.locked_until
         FROM ${schema}.user_credentials c
         JOIN ${schema}.users u ON u.id = c.user_id AND u.status = 'ACTIVE'
         WHERE c.user_id = $1
         FOR UPDATE OF c`,
        [actor.userId],
      );
      assertLoginNotLocked(result.rows[0]?.locked_until);
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
