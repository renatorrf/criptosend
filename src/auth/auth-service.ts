import { randomInt, randomUUID } from 'node:crypto';

import type { PoolClient } from 'pg';

import { env } from '../config/env.js';
import { databasePool } from '../database/pool.js';
import { quoteIdentifier } from '../database/identifier.js';
import { normalizePhone } from '../identity/phone.js';
import { AppError } from '../http/app-error.js';
import { decryptField, encryptField } from '../security/field-crypto.js';
import {
  constantTimeHexEqual,
  createPhoneLookupHash,
  createVerificationCodeHash,
  hashRefreshToken,
} from '../security/hashes.js';
import { hashPin, verifyPin } from '../security/pin.js';
import {
  createAccessToken,
  createRefreshToken,
  type AuthContext,
  verifyAccessToken,
} from './tokens.js';
import type { VerificationProvider } from './verification-provider.js';

const schema = quoteIdentifier(env.SCHEMA);

interface ChallengeRow {
  phone_encrypted: Buffer;
  phone_lookup_hash: string;
  code_lookup_hash: string;
  attempts: number;
  max_attempts: number;
  expires_at: Date;
  consumed_at: Date | null;
}

interface LoginRow {
  user_id: string;
  password_hash: string;
  failed_attempts: number;
  locked_until: Date | null;
}

interface SessionRow {
  id: string;
  user_id: string;
  device_id: string;
  session_family_id: string | null;
  expires_at: Date;
  revoked_at: Date | null;
  replaced_by_id: string | null;
}

interface UserRow {
  id: string;
  name_encrypted: Buffer;
  phone_encrypted: Buffer;
  discoverable: boolean;
  read_receipts_enabled: boolean;
  typing_indicators_enabled: boolean;
  created_at: Date;
}

export interface SessionTokens {
  accessToken: string;
  refreshToken: string;
  accessExpiresInSeconds: number;
  refreshExpiresInSeconds: number;
}

export interface VerifyRegistrationInput {
  verificationId: string;
  code: string;
  name: string;
  pin: string;
  deviceName: string;
  identityPublicKey: Buffer;
  registrationId: number;
}

async function beginTransaction(): Promise<PoolClient> {
  const client = await databasePool.connect();
  await client.query('BEGIN');
  return client;
}

async function insertSession(
  client: PoolClient,
  userId: string,
  deviceId: string,
  familyId: string = randomUUID(),
  rotatedFromId?: string,
): Promise<SessionTokens> {
  const sessionId = randomUUID();
  const refreshToken = createRefreshToken();
  const expiresAt = new Date(Date.now() + env.AUTH_REFRESH_TTL_SECONDS * 1_000);

  await client.query(
    `INSERT INTO ${schema}.auth_sessions
       (id, user_id, device_id, refresh_token_hash, expires_at,
        session_family_id, rotated_from_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [
      sessionId,
      userId,
      deviceId,
      hashRefreshToken(refreshToken),
      expiresAt,
      familyId,
      rotatedFromId ?? null,
    ],
  );

  return {
    accessToken: await createAccessToken({ userId, deviceId, sessionId }),
    refreshToken,
    accessExpiresInSeconds: env.AUTH_ACCESS_TTL_SECONDS,
    refreshExpiresInSeconds: env.AUTH_REFRESH_TTL_SECONDS,
  };
}

async function recordSecurityEvent(
  client: PoolClient,
  eventType: string,
  outcome: 'SUCCESS' | 'FAILURE' | 'BLOCKED',
  requestId: string,
  userId?: string,
  deviceId?: string,
): Promise<void> {
  await client.query(
    `INSERT INTO ${schema}.security_events
       (id, user_id, device_id, event_type, outcome, request_id)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [randomUUID(), userId ?? null, deviceId ?? null, eventType, outcome, requestId],
  );
}

export class AuthService {
  constructor(private readonly verificationProvider: VerificationProvider) {}

  async startRegistration(phoneInput: string): Promise<{
    verificationId: string;
    expiresInSeconds: number;
  }> {
    const phone = normalizePhone(phoneInput);
    const verificationId = randomUUID();
    const code = randomInt(0, 1_000_000).toString().padStart(6, '0');
    const expiresAt = new Date(Date.now() + env.VERIFICATION_TTL_SECONDS * 1_000);

    await databasePool.query(
      `INSERT INTO ${schema}.phone_verification_challenges
         (id, phone_encrypted, phone_lookup_hash, code_lookup_hash, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        verificationId,
        encryptField(phone, 'phone'),
        createPhoneLookupHash(phone),
        createVerificationCodeHash(verificationId, code),
        expiresAt,
      ],
    );

    try {
      await this.verificationProvider.sendCode(phone, code);
    } catch (error) {
      await databasePool.query(
        `UPDATE ${schema}.phone_verification_challenges
         SET consumed_at = NOW()
         WHERE id = $1`,
        [verificationId],
      );
      throw error;
    }

    return {
      verificationId,
      expiresInSeconds: env.VERIFICATION_TTL_SECONDS,
    };
  }

  async verifyRegistration(
    input: VerifyRegistrationInput,
    requestId: string,
  ): Promise<SessionTokens> {
    const client = await beginTransaction();
    let transactionFinished = false;

    try {
      const challengeResult = await client.query<ChallengeRow>(
        `SELECT phone_encrypted, phone_lookup_hash, code_lookup_hash,
                attempts, max_attempts, expires_at, consumed_at
         FROM ${schema}.phone_verification_challenges
         WHERE id = $1
         FOR UPDATE`,
        [input.verificationId],
      );
      const challenge = challengeResult.rows[0];

      if (
        !challenge ||
        challenge.consumed_at ||
        challenge.expires_at.getTime() <= Date.now() ||
        challenge.attempts >= challenge.max_attempts
      ) {
        throw new AppError(400, 'INVALID_OR_EXPIRED_VERIFICATION');
      }

      const suppliedCodeHash = createVerificationCodeHash(
        input.verificationId,
        input.code,
      );
      if (!constantTimeHexEqual(challenge.code_lookup_hash, suppliedCodeHash)) {
        await client.query(
          `UPDATE ${schema}.phone_verification_challenges
           SET attempts = attempts + 1
           WHERE id = $1`,
          [input.verificationId],
        );
        await recordSecurityEvent(client, 'PHONE_VERIFICATION', 'FAILURE', requestId);
        await client.query('COMMIT');
        transactionFinished = true;
        throw new AppError(400, 'INVALID_OR_EXPIRED_VERIFICATION');
      }

      const existing = await client.query(
        `SELECT 1 FROM ${schema}.users WHERE phone_lookup_hash = $1`,
        [challenge.phone_lookup_hash],
      );
      if (existing.rowCount !== 0) {
        throw new AppError(409, 'ACCOUNT_ALREADY_EXISTS');
      }

      const userId = randomUUID();
      const deviceId = randomUUID();
      const phone = decryptField(challenge.phone_encrypted, 'phone');
      const pinHash = await hashPin(input.pin);

      await client.query(
        `INSERT INTO ${schema}.users
           (id, phone_encrypted, phone_lookup_hash, name_encrypted)
         VALUES ($1, $2, $3, $4)`,
        [
          userId,
          encryptField(phone, 'phone'),
          challenge.phone_lookup_hash,
          encryptField(input.name.trim(), 'user-name'),
        ],
      );
      await client.query(
        `INSERT INTO ${schema}.user_credentials (user_id, password_hash)
         VALUES ($1, $2)`,
        [userId, pinHash],
      );
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
      await client.query(
        `UPDATE ${schema}.phone_verification_challenges
         SET consumed_at = NOW()
         WHERE id = $1`,
        [input.verificationId],
      );

      const tokens = await insertSession(client, userId, deviceId);
      await recordSecurityEvent(
        client,
        'ACCOUNT_CREATED',
        'SUCCESS',
        requestId,
        userId,
        deviceId,
      );
      await client.query('COMMIT');
      transactionFinished = true;
      return tokens;
    } catch (error) {
      if (!transactionFinished) {
        await client.query('ROLLBACK');
      }
      if (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        error.code === '23505'
      ) {
        throw new AppError(409, 'ACCOUNT_ALREADY_EXISTS');
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async login(
    phoneInput: string,
    pin: string,
    deviceId: string,
    requestId: string,
  ): Promise<SessionTokens> {
    const phoneHash = createPhoneLookupHash(normalizePhone(phoneInput));
    const result = await databasePool.query<LoginRow>(
      `SELECT u.id AS user_id, c.password_hash, c.failed_attempts, c.locked_until
       FROM ${schema}.users u
       JOIN ${schema}.user_credentials c ON c.user_id = u.id
       JOIN ${schema}.devices d ON d.user_id = u.id AND d.id = $2
       WHERE u.phone_lookup_hash = $1
         AND u.status = 'ACTIVE'
         AND d.status = 'ACTIVE'`,
      [phoneHash, deviceId],
    );
    const login = result.rows[0];
    const validPin = await verifyPin(login?.password_hash, pin);
    const locked = login?.locked_until && login.locked_until.getTime() > Date.now();

    if (!login || !validPin || locked) {
      if (login) {
        await databasePool.query(
          `UPDATE ${schema}.user_credentials
           SET failed_attempts = failed_attempts + 1,
               locked_until = CASE
                 WHEN failed_attempts + 1 >= 5 THEN NOW() + INTERVAL '15 minutes'
                 ELSE locked_until
               END
           WHERE user_id = $1`,
          [login.user_id],
        );
      }
      throw new AppError(401, 'INVALID_CREDENTIALS');
    }

    const client = await beginTransaction();
    try {
      await client.query(
        `UPDATE ${schema}.user_credentials
         SET failed_attempts = 0, locked_until = NULL
         WHERE user_id = $1`,
        [login.user_id],
      );
      const tokens = await insertSession(client, login.user_id, deviceId);
      await recordSecurityEvent(
        client,
        'LOGIN',
        'SUCCESS',
        requestId,
        login.user_id,
        deviceId,
      );
      await client.query('COMMIT');
      return tokens;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async refresh(refreshToken: string, requestId: string): Promise<SessionTokens> {
    const client = await beginTransaction();
    let transactionFinished = false;
    try {
      const result = await client.query<SessionRow>(
        `SELECT s.id, s.user_id, s.device_id, s.session_family_id,
                s.expires_at, s.revoked_at, s.replaced_by_id
         FROM ${schema}.auth_sessions s
         JOIN ${schema}.users u ON u.id = s.user_id AND u.status = 'ACTIVE'
         JOIN ${schema}.devices d ON d.id = s.device_id AND d.status = 'ACTIVE'
         WHERE s.refresh_token_hash = $1
         FOR UPDATE OF s`,
        [hashRefreshToken(refreshToken)],
      );
      const session = result.rows[0];

      if (!session) {
        throw new AppError(401, 'INVALID_REFRESH_TOKEN');
      }

      if (session.revoked_at || session.replaced_by_id) {
        if (session.session_family_id) {
          await client.query(
            `UPDATE ${schema}.auth_sessions
             SET revoked_at = COALESCE(revoked_at, NOW())
             WHERE session_family_id = $1`,
            [session.session_family_id],
          );
        }
        await recordSecurityEvent(
          client,
          'REFRESH_TOKEN_REUSE',
          'BLOCKED',
          requestId,
          session.user_id,
          session.device_id,
        );
        await client.query('COMMIT');
        transactionFinished = true;
        throw new AppError(401, 'INVALID_REFRESH_TOKEN');
      }

      if (session.expires_at.getTime() <= Date.now()) {
        await client.query(
          `UPDATE ${schema}.auth_sessions SET revoked_at = NOW() WHERE id = $1`,
          [session.id],
        );
        await client.query('COMMIT');
        transactionFinished = true;
        throw new AppError(401, 'INVALID_REFRESH_TOKEN');
      }

      const tokens = await insertSession(
        client,
        session.user_id,
        session.device_id,
        session.session_family_id ?? randomUUID(),
        session.id,
      );
      const replacementHash = hashRefreshToken(tokens.refreshToken);
      const replacement = await client.query<{ id: string }>(
        `SELECT id FROM ${schema}.auth_sessions WHERE refresh_token_hash = $1`,
        [replacementHash],
      );
      await client.query(
        `UPDATE ${schema}.auth_sessions
         SET revoked_at = NOW(), last_used_at = NOW(), replaced_by_id = $2
         WHERE id = $1`,
        [session.id, replacement.rows[0]?.id],
      );
      await client.query('COMMIT');
      transactionFinished = true;
      return tokens;
    } catch (error) {
      if (!transactionFinished) {
        await client.query('ROLLBACK');
      }
      throw error;
    } finally {
      client.release();
    }
  }

  async logout(refreshToken: string | undefined): Promise<void> {
    if (!refreshToken) {
      return;
    }
    await databasePool.query(
      `UPDATE ${schema}.auth_sessions
       SET revoked_at = COALESCE(revoked_at, NOW())
       WHERE refresh_token_hash = $1`,
      [hashRefreshToken(refreshToken)],
    );
  }

  async authenticate(authorization: string | undefined): Promise<AuthContext> {
    if (!authorization?.startsWith('Bearer ')) {
      throw new AppError(401, 'UNAUTHORIZED');
    }
    const context = await verifyAccessToken(authorization.slice(7));
    const active = await databasePool.query(
      `SELECT 1
       FROM ${schema}.auth_sessions s
       JOIN ${schema}.users u ON u.id = s.user_id AND u.status = 'ACTIVE'
       JOIN ${schema}.devices d ON d.id = s.device_id AND d.status = 'ACTIVE'
       WHERE s.id = $1 AND s.user_id = $2 AND s.device_id = $3
         AND s.revoked_at IS NULL AND s.expires_at > NOW()`,
      [context.sessionId, context.userId, context.deviceId],
    );
    if (active.rowCount !== 1) {
      throw new AppError(401, 'UNAUTHORIZED');
    }
    return context;
  }

  async getMe(userId: string): Promise<Record<string, unknown>> {
    const result = await databasePool.query<UserRow>(
      `SELECT id, name_encrypted, phone_encrypted, discoverable,
              read_receipts_enabled, typing_indicators_enabled, created_at
       FROM ${schema}.users
       WHERE id = $1 AND status = 'ACTIVE'`,
      [userId],
    );
    const user = result.rows[0];
    if (!user) {
      throw new AppError(404, 'USER_NOT_FOUND');
    }
    return {
      id: user.id,
      name: decryptField(user.name_encrypted, 'user-name'),
      phone: decryptField(user.phone_encrypted, 'phone'),
      discoverable: user.discoverable,
      readReceiptsEnabled: user.read_receipts_enabled,
      typingIndicatorsEnabled: user.typing_indicators_enabled,
      createdAt: user.created_at,
    };
  }

  async updatePrivacyPreferences(
    userId: string,
    preferences: {
      readReceiptsEnabled?: boolean | undefined;
      typingIndicatorsEnabled?: boolean | undefined;
    },
  ): Promise<Record<string, unknown>> {
    const result = await databasePool.query<{
      read_receipts_enabled: boolean;
      typing_indicators_enabled: boolean;
    }>(
      `UPDATE ${schema}.users
       SET read_receipts_enabled = COALESCE($2, read_receipts_enabled),
           typing_indicators_enabled = COALESCE($3, typing_indicators_enabled)
       WHERE id = $1 AND status = 'ACTIVE'
       RETURNING read_receipts_enabled, typing_indicators_enabled`,
      [
        userId,
        preferences.readReceiptsEnabled ?? null,
        preferences.typingIndicatorsEnabled ?? null,
      ],
    );
    const updated = result.rows[0];
    if (!updated) {
      throw new AppError(404, 'USER_NOT_FOUND');
    }
    return {
      readReceiptsEnabled: updated.read_receipts_enabled,
      typingIndicatorsEnabled: updated.typing_indicators_enabled,
    };
  }

  async listDevices(userId: string): Promise<Record<string, unknown>[]> {
    const result = await databasePool.query<{
      id: string;
      device_name_encrypted: Buffer | null;
      status: string;
      created_at: Date;
      last_seen_at: Date | null;
    }>(
      `SELECT id, device_name_encrypted, status, created_at, last_seen_at
       FROM ${schema}.devices
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [userId],
    );
    return result.rows.map((device) => ({
      id: device.id,
      name: device.device_name_encrypted
        ? decryptField(device.device_name_encrypted, 'device-name')
        : null,
      status: device.status,
      createdAt: device.created_at,
      lastSeenAt: device.last_seen_at,
    }));
  }

  async revokeDevice(userId: string, deviceId: string): Promise<void> {
    const client = await beginTransaction();
    try {
      const result = await client.query(
        `UPDATE ${schema}.devices
         SET status = 'REVOKED', revoked_at = NOW()
         WHERE id = $1 AND user_id = $2 AND status = 'ACTIVE'`,
        [deviceId, userId],
      );
      if (result.rowCount !== 1) {
        throw new AppError(404, 'DEVICE_NOT_FOUND');
      }
      await client.query(
        `UPDATE ${schema}.auth_sessions
         SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE device_id = $1 AND user_id = $2`,
        [deviceId, userId],
      );
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}
