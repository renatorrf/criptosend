import {
  randomBytes,
  randomInt,
  randomUUID,
} from 'node:crypto';

import type { PoolClient } from 'pg';

import { env } from '../config/env.js';
import { databasePool } from '../database/pool.js';
import { quoteIdentifier } from '../database/identifier.js';
import { AppError } from '../http/app-error.js';
import { normalizePhone } from '../identity/phone.js';
import { decryptField, encryptField } from '../security/field-crypto.js';
import {
  constantTimeHexEqual,
  createPhoneLookupHash,
  createVerificationCodeHash,
  hashRefreshToken,
} from '../security/hashes.js';
import { hashPassword, verifyPassword } from '../security/pin.js';
import { createAccessToken, createRefreshToken } from './tokens.js';
import { verifyRecoveryProof } from './recovery-proof.js';
import type { VerificationProvider } from './verification-provider.js';

const schema = quoteIdentifier(env.SCHEMA);
const FLOW_TTL_SECONDS = 15 * 60;
const ADMIN_RESET_TTL_SECONDS = 7 * 24 * 60 * 60;

export type AccessPurpose = 'ACCESS' | 'PASSWORD_RECOVERY' | 'ADMIN_RESET';

interface AccessChallengeRow {
  phone_encrypted: Buffer;
  phone_lookup_hash: string;
  code_lookup_hash: string;
  requested_name_encrypted: Buffer | null;
  purpose: AccessPurpose;
  attempts: number;
  max_attempts: number;
  expires_at: Date;
  verified_at: Date | null;
  flow_token_hash: string | null;
  flow_expires_at: Date | null;
  recovery_challenge: Buffer | null;
  consumed_at: Date | null;
}

interface UserCredentialRow {
  user_id: string;
  password_hash: string;
  failed_attempts: number;
  locked_until: Date | null;
}

interface RecoveryRow {
  key_id: string;
  public_key: Buffer;
  wrapped_private_key: Buffer;
  wrapping_iv: Buffer;
  kdf_salt: Buffer;
  kdf_parameters: Record<string, number>;
  version: number;
}

export interface DeviceInput {
  deviceId?: string;
  deviceName?: string;
  identityPublicKey?: Buffer;
  registrationId?: number;
}

export interface RecoveryCredentialInput {
  keyId: string;
  publicKey: Buffer;
  wrappedPrivateKey: Buffer;
  wrappingIv: Buffer;
  kdfSalt: Buffer;
  kdfParameters: {
    memorySize: number;
    iterations: number;
    parallelism: number;
    hashLength: number;
  };
}

export interface AccessSession {
  userId: string;
  deviceId: string;
  accessToken: string;
  refreshToken: string;
  accessExpiresInSeconds: number;
}

async function beginTransaction(): Promise<PoolClient> {
  const client = await databasePool.connect();
  await client.query('BEGIN');
  return client;
}

async function recordEvent(
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

async function createSession(
  client: PoolClient,
  userId: string,
  deviceId: string,
): Promise<AccessSession> {
  const sessionId = randomUUID();
  const refreshToken = createRefreshToken();
  const expiresAt = new Date(Date.now() + env.AUTH_REFRESH_TTL_SECONDS * 1_000);
  await client.query(
    `INSERT INTO ${schema}.auth_sessions
       (id, user_id, device_id, refresh_token_hash, expires_at, session_family_id)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      sessionId,
      userId,
      deviceId,
      hashRefreshToken(refreshToken),
      expiresAt,
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

function assertFlow(challenge: AccessChallengeRow, flowToken: string): void {
  if (
    challenge.consumed_at ||
    !challenge.verified_at ||
    !challenge.flow_token_hash ||
    !challenge.flow_expires_at ||
    challenge.flow_expires_at.getTime() <= Date.now() ||
    !constantTimeHexEqual(challenge.flow_token_hash, hashRefreshToken(flowToken))
  ) {
    throw new AppError(401, 'INVALID_ACCESS_FLOW');
  }
}

async function insertDevice(
  client: PoolClient,
  userId: string,
  input: Required<Omit<DeviceInput, 'deviceId'>>,
): Promise<string> {
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

function requireNewDevice(input: DeviceInput): Required<Omit<DeviceInput, 'deviceId'>> {
  if (
    !input.deviceName ||
    !input.identityPublicKey ||
    input.registrationId === undefined
  ) {
    throw new AppError(400, 'DEVICE_REGISTRATION_REQUIRED');
  }
  return {
    deviceName: input.deviceName,
    identityPublicKey: input.identityPublicKey,
    registrationId: input.registrationId,
  };
}

export class AccountAccessService {
  constructor(private readonly verificationProvider: VerificationProvider) {}

  async start(phoneInput: string, name: string, purpose: AccessPurpose): Promise<{
    verificationId: string;
    expiresInSeconds: number;
  }> {
    const phone = normalizePhone(phoneInput);
    const verificationId = randomUUID();
    const code = randomInt(0, 1_000_000).toString().padStart(6, '0');
    const expiresAt = new Date(Date.now() + env.VERIFICATION_TTL_SECONDS * 1_000);
    await databasePool.query(
      `INSERT INTO ${schema}.phone_verification_challenges
         (id, phone_encrypted, phone_lookup_hash, code_lookup_hash, expires_at,
          purpose, requested_name_encrypted)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        verificationId,
        encryptField(phone, 'phone'),
        createPhoneLookupHash(phone),
        createVerificationCodeHash(verificationId, code),
        expiresAt,
        purpose,
        encryptField(name.trim(), 'access-name'),
      ],
    );
    try {
      await this.verificationProvider.sendCode(phone, code);
    } catch (error) {
      await databasePool.query(
        `UPDATE ${schema}.phone_verification_challenges
         SET consumed_at = NOW() WHERE id = $1`,
        [verificationId],
      );
      throw error;
    }
    return { verificationId, expiresInSeconds: env.VERIFICATION_TTL_SECONDS };
  }

  async verifyPhone(verificationId: string, code: string, requestId: string): Promise<{
    flowToken: string;
    expiresInSeconds: number;
    nextAction: 'LOGIN' | 'CREATE_ACCOUNT' | 'RECOVER_PASSWORD' | 'REQUEST_ADMIN_RESET';
    recovery?: {
      keyId: string;
      wrappedPrivateKey: string;
      wrappingIv: string;
      kdfSalt: string;
      kdfParameters: Record<string, number>;
      challenge: string;
    };
  }> {
    const client = await beginTransaction();
    let finished = false;
    try {
      const result = await client.query<AccessChallengeRow>(
        `SELECT phone_encrypted, phone_lookup_hash, code_lookup_hash,
                requested_name_encrypted, purpose, attempts, max_attempts,
                expires_at, verified_at, flow_token_hash, flow_expires_at,
                recovery_challenge, consumed_at
         FROM ${schema}.phone_verification_challenges WHERE id = $1 FOR UPDATE`,
        [verificationId],
      );
      const challenge = result.rows[0];
      if (
        !challenge ||
        challenge.consumed_at ||
        challenge.verified_at ||
        challenge.expires_at.getTime() <= Date.now() ||
        challenge.attempts >= challenge.max_attempts
      ) {
        throw new AppError(400, 'INVALID_OR_EXPIRED_VERIFICATION');
      }
      const supplied = createVerificationCodeHash(verificationId, code);
      if (!constantTimeHexEqual(challenge.code_lookup_hash, supplied)) {
        await client.query(
          `UPDATE ${schema}.phone_verification_challenges
           SET attempts = attempts + 1 WHERE id = $1`,
          [verificationId],
        );
        await recordEvent(client, 'PHONE_VERIFICATION', 'FAILURE', requestId);
        await client.query('COMMIT');
        finished = true;
        throw new AppError(400, 'INVALID_OR_EXPIRED_VERIFICATION');
      }
      const user = await client.query<{ id: string }>(
        `SELECT id FROM ${schema}.users
         WHERE phone_lookup_hash = $1 AND status = 'ACTIVE'`,
        [challenge.phone_lookup_hash],
      );
      const userId = user.rows[0]?.id;
      const flowToken = randomBytes(32).toString('base64url');
      const flowExpiresAt = new Date(Date.now() + FLOW_TTL_SECONDS * 1_000);
      const recoveryChallenge = randomBytes(32);
      await client.query(
        `UPDATE ${schema}.phone_verification_challenges
         SET verified_at = NOW(), flow_token_hash = $2, flow_expires_at = $3,
             recovery_challenge = $4
         WHERE id = $1`,
        [verificationId, hashRefreshToken(flowToken), flowExpiresAt, recoveryChallenge],
      );

      let nextAction: 'LOGIN' | 'CREATE_ACCOUNT' | 'RECOVER_PASSWORD' | 'REQUEST_ADMIN_RESET';
      let recovery: {
        keyId: string;
        wrappedPrivateKey: string;
        wrappingIv: string;
        kdfSalt: string;
        kdfParameters: Record<string, number>;
        challenge: string;
      } | undefined;
      if (!userId) {
        nextAction = 'CREATE_ACCOUNT';
      } else if (challenge.purpose === 'PASSWORD_RECOVERY') {
        const recoveryResult = await client.query<RecoveryRow>(
          `SELECT key_id, public_key, wrapped_private_key, wrapping_iv,
                  kdf_salt, kdf_parameters, version
           FROM ${schema}.account_recovery_credentials WHERE user_id = $1`,
          [userId],
        );
        const stored = recoveryResult.rows[0];
        if (!stored) {
          throw new AppError(409, 'MASTER_RECOVERY_NOT_CONFIGURED');
        }
        nextAction = 'RECOVER_PASSWORD';
        recovery = {
          keyId: stored.key_id,
          wrappedPrivateKey: stored.wrapped_private_key.toString('base64'),
          wrappingIv: stored.wrapping_iv.toString('base64'),
          kdfSalt: stored.kdf_salt.toString('base64'),
          kdfParameters: stored.kdf_parameters,
          challenge: recoveryChallenge.toString('base64'),
        };
      } else if (challenge.purpose === 'ADMIN_RESET') {
        nextAction = 'REQUEST_ADMIN_RESET';
      } else {
        nextAction = 'LOGIN';
      }
      await recordEvent(client, 'PHONE_VERIFICATION', 'SUCCESS', requestId, userId);
      await client.query('COMMIT');
      finished = true;
      return {
        flowToken,
        expiresInSeconds: FLOW_TTL_SECONDS,
        nextAction,
        ...(recovery ? { recovery } : {}),
      };
    } catch (error) {
      if (!finished) await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async register(
    verificationId: string,
    flowToken: string,
    name: string,
    password: string,
    device: DeviceInput,
    recovery: RecoveryCredentialInput,
    requestId: string,
  ): Promise<AccessSession> {
    const client = await beginTransaction();
    try {
      const challenge = await this.lockFlow(client, verificationId);
      assertFlow(challenge, flowToken);
      const existing = await client.query(
        `SELECT 1 FROM ${schema}.users WHERE phone_lookup_hash = $1`,
        [challenge.phone_lookup_hash],
      );
      if (existing.rowCount !== 0) throw new AppError(409, 'ACCOUNT_ALREADY_EXISTS');
      const userId = randomUUID();
      await client.query(
        `INSERT INTO ${schema}.users
           (id, phone_encrypted, phone_lookup_hash, name_encrypted)
         VALUES ($1, $2, $3, $4)`,
        [
          userId,
          encryptField(decryptField(challenge.phone_encrypted, 'phone'), 'phone'),
          challenge.phone_lookup_hash,
          encryptField(name.trim(), 'user-name'),
        ],
      );
      await client.query(
        `INSERT INTO ${schema}.user_credentials (user_id, password_hash)
         VALUES ($1, $2)`,
        [userId, await hashPassword(password)],
      );
      const deviceId = await insertDevice(client, userId, requireNewDevice(device));
      await upsertRecovery(client, userId, recovery);
      await client.query(
        `UPDATE ${schema}.phone_verification_challenges
         SET consumed_at = NOW() WHERE id = $1`,
        [verificationId],
      );
      const session = await createSession(client, userId, deviceId);
      await recordEvent(client, 'ACCOUNT_CREATED', 'SUCCESS', requestId, userId, deviceId);
      await client.query('COMMIT');
      return session;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async login(
    verificationId: string,
    flowToken: string,
    password: string,
    device: DeviceInput,
    requestId: string,
  ): Promise<AccessSession> {
    const client = await beginTransaction();
    let finished = false;
    try {
      const challenge = await this.lockFlow(client, verificationId);
      assertFlow(challenge, flowToken);
      if (challenge.purpose !== 'ACCESS') throw new AppError(400, 'INVALID_ACCESS_FLOW');
      const result = await client.query<UserCredentialRow>(
        `SELECT u.id AS user_id, c.password_hash, c.failed_attempts, c.locked_until
         FROM ${schema}.users u
         JOIN ${schema}.user_credentials c ON c.user_id = u.id
         WHERE u.phone_lookup_hash = $1 AND u.status = 'ACTIVE'
         FOR UPDATE OF c`,
        [challenge.phone_lookup_hash],
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
          await recordEvent(client, 'LOGIN', locked ? 'BLOCKED' : 'FAILURE', requestId, credential.user_id);
        }
        await client.query('COMMIT');
        finished = true;
        throw new AppError(401, 'INVALID_CREDENTIALS');
      }
      let deviceId = device.deviceId;
      if (deviceId) {
        const existingDevice = await client.query(
          `SELECT 1 FROM ${schema}.devices
           WHERE id = $1 AND user_id = $2 AND status = 'ACTIVE'`,
          [deviceId, credential.user_id],
        );
        if (existingDevice.rowCount !== 1) deviceId = undefined;
      }
      deviceId ??= await insertDevice(client, credential.user_id, requireNewDevice(device));
      await client.query(
        `UPDATE ${schema}.user_credentials
         SET failed_attempts = 0, locked_until = NULL WHERE user_id = $1`,
        [credential.user_id],
      );
      await client.query(
        `UPDATE ${schema}.phone_verification_challenges
         SET consumed_at = NOW() WHERE id = $1`,
        [verificationId],
      );
      const session = await createSession(client, credential.user_id, deviceId);
      await recordEvent(client, 'LOGIN', 'SUCCESS', requestId, credential.user_id, deviceId);
      await client.query('COMMIT');
      finished = true;
      return session;
    } catch (error) {
      if (!finished) await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async recoverPassword(
    verificationId: string,
    flowToken: string,
    signature: Buffer,
    newPassword: string,
    requestId: string,
  ): Promise<void> {
    const client = await beginTransaction();
    let finished = false;
    try {
      const challenge = await this.lockFlow(client, verificationId);
      assertFlow(challenge, flowToken);
      if (challenge.purpose !== 'PASSWORD_RECOVERY' || !challenge.recovery_challenge) {
        throw new AppError(400, 'INVALID_ACCESS_FLOW');
      }
      const result = await client.query<{ user_id: string; public_key: Buffer }>(
        `SELECT u.id AS user_id, r.public_key
         FROM ${schema}.users u
         JOIN ${schema}.account_recovery_credentials r ON r.user_id = u.id
         WHERE u.phone_lookup_hash = $1 AND u.status = 'ACTIVE'`,
        [challenge.phone_lookup_hash],
      );
      const recovery = result.rows[0];
      if (!recovery) throw new AppError(401, 'INVALID_RECOVERY_PROOF');
      const valid = verifyRecoveryProof(
        recovery.public_key,
        verificationId,
        challenge.recovery_challenge,
        signature,
      );
      if (!valid) {
        await recordEvent(client, 'PASSWORD_RECOVERY', 'FAILURE', requestId, recovery.user_id);
        await client.query('COMMIT');
        finished = true;
        throw new AppError(401, 'INVALID_RECOVERY_PROOF');
      }
      await client.query(
        `UPDATE ${schema}.user_credentials
         SET password_hash = $2, failed_attempts = 0, locked_until = NULL
         WHERE user_id = $1`,
        [recovery.user_id, await hashPassword(newPassword)],
      );
      await client.query(
        `UPDATE ${schema}.auth_sessions SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE user_id = $1`,
        [recovery.user_id],
      );
      await client.query(
        `UPDATE ${schema}.phone_verification_challenges SET consumed_at = NOW()
         WHERE id = $1`,
        [verificationId],
      );
      await recordEvent(client, 'PASSWORD_RECOVERY', 'SUCCESS', requestId, recovery.user_id);
      await client.query('COMMIT');
      finished = true;
    } catch (error) {
      if (!finished) await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async requestAdminReset(
    verificationId: string,
    flowToken: string,
    requestId: string,
  ): Promise<{ requestId: string; claimToken: string; expiresInSeconds: number }> {
    const client = await beginTransaction();
    try {
      const challenge = await this.lockFlow(client, verificationId);
      assertFlow(challenge, flowToken);
      if (challenge.purpose !== 'ADMIN_RESET') throw new AppError(400, 'INVALID_ACCESS_FLOW');
      const user = await client.query<{ id: string }>(
        `SELECT id FROM ${schema}.users
         WHERE phone_lookup_hash = $1 AND status = 'ACTIVE'`,
        [challenge.phone_lookup_hash],
      );
      const userId = user.rows[0]?.id;
      if (!userId) throw new AppError(404, 'ACCOUNT_NOT_FOUND');
      const adminRequestId = randomUUID();
      const claimToken = randomBytes(32).toString('base64url');
      await client.query(
        `INSERT INTO ${schema}.account_reset_requests
           (id, user_id, claim_token_hash, expires_at)
         VALUES ($1, $2, $3, $4)`,
        [
          adminRequestId,
          userId,
          hashRefreshToken(claimToken),
          new Date(Date.now() + ADMIN_RESET_TTL_SECONDS * 1_000),
        ],
      );
      await client.query(
        `UPDATE ${schema}.phone_verification_challenges SET consumed_at = NOW()
         WHERE id = $1`,
        [verificationId],
      );
      await recordEvent(client, 'ADMIN_RESET_REQUESTED', 'SUCCESS', requestId, userId);
      await client.query('COMMIT');
      return { requestId: adminRequestId, claimToken, expiresInSeconds: ADMIN_RESET_TTL_SECONDS };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async adminResetStatus(requestId: string, claimToken: string): Promise<{ status: string }> {
    const result = await databasePool.query<{ status: string; expires_at: Date }>(
      `SELECT status, expires_at FROM ${schema}.account_reset_requests
       WHERE id = $1 AND claim_token_hash = $2`,
      [requestId, hashRefreshToken(claimToken)],
    );
    const reset = result.rows[0];
    if (!reset) throw new AppError(404, 'RESET_REQUEST_NOT_FOUND');
    if (reset.expires_at.getTime() <= Date.now() && reset.status !== 'COMPLETED') {
      if (reset.status === 'PENDING') {
        await databasePool.query(
          `UPDATE ${schema}.account_reset_requests SET status = 'EXPIRED' WHERE id = $1`,
          [requestId],
        );
      }
      return { status: 'EXPIRED' };
    }
    return { status: reset.status };
  }

  async completeAdminReset(
    requestId: string,
    claimToken: string,
    password: string,
    device: DeviceInput,
    recovery: RecoveryCredentialInput,
    auditRequestId: string,
  ): Promise<AccessSession> {
    const client = await beginTransaction();
    try {
      const result = await client.query<{ user_id: string; status: string; expires_at: Date }>(
        `SELECT user_id, status, expires_at FROM ${schema}.account_reset_requests
         WHERE id = $1 AND claim_token_hash = $2 FOR UPDATE`,
        [requestId, hashRefreshToken(claimToken)],
      );
      const reset = result.rows[0];
      if (!reset || reset.status !== 'APPROVED' || reset.expires_at.getTime() <= Date.now()) {
        throw new AppError(409, 'RESET_NOT_APPROVED');
      }
      await client.query(
        `UPDATE ${schema}.auth_sessions SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE user_id = $1`,
        [reset.user_id],
      );
      await client.query(
        `UPDATE ${schema}.devices
         SET status = 'REVOKED', revoked_at = COALESCE(revoked_at, NOW())
         WHERE user_id = $1 AND status = 'ACTIVE'`,
        [reset.user_id],
      );
      await client.query(
        `UPDATE ${schema}.user_credentials
         SET password_hash = $2, failed_attempts = 0, locked_until = NULL
         WHERE user_id = $1`,
        [reset.user_id, await hashPassword(password)],
      );
      await upsertRecovery(client, reset.user_id, recovery);
      const deviceId = await insertDevice(client, reset.user_id, requireNewDevice(device));
      await client.query(
        `UPDATE ${schema}.account_reset_requests
         SET status = 'COMPLETED', completed_at = NOW() WHERE id = $1`,
        [requestId],
      );
      const session = await createSession(client, reset.user_id, deviceId);
      await recordEvent(client, 'ADMIN_ACCOUNT_RESET', 'SUCCESS', auditRequestId, reset.user_id, deviceId);
      await client.query('COMMIT');
      return session;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  private async lockFlow(client: PoolClient, verificationId: string): Promise<AccessChallengeRow> {
    const result = await client.query<AccessChallengeRow>(
      `SELECT phone_encrypted, phone_lookup_hash, code_lookup_hash,
              requested_name_encrypted, purpose, attempts, max_attempts,
              expires_at, verified_at, flow_token_hash, flow_expires_at,
              recovery_challenge, consumed_at
       FROM ${schema}.phone_verification_challenges WHERE id = $1 FOR UPDATE`,
      [verificationId],
    );
    const challenge = result.rows[0];
    if (!challenge) throw new AppError(401, 'INVALID_ACCESS_FLOW');
    return challenge;
  }
}
