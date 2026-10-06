import { randomUUID } from 'node:crypto';

import type { PoolClient } from 'pg';

import { env } from '../config/env.js';
import { quoteIdentifier } from '../database/identifier.js';
import { databasePool } from '../database/pool.js';
import { AppError } from '../http/app-error.js';

const schema = quoteIdentifier(env.SCHEMA);

export interface PublicPrekeyInput {
  prekeyId: number;
  publicKey: Buffer;
}

export interface SignedPrekeyInput extends PublicPrekeyInput {
  signature: Buffer;
}

export interface PublicDeviceBundle {
  deviceId: string;
  registrationId: number;
  identityPublicKey: string;
  signedPrekey: {
    prekeyId: number;
    publicKey: string;
    signature: string;
  };
  oneTimePrekey: {
    prekeyId: number;
    publicKey: string;
  } | null;
}

export interface PublicMediaIdentity {
  deviceId: string;
  publicKey: string;
  createdAt: Date;
}

async function beginTransaction(): Promise<PoolClient> {
  const client = await databasePool.connect();
  await client.query('BEGIN');
  return client;
}

export class KeyService {
  async registerMediaIdentity(
    userId: string,
    deviceId: string,
    publicKey: Buffer,
  ): Promise<{ created: boolean }> {
    const client = await beginTransaction();
    try {
      const device = await client.query(
        `SELECT 1 FROM ${schema}.devices
         WHERE id = $1 AND user_id = $2 AND status = 'ACTIVE'
         FOR UPDATE`,
        [deviceId, userId],
      );
      if (device.rowCount !== 1) {
        throw new AppError(403, 'DEVICE_NOT_ALLOWED');
      }
      const inserted = await client.query(
        `INSERT INTO ${schema}.device_media_keys (device_id, user_id, public_key)
         VALUES ($1, $2, $3)
         ON CONFLICT (device_id) DO NOTHING`,
        [deviceId, userId, publicKey],
      );
      if (inserted.rowCount === 0) {
        const existing = await client.query<{ public_key: Buffer }>(
          `SELECT public_key FROM ${schema}.device_media_keys
           WHERE device_id = $1 AND user_id = $2`,
          [deviceId, userId],
        );
        if (!existing.rows[0]?.public_key.equals(publicKey)) {
          throw new AppError(409, 'MEDIA_IDENTITY_ALREADY_REGISTERED');
        }
      }
      await client.query('COMMIT');
      return { created: inserted.rowCount === 1 };
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async listMediaIdentities(
    requesterUserId: string,
    targetUserId: string,
  ): Promise<PublicMediaIdentity[]> {
    if (requesterUserId !== targetUserId) {
      const sharedConversation = await databasePool.query(
        `SELECT 1
         FROM ${schema}.conversation_members mine
         JOIN ${schema}.conversation_members peer
           ON peer.conversation_id = mine.conversation_id
         WHERE mine.user_id = $1 AND peer.user_id = $2
           AND mine.status = 'ACTIVE' AND peer.status = 'ACTIVE'
         LIMIT 1`,
        [requesterUserId, targetUserId],
      );
      if (sharedConversation.rowCount !== 1) {
        throw new AppError(404, 'MEDIA_IDENTITY_NOT_FOUND');
      }
    }
    const result = await databasePool.query<{
      device_id: string;
      public_key: Buffer;
      created_at: Date;
    }>(
      `SELECT mk.device_id, mk.public_key, mk.created_at
       FROM ${schema}.device_media_keys mk
       JOIN ${schema}.devices d ON d.id = mk.device_id AND d.status = 'ACTIVE'
       WHERE mk.user_id = $1
       ORDER BY mk.created_at, mk.device_id`,
      [targetUserId],
    );
    return result.rows.map((row) => ({
      deviceId: row.device_id,
      publicKey: row.public_key.toString('base64'),
      createdAt: row.created_at,
    }));
  }

  async uploadPrekeys(
    userId: string,
    deviceId: string,
    signedPrekey: SignedPrekeyInput,
    oneTimePrekeys: PublicPrekeyInput[],
  ): Promise<void> {
    const client = await beginTransaction();
    try {
      const device = await client.query(
        `SELECT 1 FROM ${schema}.devices
         WHERE id = $1 AND user_id = $2 AND status = 'ACTIVE'
         FOR UPDATE`,
        [deviceId, userId],
      );
      if (device.rowCount !== 1) {
        throw new AppError(403, 'DEVICE_NOT_ALLOWED');
      }

      await client.query(
        `UPDATE ${schema}.device_prekeys
         SET used_at = NOW()
         WHERE device_id = $1 AND is_signed = TRUE AND used_at IS NULL`,
        [deviceId],
      );
      await client.query(
        `INSERT INTO ${schema}.device_prekeys
           (id, device_id, prekey_id, public_key, is_signed, signature)
         VALUES ($1, $2, $3, $4, TRUE, $5)`,
        [
          randomUUID(),
          deviceId,
          signedPrekey.prekeyId,
          signedPrekey.publicKey,
          signedPrekey.signature,
        ],
      );

      for (const prekey of oneTimePrekeys) {
        await client.query(
          `INSERT INTO ${schema}.device_prekeys
             (id, device_id, prekey_id, public_key, is_signed)
           VALUES ($1, $2, $3, $4, FALSE)
           ON CONFLICT (device_id, prekey_id) DO NOTHING`,
          [randomUUID(), deviceId, prekey.prekeyId, prekey.publicKey],
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

  async claimBundle(
    requesterDeviceId: string,
    targetUserId: string,
  ): Promise<PublicDeviceBundle[]> {
    const client = await beginTransaction();
    try {
      const devices = await client.query<{
        id: string;
        registration_id: number;
        identity_public_key: Buffer;
      }>(
        `SELECT id, registration_id, identity_public_key
         FROM ${schema}.devices
         WHERE user_id = $1 AND status = 'ACTIVE'
         ORDER BY created_at`,
        [targetUserId],
      );
      if (devices.rowCount === 0) {
        throw new AppError(404, 'KEY_BUNDLE_NOT_FOUND');
      }

      const bundles: PublicDeviceBundle[] = [];
      for (const device of devices.rows) {
        const signedResult = await client.query<{
          prekey_id: number;
          public_key: Buffer;
          signature: Buffer;
        }>(
          `SELECT prekey_id, public_key, signature
           FROM ${schema}.device_prekeys
           WHERE device_id = $1 AND is_signed = TRUE AND used_at IS NULL
           ORDER BY created_at DESC
           LIMIT 1`,
          [device.id],
        );
        const signed = signedResult.rows[0];
        if (!signed) {
          continue;
        }

        const oneTimeResult = await client.query<{
          id: string;
          prekey_id: number;
          public_key: Buffer;
        }>(
          `SELECT id, prekey_id, public_key
           FROM ${schema}.device_prekeys
           WHERE device_id = $1 AND is_signed = FALSE AND used_at IS NULL
           ORDER BY prekey_id
           FOR UPDATE SKIP LOCKED
           LIMIT 1`,
          [device.id],
        );
        const oneTime = oneTimeResult.rows[0];
        if (oneTime) {
          await client.query(
            `UPDATE ${schema}.device_prekeys
             SET used_at = NOW(), claimed_by_device_id = $2
             WHERE id = $1`,
            [oneTime.id, requesterDeviceId],
          );
        }

        bundles.push({
          deviceId: device.id,
          registrationId: device.registration_id,
          identityPublicKey: device.identity_public_key.toString('base64'),
          signedPrekey: {
            prekeyId: signed.prekey_id,
            publicKey: signed.public_key.toString('base64'),
            signature: signed.signature.toString('base64'),
          },
          oneTimePrekey: oneTime
            ? {
                prekeyId: oneTime.prekey_id,
                publicKey: oneTime.public_key.toString('base64'),
              }
            : null,
        });
      }

      if (bundles.length === 0) {
        throw new AppError(404, 'KEY_BUNDLE_NOT_FOUND');
      }
      await client.query('COMMIT');
      return bundles;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
}
