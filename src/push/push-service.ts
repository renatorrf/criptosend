import { createHash, randomUUID } from 'node:crypto';

import webpush, { type PushSubscription } from 'web-push';

import { env } from '../config/env.js';
import { quoteIdentifier } from '../database/identifier.js';
import { databasePool } from '../database/pool.js';
import { decryptField, encryptField } from '../security/field-crypto.js';

const schema = quoteIdentifier(env.SCHEMA);

interface SubscriptionRow {
  id: string;
  endpoint_encrypted: Buffer;
  p256dh_encrypted: Buffer;
  auth_encrypted: Buffer;
}

export interface RegisterPushSubscriptionInput {
  endpoint: string;
  expirationTime: number | null;
  keys: { p256dh: string; auth: string };
}

function endpointHash(endpoint: string): string {
  return createHash('sha256').update(endpoint, 'utf8').digest('hex');
}

export class PushService {
  readonly configured = Boolean(
    env.VAPID_SUBJECT && env.VAPID_PUBLIC_KEY && env.VAPID_PRIVATE_KEY,
  );

  constructor() {
    const { VAPID_SUBJECT: subject, VAPID_PUBLIC_KEY: publicKey, VAPID_PRIVATE_KEY: privateKey } = env;
    if (subject && publicKey && privateKey) {
      webpush.setVapidDetails(subject, publicKey, privateKey);
    }
  }

  async register(
    userId: string,
    deviceId: string,
    input: RegisterPushSubscriptionInput,
  ): Promise<void> {
    await databasePool.query(
      `INSERT INTO ${schema}.push_subscriptions
         (id, user_id, device_id, endpoint_encrypted, endpoint_lookup_hash,
          p256dh_encrypted, auth_encrypted, revoked_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NULL)
       ON CONFLICT (endpoint_lookup_hash) DO UPDATE
       SET user_id = EXCLUDED.user_id,
           device_id = EXCLUDED.device_id,
           endpoint_encrypted = EXCLUDED.endpoint_encrypted,
           p256dh_encrypted = EXCLUDED.p256dh_encrypted,
           auth_encrypted = EXCLUDED.auth_encrypted,
           revoked_at = NULL`,
      [
        randomUUID(),
        userId,
        deviceId,
        encryptField(input.endpoint, 'push-endpoint'),
        endpointHash(input.endpoint),
        encryptField(input.keys.p256dh, 'push-p256dh'),
        encryptField(input.keys.auth, 'push-auth'),
      ],
    );
  }

  async revoke(userId: string, deviceId: string, endpoint: string): Promise<void> {
    await databasePool.query(
      `UPDATE ${schema}.push_subscriptions
       SET revoked_at = COALESCE(revoked_at, NOW())
       WHERE user_id = $1 AND device_id = $2 AND endpoint_lookup_hash = $3`,
      [userId, deviceId, endpointHash(endpoint)],
    );
  }

  async notifyNewMessage(
    recipientUserIds: string[],
    conversationId: string,
  ): Promise<void> {
    await this.notifyUsers(recipientUserIds, {
      notification: {
        title: 'Spotifi',
        body: 'Você recebeu uma nova mensagem.',
        icon: '/assets/icon/icon-192x192.png',
        badge: '/assets/icon/icon-96x96.png',
        tag: `conversation-${conversationId}`,
        renotify: true,
        data: {
          onActionClick: {
            default: {
              operation: 'navigateLastFocusedOrOpen',
              url: `/conversations/${conversationId}`,
            },
          },
        },
      },
    }, 120);
  }

  async notifyIncomingCall(
    recipientUserIds: string[],
    conversationId: string,
    callId: string,
  ): Promise<void> {
    await this.notifyUsers(recipientUserIds, {
      notification: {
        title: 'Chamada de vídeo',
        body: 'Você está recebendo uma chamada no Spotifi.',
        icon: '/assets/icon/icon-192x192.png',
        badge: '/assets/icon/icon-96x96.png',
        tag: `call-${callId}`,
        renotify: true,
        requireInteraction: true,
        data: {
          callId,
          conversationId,
          onActionClick: {
            default: {
              operation: 'navigateLastFocusedOrOpen',
              url: `/conversations/${conversationId}`,
            },
          },
        },
      },
    }, 60);
  }

  private async notifyUsers(
    recipientUserIds: string[],
    body: Record<string, unknown>,
    ttl: number,
  ): Promise<void> {
    if (!this.configured || recipientUserIds.length === 0) return;

    const result = await databasePool.query<SubscriptionRow>(
      `SELECT id, endpoint_encrypted, p256dh_encrypted, auth_encrypted
       FROM ${schema}.push_subscriptions
       WHERE user_id = ANY($1::uuid[]) AND revoked_at IS NULL`,
      [recipientUserIds],
    );
    const payload = JSON.stringify(body);

    await Promise.allSettled(
      result.rows.map(async (row) => {
        const subscription: PushSubscription = {
          endpoint: decryptField(row.endpoint_encrypted, 'push-endpoint'),
          keys: {
            p256dh: decryptField(row.p256dh_encrypted, 'push-p256dh'),
            auth: decryptField(row.auth_encrypted, 'push-auth'),
          },
        };
        try {
          await webpush.sendNotification(subscription, payload, { TTL: ttl });
        } catch (error) {
          const statusCode = (error as { statusCode?: number }).statusCode;
          if (statusCode === 404 || statusCode === 410) {
            await databasePool.query(
              `UPDATE ${schema}.push_subscriptions SET revoked_at = NOW() WHERE id = $1`,
              [row.id],
            );
            return;
          }
          throw error;
        }
      }),
    );
  }
}
