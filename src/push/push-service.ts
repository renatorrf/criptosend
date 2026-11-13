import { createHash, randomUUID } from 'node:crypto';

import webpush, { type PushSubscription } from 'web-push';

import type { CallMediaType } from '../calls/call-service.js';
import { env } from '../config/env.js';
import { quoteIdentifier } from '../database/identifier.js';
import { databasePool } from '../database/pool.js';
import { decryptField, encryptField } from '../security/field-crypto.js';

const schema = quoteIdentifier(env.SCHEMA);

export function pushOpenUrl(path?: string): string {
  if (!path) return env.PUSH_DEFAULT_OPEN_URL;
  return new URL(path, env.PUSH_DEFAULT_OPEN_URL).toString();
}

type PushActivity =
  | { kind: 'message' }
  | { kind: 'call'; mediaType: CallMediaType; callerName: string | undefined };

export function activityNotification(activity: PushActivity) {
  const isCall = activity.kind === 'call';
  const name = isCall ? activity.callerName?.replace(/[\p{Cc}\p{Cf}]/gu, '').trim().slice(0, 80) : '';
  const title = isCall
    ? (activity.mediaType === 'AUDIO' ? 'Chamada de áudio' : 'Chamada de vídeo')
    : 'Nova mensagem';
  return {
    notification: {
      title,
      body: isCall
        ? (name ? `${name} está te chamando.` : 'Abra o Spotifi para atender.')
        : 'Abra o Spotifi para ler.',
      icon: pushOpenUrl('/assets/icon/icon-192x192.png'),
      badge: pushOpenUrl('/assets/icon/icon-96x96.png'),
      tag: `spotifi-${activity.kind}`,
      renotify: true,
      requireInteraction: isCall,
      data: {
        onActionClick: {
          default: {
            operation: 'navigateLastFocusedOrOpen',
            url: pushOpenUrl('/conversations'),
          },
        },
      },
    },
  };
}

interface SubscriptionRow {
  id: string;
  endpoint_encrypted: Buffer;
  p256dh_encrypted: Buffer;
  auth_encrypted: Buffer;
}

export interface PushStatus {
  configured: boolean;
  publicKey: string | null;
  activeDevices: number;
}

export interface PushSubscriptionStatus {
  synchronized: boolean;
}

export interface PushDeliverySummary {
  attempted: number;
  delivered: number;
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

  async status(userId: string): Promise<PushStatus> {
    const result = await databasePool.query<{ active_devices: string }>(
      `SELECT COUNT(DISTINCT device_id)::text AS active_devices
       FROM ${schema}.push_subscriptions
       WHERE user_id = $1 AND revoked_at IS NULL`,
      [userId],
    );
    return {
      configured: this.configured,
      publicKey: this.configured ? env.VAPID_PUBLIC_KEY ?? null : null,
      activeDevices: Number(result.rows[0]?.active_devices ?? 0),
    };
  }

  async subscriptionStatus(
    userId: string,
    deviceId: string,
    endpoint: string,
  ): Promise<PushSubscriptionStatus> {
    const result = await databasePool.query(
      `SELECT 1
       FROM ${schema}.push_subscriptions
       WHERE user_id = $1 AND device_id = $2
         AND endpoint_lookup_hash = $3 AND revoked_at IS NULL`,
      [userId, deviceId, endpointHash(endpoint)],
    );
    return { synchronized: result.rowCount === 1 };
  }

  async revoke(userId: string, deviceId: string, endpoint: string): Promise<void> {
    await databasePool.query(
      `UPDATE ${schema}.push_subscriptions
       SET revoked_at = COALESCE(revoked_at, NOW())
       WHERE user_id = $1 AND device_id = $2 AND endpoint_lookup_hash = $3`,
      [userId, deviceId, endpointHash(endpoint)],
    );
  }

  async notifyNewMessage(recipientUserIds: string[]): Promise<void> {
    await this.notifyUsers(recipientUserIds, activityNotification({ kind: 'message' }), 300, 'spotifi-message');
  }

  async notifyIncomingCall(
    recipientUserIds: string[],
    mediaType: CallMediaType,
    callerName?: string,
  ): Promise<void> {
    await this.notifyUsers(
      recipientUserIds,
      activityNotification({ kind: 'call', mediaType, callerName }),
      90,
      'spotifi-call',
    );
  }

  async notifyTest(userId: string): Promise<PushDeliverySummary> {
    return this.notifyUsers([userId], {
      notification: {
        title: 'Spotifi',
        body: 'As notificações estão funcionando neste dispositivo.',
        icon: pushOpenUrl('/assets/icon/icon-192x192.png'),
        badge: pushOpenUrl('/assets/icon/icon-96x96.png'),
        tag: 'spotifi-test',
        renotify: false,
        data: {
          onActionClick: {
            default: {
              operation: 'navigateLastFocusedOrOpen',
              url: pushOpenUrl(),
            },
          },
        },
      },
    }, 300, 'spotifi-test');
  }

  private async notifyUsers(
    recipientUserIds: string[],
    body: Record<string, unknown>,
    ttl: number,
    notificationKey: string,
  ): Promise<PushDeliverySummary> {
    const { VAPID_SUBJECT: subject, VAPID_PUBLIC_KEY: publicKey, VAPID_PRIVATE_KEY: privateKey } = env;
    if (!subject || !publicKey || !privateKey || recipientUserIds.length === 0) {
      return { attempted: 0, delivered: 0 };
    }

    const result = await databasePool.query<SubscriptionRow>(
      `SELECT id, endpoint_encrypted, p256dh_encrypted, auth_encrypted
       FROM ${schema}.push_subscriptions
       WHERE user_id = ANY($1::uuid[]) AND revoked_at IS NULL`,
      [recipientUserIds],
    );
    const payload = JSON.stringify(body);
    const topic = createHash('sha256')
      .update(notificationKey, 'utf8')
      .digest('base64url')
      .slice(0, 32);

    const outcomes = await Promise.all(
      result.rows.map(async (row) => {
        const subscription: PushSubscription = {
          endpoint: decryptField(row.endpoint_encrypted, 'push-endpoint'),
          keys: {
            p256dh: decryptField(row.p256dh_encrypted, 'push-p256dh'),
            auth: decryptField(row.auth_encrypted, 'push-auth'),
          },
        };
        try {
          await webpush.sendNotification(subscription, payload, {
            vapidDetails: {
              subject,
              publicKey,
              privateKey,
            },
            TTL: ttl,
            urgency: 'high',
            topic,
          });
          return true;
        } catch (error) {
          const statusCode = (error as { statusCode?: number }).statusCode;
          if (statusCode === 404 || statusCode === 410) {
            await databasePool.query(
              `UPDATE ${schema}.push_subscriptions SET revoked_at = NOW() WHERE id = $1`,
              [row.id],
            );
            return false;
          }
          throw error;
        }
      }),
    );
    return {
      attempted: result.rows.length,
      delivered: outcomes.filter(Boolean).length,
    };
  }
}
