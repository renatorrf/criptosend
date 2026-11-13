import { randomBytes, randomUUID } from 'node:crypto';

import { normalizePlatformUsername } from '../auth/platform-access-service.js';
import { env } from '../config/env.js';
import { closeDatabasePool, databasePool } from '../database/pool.js';
import { quoteIdentifier } from '../database/identifier.js';
import { encryptField } from '../security/field-crypto.js';
import { hashPassword } from '../security/pin.js';

const schema = quoteIdentifier(env.SCHEMA);
const platformDataTables = [
  'account_recovery_credentials',
  'account_reset_requests',
  'auth_sessions',
  'call_events',
  'call_participants',
  'call_sessions',
  'conversation_members',
  'conversations',
  'device_media_keys',
  'device_prekeys',
  'devices',
  'invitation_codes',
  'manager_invitation_balances',
  'manager_invitation_grants',
  'manager_network_links',
  'manager_network_requests',
  'manager_recovery_tokens',
  'message_events',
  'message_receipts',
  'messages',
  'phone_verification_challenges',
  'push_subscriptions',
  'security_events',
  'user_access_reset_tokens',
  'user_credentials',
  'username_recovery_challenges',
  'users',
];

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const resetExisting = args.includes('--reset-existing');
  const positional = args.filter((arg) => arg !== '--reset-existing');
  if (positional.length > 2 || positional.some((arg) => arg.startsWith('--'))) {
    throw new Error('INVALID_ARGUMENTS');
  }
  const username = normalizePlatformUsername(positional[0] ?? 'admin');
  const name = (positional[1] ?? 'Administrador da plataforma').trim();
  if (!name) throw new Error('INVALID_ADMIN_NAME');
  const suggestedPassword = randomBytes(18).toString('base64url');
  const tokenId = randomUUID();
  const token = `ar_${tokenId}_${randomBytes(32).toString('base64url')}`;
  const [placeholderHash, tokenHash] = await Promise.all([
    hashPassword(randomBytes(32).toString('base64url')),
    hashPassword(token),
  ]);
  const client = await databasePool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL lock_timeout = '10s'");
    await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [
      `criptsend:admin-bootstrap:${env.SCHEMA}`,
    ]);
    if (resetExisting) {
      const tables = platformDataTables.map((table) => `${schema}.${quoteIdentifier(table)}`);
      await client.query(`TRUNCATE ${tables.join(', ')} RESTRICT`);
    }
    const admins = await client.query<{ id: string; username: string; activation_pending: boolean }>(
      `SELECT u.id, u.username,
              COALESCE(c.reset_reason = 'MANAGER_REQUEST' AND c.reset_requested_by_user_id = u.id, FALSE)
                AS activation_pending
       FROM ${schema}.users u
       LEFT JOIN ${schema}.user_credentials c ON c.user_id = u.id
       WHERE u.role = 'PLATFORM_ADMIN'`,
    );
    const existing = admins.rows[0];
    if (existing && (admins.rowCount !== 1 || existing.username !== username || !existing.activation_pending)) {
      await client.query('ROLLBACK');
      console.log('PLATFORM_ADMIN_ALREADY_CONFIGURED');
      return;
    }
    const userId = existing?.id ?? randomUUID();
    if (existing) {
      const pending = await client.query(
        `SELECT 1 FROM ${schema}.user_credentials
         WHERE user_id = $1 AND reset_reason = 'MANAGER_REQUEST' AND reset_requested_by_user_id = $1
         FOR UPDATE`,
        [userId],
      );
      if (!pending.rowCount) throw new Error('PLATFORM_ADMIN_ALREADY_CONFIGURED');
      await client.query(
        `UPDATE ${schema}.user_access_reset_tokens SET consumed_at = NOW()
         WHERE user_id = $1 AND consumed_at IS NULL`,
        [userId],
      );
    } else {
      await client.query(
        `INSERT INTO ${schema}.users (id, name_encrypted, username, nickname, role, discoverable)
         VALUES ($1, $2, $3, $3, 'PLATFORM_ADMIN', FALSE)`,
        [userId, encryptField(name, 'user-name'), username],
      );
      await client.query(
        `INSERT INTO ${schema}.user_credentials
           (user_id, password_hash, reset_required_at, reset_reason, reset_requested_by_user_id)
         VALUES ($1, $2, NOW(), 'MANAGER_REQUEST', $1)`,
        [userId, placeholderHash],
      );
    }
    const issued = await client.query<{ expires_at: Date }>(
      `INSERT INTO ${schema}.user_access_reset_tokens
         (id, user_id, token_hash, created_by_user_id, expires_at)
       VALUES ($1, $2, $3, $2, NOW() + INTERVAL '24 hours')
       RETURNING expires_at`,
      [tokenId, userId, tokenHash],
    );
    const invitation = issued.rows[0];
    if (!invitation) throw new Error('ADMIN_ACTIVATION_EXPIRATION_MISSING');
    await client.query(
      `INSERT INTO ${schema}.security_events
         (id, user_id, event_type, outcome, request_id)
       VALUES ($1, $2, 'PLATFORM_ADMIN_BOOTSTRAPPED', 'SUCCESS', $3)`,
      [randomUUID(), userId, `bootstrap-${randomUUID()}`],
    );
    await client.query('COMMIT');
    console.log(`PLATFORM_ADMIN_ACTIVATION username=${username}`);
    console.log(`PLATFORM_ADMIN_ACTIVATION_TOKEN=${token}`);
    console.log(`PLATFORM_ADMIN_ACTIVATION_EXPIRES_AT=${invitation.expires_at.toISOString()}`);
    console.log(`PLATFORM_ADMIN_SUGGESTED_PASSWORD=${suggestedPassword}`);
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

main()
  .catch((error: unknown) => {
    const code = error && typeof error === 'object' && 'code' in error ? error.code : null;
    const suffix = typeof code === 'string' && /^[A-Z0-9]{5}$/.test(code) ? ` code=${code}` : '';
    console.error(`PLATFORM_ADMIN_BOOTSTRAP_FAILED${suffix}`);
    process.exitCode = 1;
  })
  .finally(async () => closeDatabasePool());
