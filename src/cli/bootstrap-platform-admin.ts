import { randomBytes, randomUUID } from 'node:crypto';

import { env } from '../config/env.js';
import { closeDatabasePool, databasePool } from '../database/pool.js';
import { quoteIdentifier } from '../database/identifier.js';
import { encryptField } from '../security/field-crypto.js';
import { hashPassword } from '../security/pin.js';

const schema = quoteIdentifier(env.SCHEMA);

function usernameFromArgument(): string {
  const value = (process.argv[2] ?? 'admin').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{2,39}$/.test(value)) {
    throw new Error('INVALID_ADMIN_USERNAME');
  }
  return value;
}

async function main(): Promise<void> {
  const username = usernameFromArgument();
  const name = (process.argv[3] ?? 'Administrador da plataforma').trim();
  const existing = await databasePool.query(
    `SELECT 1 FROM ${schema}.users WHERE username = $1`,
    [username],
  );
  if (existing.rowCount !== 0) {
    console.log(`PLATFORM_ADMIN_EXISTS username=${username}`);
    return;
  }

  const password = randomBytes(18).toString('base64url');
  const userId = randomUUID();
  const client = await databasePool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO ${schema}.users
         (id, phone_encrypted, phone_lookup_hash, name_encrypted, username,
          role, discoverable)
       VALUES ($1, NULL, NULL, $2, $3, 'PLATFORM_ADMIN', FALSE)`,
      [userId, encryptField(name, 'user-name'), username],
    );
    await client.query(
      `INSERT INTO ${schema}.user_credentials (user_id, password_hash)
       VALUES ($1, $2)`,
      [userId, await hashPassword(password)],
    );
    await client.query(
      `INSERT INTO ${schema}.security_events
         (id, user_id, event_type, outcome, request_id)
       VALUES ($1, $2, 'PLATFORM_ADMIN_BOOTSTRAPPED', 'SUCCESS', $3)`,
      [randomUUID(), userId, `bootstrap-${randomUUID()}`],
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
  console.log(`PLATFORM_ADMIN_CREATED username=${username}`);
  console.log(`PLATFORM_ADMIN_INITIAL_PASSWORD=${password}`);
}

main()
  .catch(() => {
    console.error('PLATFORM_ADMIN_BOOTSTRAP_FAILED');
    process.exitCode = 1;
  })
  .finally(async () => closeDatabasePool());
