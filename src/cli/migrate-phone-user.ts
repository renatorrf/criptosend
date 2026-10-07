import { randomBytes } from 'node:crypto';

import { env } from '../config/env.js';
import { closeDatabasePool, databasePool } from '../database/pool.js';
import { quoteIdentifier } from '../database/identifier.js';
import { normalizePhone } from '../identity/phone.js';
import { createPhoneLookupHash } from '../security/hashes.js';
import { hashPassword } from '../security/pin.js';

const schema = quoteIdentifier(env.SCHEMA);

function usernameArgument(): string {
  const value = (process.argv[3] ?? '').trim().normalize('NFKC').toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{2,39}$/.test(value)) {
    throw new Error('INVALID_USERNAME');
  }
  return value;
}

async function main(): Promise<void> {
  const phone = normalizePhone(process.argv[2] ?? '');
  const username = usernameArgument();
  const client = await databasePool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query<{ id: string; username: string | null }>(
      `SELECT id, username FROM ${schema}.users
       WHERE phone_lookup_hash = $1 FOR UPDATE`,
      [createPhoneLookupHash(phone)],
    );
    const user = result.rows[0];
    if (!user) throw new Error('PHONE_USER_NOT_FOUND');
    if (user.username) throw new Error('PHONE_USER_ALREADY_MIGRATED');
    const duplicate = await client.query(
      `SELECT 1 FROM ${schema}.users WHERE username = $1`,
      [username],
    );
    if (duplicate.rowCount !== 0) throw new Error('USERNAME_ALREADY_EXISTS');
    const password = randomBytes(18).toString('base64url');
    await client.query(
      `UPDATE ${schema}.users SET username = $2, role = 'USER' WHERE id = $1`,
      [user.id, username],
    );
    await client.query(
      `UPDATE ${schema}.user_credentials
       SET password_hash = $2, failed_attempts = 0, locked_until = NULL
       WHERE user_id = $1`,
      [user.id, await hashPassword(password)],
    );
    await client.query(
      `UPDATE ${schema}.auth_sessions
       SET revoked_at = COALESCE(revoked_at, NOW()) WHERE user_id = $1`,
      [user.id],
    );
    await client.query('COMMIT');
    console.log(`PHONE_USER_MIGRATED username=${username}`);
    console.log(`PHONE_USER_INITIAL_PASSWORD=${password}`);
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

main()
  .catch((error: unknown) => {
    const code = error instanceof Error ? error.message : 'UNKNOWN';
    console.error(`PHONE_USER_MIGRATION_FAILED reason=${code}`);
    process.exitCode = 1;
  })
  .finally(async () => closeDatabasePool());
