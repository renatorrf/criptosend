import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';

import type { PoolClient } from 'pg';

import { env } from '../config/env.js';
import { createSearchPath, quoteIdentifier } from './identifier.js';
import { databasePool } from './pool.js';

const MIGRATIONS_DIRECTORY = resolve(process.cwd(), 'migrations');
const MIGRATION_FILE_PATTERN = /^(\d{3}_[a-z0-9_]+)\.up\.sql$/;

interface AppliedMigration {
  name: string;
}

async function listMigrationNames(): Promise<string[]> {
  const files = await readdir(MIGRATIONS_DIRECTORY);

  return files
    .map((fileName) => MIGRATION_FILE_PATTERN.exec(fileName)?.[1])
    .filter((name): name is string => Boolean(name))
    .sort((left, right) => left.localeCompare(right));
}

async function prepareMigrationTransaction(client: PoolClient): Promise<void> {
  await client.query('BEGIN');
  await client.query(`CREATE SCHEMA IF NOT EXISTS ${quoteIdentifier(env.SCHEMA)}`);
  await client.query("SELECT set_config('search_path', $1, true)", [
    createSearchPath(env.SCHEMA),
  ]);
  await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [
    `criptsend:migrations:${env.SCHEMA}`,
  ]);
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      name VARCHAR(255) PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

export async function migrate(): Promise<string[]> {
  const client = await databasePool.connect();
  const appliedNow: string[] = [];

  try {
    await prepareMigrationTransaction(client);

    const result = await client.query<AppliedMigration>(
      'SELECT name FROM schema_migrations ORDER BY name',
    );
    const applied = new Set(result.rows.map(({ name }) => name));

    for (const migrationName of await listMigrationNames()) {
      if (applied.has(migrationName)) {
        continue;
      }

      const sql = await readFile(
        resolve(MIGRATIONS_DIRECTORY, `${migrationName}.up.sql`),
        'utf8',
      );
      await client.query(sql);
      await client.query('INSERT INTO schema_migrations (name) VALUES ($1)', [
        migrationName,
      ]);
      appliedNow.push(migrationName);
    }

    await client.query('COMMIT');
    return appliedNow;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

export async function rollbackLatest(): Promise<string | null> {
  const client = await databasePool.connect();

  try {
    await prepareMigrationTransaction(client);
    const result = await client.query<AppliedMigration>(
      'SELECT name FROM schema_migrations ORDER BY name DESC LIMIT 1',
    );
    const latest = result.rows[0]?.name;

    if (!latest) {
      await client.query('COMMIT');
      return null;
    }

    const downFile = resolve(MIGRATIONS_DIRECTORY, `${latest}.down.sql`);
    await client.query(await readFile(downFile, 'utf8'));
    await client.query('DELETE FROM schema_migrations WHERE name = $1', [latest]);
    await client.query('COMMIT');
    return latest;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

export async function verifyTables(): Promise<string[]> {
  const expectedTables = [
    'auth_sessions',
    'account_recovery_credentials',
    'account_reset_requests',
    'conversation_members',
    'conversations',
    'device_prekeys',
    'devices',
    'device_media_keys',
    'message_receipts',
    'message_events',
    'messages',
    'push_subscriptions',
    'security_events',
    'phone_verification_challenges',
    'user_credentials',
    'users',
    'call_events',
    'call_participants',
    'call_sessions',
  ];
  const result = await databasePool.query<{ table_name: string }>(
    `
      SELECT table_name
      FROM information_schema.tables
      WHERE table_schema = $1
        AND table_name = ANY($2::text[])
      ORDER BY table_name
    `,
    [env.SCHEMA, expectedTables],
  );

  const existingTables = result.rows.map(({ table_name }) => table_name);

  if (
    existingTables.length !== expectedTables.length ||
    expectedTables.some((table) => !existingTables.includes(table))
  ) {
    throw new Error('The configured schema is missing required tables.');
  }

  const forbiddenMessageColumns = await databasePool.query<{ column_name: string }>(
    `
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = $1
        AND table_name = 'messages'
        AND column_name = ANY($2::text[])
    `,
    [env.SCHEMA, ['message', 'message_text', 'plaintext', 'content', 'body', 'text']],
  );

  if (forbiddenMessageColumns.rowCount !== 0) {
    throw new Error('The messages table contains a forbidden plaintext column.');
  }

  const encryptedColumns = await databasePool.query<{
    column_name: string;
    data_type: string;
    table_name: string;
  }>(
    `
      SELECT table_name, column_name, data_type
      FROM information_schema.columns
      WHERE table_schema = $1
        AND (
          (table_name = 'users' AND column_name IN ('phone_encrypted', 'name_encrypted'))
          OR (table_name = 'messages' AND column_name = 'ciphertext')
        )
    `,
    [env.SCHEMA],
  );

  if (
    encryptedColumns.rowCount !== 3 ||
    encryptedColumns.rows.some(({ data_type }) => data_type !== 'bytea')
  ) {
    throw new Error('Sensitive database columns are not stored as BYTEA.');
  }

  const identityColumns = await databasePool.query<{
    column_name: string;
    data_type: string;
    table_name: string;
  }>(
    `
      SELECT table_name, column_name, data_type
      FROM information_schema.columns
      WHERE table_schema = $1
        AND (
          (table_name = 'user_credentials' AND column_name = 'password_hash')
          OR (table_name = 'phone_verification_challenges'
              AND column_name IN ('phone_encrypted', 'code_lookup_hash'))
          OR (table_name = 'auth_sessions'
              AND column_name IN ('session_family_id', 'rotated_from_id', 'replaced_by_id'))
        )
    `,
    [env.SCHEMA],
  );

  if (identityColumns.rowCount !== 6) {
    throw new Error('The configured schema is missing identity security columns.');
  }

  const prekeyLifecycle = await databasePool.query<{ column_name: string }>(
    `
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = $1
        AND table_name = 'device_prekeys'
        AND column_name = 'claimed_by_device_id'
    `,
    [env.SCHEMA],
  );

  if (prekeyLifecycle.rowCount !== 1) {
    throw new Error('The configured schema is missing the prekey lifecycle column.');
  }

  const messagePrivacy = await databasePool.query<{ column_name: string }>(
    `
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = $1
        AND table_name = 'messages'
        AND column_name = 'deletion_reason'
    `,
    [env.SCHEMA],
  );

  if (messagePrivacy.rowCount !== 1) {
    throw new Error('The configured schema is missing message privacy controls.');
  }

  const callSignalingColumns = await databasePool.query<{ column_name: string }>(
    `
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = $1
        AND table_name IN ('call_sessions', 'call_participants', 'call_events')
        AND column_name IN ('sdp', 'offer', 'answer', 'candidate', 'ice_candidate')
    `,
    [env.SCHEMA],
  );

  if (callSignalingColumns.rowCount !== 0) {
    throw new Error('Call signaling data must not be persisted.');
  }

  return existingTables;
}
