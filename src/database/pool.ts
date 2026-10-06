import pg from 'pg';

import { env } from '../config/env.js';

const { Pool } = pg;

export const databasePool = new Pool({
  connectionString: env.DATABASE_URL,
  application_name: 'criptsend-api',
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
  ...(env.DATABASE_SSL
    ? {
        ssl: {
          rejectUnauthorized: env.DATABASE_SSL_REJECT_UNAUTHORIZED,
        },
      }
    : {}),
});

databasePool.on('error', () => {
  // Do not log connection details or query data.
  console.error('DATABASE_POOL_ERROR');
});

export async function closeDatabasePool(): Promise<void> {
  await databasePool.end();
}
