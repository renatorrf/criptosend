import { randomUUID } from 'node:crypto';

import { z } from 'zod';

import { env } from '../config/env.js';
import { databasePool } from '../database/pool.js';
import { quoteIdentifier } from '../database/identifier.js';

const requestId = z.uuid().parse(process.argv[2]);
const operator = z.string().trim().min(3).max(120).parse(process.argv[3]);
const schema = quoteIdentifier(env.SCHEMA);

try {
  const client = await databasePool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query<{ user_id: string }>(
      `UPDATE ${schema}.account_reset_requests
       SET status = 'APPROVED', approved_at = NOW(), approved_by = $2
       WHERE id = $1 AND status = 'PENDING' AND expires_at > NOW()
       RETURNING user_id`,
      [requestId, operator],
    );
    if (result.rowCount !== 1 || !result.rows[0]) {
      throw new Error('Reset request not found, expired, or already processed.');
    }
    await client.query(
      `INSERT INTO ${schema}.security_events
         (id, user_id, event_type, outcome, request_id)
       VALUES ($1, $2, 'ADMIN_RESET_APPROVED', 'SUCCESS', $3)`,
      [randomUUID(), result.rows[0].user_id, `admin-cli:${operator}`],
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
  console.log('ACCOUNT_RESET_APPROVED');
} finally {
  await databasePool.end();
}
