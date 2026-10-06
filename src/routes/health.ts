import type { FastifyPluginCallback } from 'fastify';

import { databasePool } from '../database/pool.js';

export const healthRoutes: FastifyPluginCallback = (app, _options, done) => {
  app.get('/health', () => ({ status: 'ok' }));

  app.get('/ready', async (_request, reply) => {
    try {
      await databasePool.query('SELECT 1');
      return { status: 'ready' };
    } catch {
      return reply.code(503).send({ status: 'unavailable' });
    }
  });

  done();
};
