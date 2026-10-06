import { buildApp } from './app.js';
import { env } from './config/env.js';
import { closeDatabasePool } from './database/pool.js';

const app = await buildApp();

async function shutdown(signal: string): Promise<void> {
  app.log.info({ signal }, 'SERVER_SHUTDOWN');
  await app.close();
  await closeDatabasePool();
  process.exit(0);
}

process.once('SIGINT', () => {
  void shutdown('SIGINT');
});
process.once('SIGTERM', () => {
  void shutdown('SIGTERM');
});

try {
  await app.listen({ host: '0.0.0.0', port: env.PORT });
} catch (error) {
  app.log.error({ err: { name: error instanceof Error ? error.name : 'Error' } }, 'SERVER_START_FAILED');
  await closeDatabasePool();
  process.exit(1);
}
