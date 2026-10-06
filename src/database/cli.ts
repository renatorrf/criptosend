import { closeDatabasePool } from './pool.js';
import { migrate, rollbackLatest, verifyTables } from './migrator.js';

type Command = 'migrate' | 'rollback' | 'verify';

function getSafeErrorMetadata(error: unknown): string {
  if (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof error.code === 'string' &&
    /^[A-Z0-9]{5}$/.test(error.code)
  ) {
    const position =
      'position' in error &&
      typeof error.position === 'string' &&
      /^\d+$/.test(error.position)
        ? ` position=${error.position}`
        : '';

    return `code=${error.code}${position}`;
  }

  return 'code=UNKNOWN';
}

async function main(): Promise<void> {
  const command = process.argv[2] as Command | undefined;

  switch (command) {
    case 'migrate': {
      const applied = await migrate();
      console.log(`MIGRATIONS_APPLIED count=${String(applied.length)}`);
      break;
    }
    case 'rollback': {
      const rolledBack = await rollbackLatest();
      console.log(`MIGRATION_ROLLBACK applied=${String(rolledBack !== null)}`);
      break;
    }
    case 'verify': {
      const tables = await verifyTables();
      console.log(`DATABASE_TABLES_VERIFIED count=${String(tables.length)}`);
      console.log(tables.join('\n'));
      break;
    }
    default:
      throw new Error('Use one of: migrate, rollback, verify.');
  }
}

main()
  .catch((error: unknown) => {
    console.error(`DATABASE_COMMAND_FAILED ${getSafeErrorMetadata(error)}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await closeDatabasePool();
  });
