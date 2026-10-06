import { randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const environmentPath = resolve(process.cwd(), '.env');
const current = await readFile(environmentPath, 'utf8');
const required: Record<string, () => string> = {
  JWT_ACCESS_SECRET: () => randomBytes(48).toString('base64url'),
  JWT_REFRESH_SECRET: () => randomBytes(48).toString('base64url'),
  FIELD_ENCRYPTION_KEY: () => randomBytes(32).toString('base64'),
  PHONE_LOOKUP_SECRET: () => randomBytes(48).toString('base64url'),
  VERIFICATION_CODE_SECRET: () => randomBytes(48).toString('base64url'),
  CONVERSATION_KEY_SECRET: () => randomBytes(48).toString('base64url'),
};

const additions: string[] = [];
for (const [name, generate] of Object.entries(required)) {
  const pattern = new RegExp(`^${name}=.+$`, 'm');
  if (!pattern.test(current)) {
    additions.push(`${name}=${generate()}`);
  }
}

if (additions.length > 0) {
  const separator = current.endsWith('\n') ? '' : '\n';
  await writeFile(
    environmentPath,
    `${current}${separator}\n# Generated local security material (do not commit)\n${additions.join('\n')}\n`,
    'utf8',
  );
}

console.log(
  additions.length === 0
    ? 'Local security variables already configured.'
    : `Configured ${String(additions.length)} missing local security variables.`,
);
