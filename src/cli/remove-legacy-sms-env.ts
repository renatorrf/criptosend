import { access, readFile, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve } from 'node:path';

const obsolete = new Set([
  'TWILIO_ACCOUNT_SID',
  'TWILIO_AUTH_TOKEN',
  'TWILIO_FROM_NUMBER',
  'PHONE_VERIFICATION_WEBHOOK_URL',
  'PHONE_VERIFICATION_WEBHOOK_TOKEN',
  'PHONE_VERIFICATION_TEST_CODES_JSON',
]);

async function clean(fileName: string): Promise<void> {
  const path = resolve(process.cwd(), fileName);
  try {
    await access(path, constants.F_OK);
  } catch {
    return;
  }
  const source = await readFile(path, 'utf8');
  const newline = source.includes('\r\n') ? '\r\n' : '\n';
  const filtered = source
    .split(/\r?\n/)
    .filter((line) => {
      const key = /^([A-Z][A-Z0-9_]*)=/.exec(line)?.[1];
      return !key || !obsolete.has(key);
    })
    .join(newline)
    .replace(new RegExp(`${newline}{3,}`, 'g'), `${newline}${newline}`)
    .replace(new RegExp(`${newline}*$`), newline);
  await writeFile(path, filtered, { encoding: 'utf8', mode: 0o600 });
  console.log(`LEGACY_SMS_ENV_REMOVED file=${fileName}`);
}

Promise.all([clean('.env'), clean('.env.cloudrun')]).catch(() => {
  console.error('LEGACY_SMS_ENV_REMOVAL_FAILED');
  process.exitCode = 1;
});
