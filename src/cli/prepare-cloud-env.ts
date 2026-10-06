import { randomBytes } from 'node:crypto';
import { chmod, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import dotenv from 'dotenv';

const localPath = resolve(process.cwd(), '.env');
const cloudPath = resolve(process.cwd(), '.env.cloudrun');
const checkOnly = process.argv.includes('--check');

async function readEnvironment(path: string): Promise<Record<string, string>> {
  try {
    return dotenv.parse(await readFile(path, 'utf8'));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return {};
    }
    throw error;
  }
}

function required(
  environment: Record<string, string>,
  name: string,
): string {
  const value = environment[name]?.trim();
  if (!value) {
    throw new Error(`Missing required local variable: ${name}`);
  }
  return value;
}

function preserved(
  cloud: Record<string, string>,
  local: Record<string, string>,
  name: string,
): string {
  return cloud[name]?.trim() || local[name]?.trim() || '';
}

function quote(value: string): string {
  return JSON.stringify(value);
}

function operationalPending(environment: Record<string, string>): string[] {
  const pending: string[] = [];
  const webhookUrl = environment['PHONE_VERIFICATION_WEBHOOK_URL']?.trim();
  const twilioNames = [
    'TWILIO_ACCOUNT_SID',
    'TWILIO_AUTH_TOKEN',
    'TWILIO_FROM_NUMBER',
  ];
  const hasTwilio = twilioNames.every((name) => environment[name]?.trim());
  const turnUrls = environment['RTC_TURN_URLS']?.trim();

  if (!hasTwilio && (!webhookUrl || !webhookUrl.startsWith('https://'))) {
    pending.push('TWILIO_* or PHONE_VERIFICATION_WEBHOOK_URL');
  }
  if (!turnUrls) {
    pending.push('RTC_TURN_URLS');
  }

  return pending;
}

function validateCloudEnvironment(environment: Record<string, string>): string[] {
  const invalid = operationalPending(environment);
  const requiredNames = [
    'DATABASE_URL',
    'SCHEMA',
    'JWT_ACCESS_SECRET',
    'JWT_REFRESH_SECRET',
    'FIELD_ENCRYPTION_KEY',
    'PHONE_LOOKUP_SECRET',
    'VERIFICATION_CODE_SECRET',
    'CONVERSATION_KEY_SECRET',
    'RTC_TURN_SHARED_SECRET',
  ];

  for (const name of requiredNames) {
    if (!environment[name]?.trim()) {
      invalid.push(name);
    }
  }

  if (environment['NODE_ENV'] !== 'production') {
    invalid.push('NODE_ENV');
  }
  if (environment['AUTH_COOKIE_SECURE'] !== 'true') {
    invalid.push('AUTH_COOKIE_SECURE');
  }
  if (environment['DATABASE_SSL'] !== 'true') {
    invalid.push('DATABASE_SSL');
  }
  if (environment['DATABASE_SSL_REJECT_UNAUTHORIZED'] !== 'true') {
    invalid.push('DATABASE_SSL_REJECT_UNAUTHORIZED');
  }

  const origins = environment['APP_ORIGINS']?.split(',') ?? [];
  for (const origin of [
    'https://criptsend.web.app',
    'https://criptsend.firebaseapp.com',
  ]) {
    if (!origins.includes(origin)) {
      invalid.push('APP_ORIGINS');
      break;
    }
  }

  try {
    if (Buffer.from(environment['FIELD_ENCRYPTION_KEY'] ?? '', 'base64').length !== 32) {
      invalid.push('FIELD_ENCRYPTION_KEY');
    }
  } catch {
    invalid.push('FIELD_ENCRYPTION_KEY');
  }

  return [...new Set(invalid)].sort();
}

if (checkOnly) {
  const cloud = await readEnvironment(cloudPath);
  const invalid = validateCloudEnvironment(cloud);
  if (invalid.length > 0) {
    console.error(`CLOUD_ENV_PENDING names=${invalid.join(',')}`);
    process.exitCode = 2;
  } else {
    console.log('CLOUD_ENV_READY');
  }
} else {
  const local = await readEnvironment(localPath);
  const currentCloud = await readEnvironment(cloudPath);
  const values: Record<string, string> = {
    NODE_ENV: 'production',
    DATABASE_URL: preserved(currentCloud, local, 'DATABASE_URL') || required(local, 'DATABASE_URL'),
    SCHEMA: preserved(currentCloud, local, 'SCHEMA') || required(local, 'SCHEMA'),
    APP_ORIGINS:
      'https://criptsend.web.app,https://criptsend.firebaseapp.com',
    DATABASE_SSL: 'true',
    DATABASE_SSL_REJECT_UNAUTHORIZED: 'true',
    JWT_ACCESS_SECRET:
      preserved(currentCloud, local, 'JWT_ACCESS_SECRET') || required(local, 'JWT_ACCESS_SECRET'),
    JWT_REFRESH_SECRET:
      preserved(currentCloud, local, 'JWT_REFRESH_SECRET') || required(local, 'JWT_REFRESH_SECRET'),
    FIELD_ENCRYPTION_KEY:
      preserved(currentCloud, local, 'FIELD_ENCRYPTION_KEY') || required(local, 'FIELD_ENCRYPTION_KEY'),
    PHONE_LOOKUP_SECRET:
      preserved(currentCloud, local, 'PHONE_LOOKUP_SECRET') || required(local, 'PHONE_LOOKUP_SECRET'),
    VERIFICATION_CODE_SECRET:
      preserved(currentCloud, local, 'VERIFICATION_CODE_SECRET') || required(local, 'VERIFICATION_CODE_SECRET'),
    CONVERSATION_KEY_SECRET:
      preserved(currentCloud, local, 'CONVERSATION_KEY_SECRET') || required(local, 'CONVERSATION_KEY_SECRET'),
    AUTH_ACCESS_TTL_SECONDS: preserved(currentCloud, local, 'AUTH_ACCESS_TTL_SECONDS') || '900',
    AUTH_REFRESH_TTL_SECONDS:
      preserved(currentCloud, local, 'AUTH_REFRESH_TTL_SECONDS') || '2592000',
    AUTH_COOKIE_NAME: preserved(currentCloud, local, 'AUTH_COOKIE_NAME') || 'criptsend_refresh',
    AUTH_COOKIE_SECURE: 'true',
    VERIFICATION_TTL_SECONDS:
      preserved(currentCloud, local, 'VERIFICATION_TTL_SECONDS') || '600',
    PHONE_DEFAULT_COUNTRY: preserved(currentCloud, local, 'PHONE_DEFAULT_COUNTRY') || 'BR',
    ARGON2_MEMORY_COST: preserved(currentCloud, local, 'ARGON2_MEMORY_COST') || '19456',
    ARGON2_TIME_COST: preserved(currentCloud, local, 'ARGON2_TIME_COST') || '2',
    ARGON2_PARALLELISM: preserved(currentCloud, local, 'ARGON2_PARALLELISM') || '1',
    PHONE_VERIFICATION_WEBHOOK_URL: preserved(
      currentCloud,
      local,
      'PHONE_VERIFICATION_WEBHOOK_URL',
    ),
    PHONE_VERIFICATION_WEBHOOK_TOKEN: preserved(
      currentCloud,
      local,
      'PHONE_VERIFICATION_WEBHOOK_TOKEN',
    ),
    TWILIO_ACCOUNT_SID: preserved(currentCloud, local, 'TWILIO_ACCOUNT_SID'),
    TWILIO_AUTH_TOKEN: preserved(currentCloud, local, 'TWILIO_AUTH_TOKEN'),
    TWILIO_FROM_NUMBER: preserved(currentCloud, local, 'TWILIO_FROM_NUMBER'),
    RTC_ICE_SERVERS_JSON: preserved(currentCloud, local, 'RTC_ICE_SERVERS_JSON') || '[]',
    RTC_TURN_URLS: preserved(currentCloud, local, 'RTC_TURN_URLS'),
    RTC_TURN_SHARED_SECRET:
      preserved(currentCloud, local, 'RTC_TURN_SHARED_SECRET') ||
      randomBytes(48).toString('base64url'),
    RTC_TURN_CREDENTIAL_TTL_SECONDS:
      preserved(currentCloud, local, 'RTC_TURN_CREDENTIAL_TTL_SECONDS') || '3600',
    RTC_RING_TIMEOUT_SECONDS:
      preserved(currentCloud, local, 'RTC_RING_TIMEOUT_SECONDS') || '45',
  };

  const sections: Array<[string, string[]]> = [
    ['Runtime', ['NODE_ENV']],
    [
      'Database',
      [
        'DATABASE_URL',
        'SCHEMA',
        'DATABASE_SSL',
        'DATABASE_SSL_REJECT_UNAUTHORIZED',
      ],
    ],
    ['Allowed web origins', ['APP_ORIGINS']],
    [
      'Application secrets',
      [
        'JWT_ACCESS_SECRET',
        'JWT_REFRESH_SECRET',
        'FIELD_ENCRYPTION_KEY',
        'PHONE_LOOKUP_SECRET',
        'VERIFICATION_CODE_SECRET',
        'CONVERSATION_KEY_SECRET',
      ],
    ],
    [
      'Authentication',
      [
        'AUTH_ACCESS_TTL_SECONDS',
        'AUTH_REFRESH_TTL_SECONDS',
        'AUTH_COOKIE_NAME',
        'AUTH_COOKIE_SECURE',
        'VERIFICATION_TTL_SECONDS',
        'PHONE_DEFAULT_COUNTRY',
        'ARGON2_MEMORY_COST',
        'ARGON2_TIME_COST',
        'ARGON2_PARALLELISM',
      ],
    ],
    [
      'External SMS provider',
      [
        'TWILIO_ACCOUNT_SID',
        'TWILIO_AUTH_TOKEN',
        'TWILIO_FROM_NUMBER',
        'PHONE_VERIFICATION_WEBHOOK_URL',
        'PHONE_VERIFICATION_WEBHOOK_TOKEN',
      ],
    ],
    [
      'WebRTC infrastructure',
      [
        'RTC_ICE_SERVERS_JSON',
        'RTC_TURN_URLS',
        'RTC_TURN_SHARED_SECRET',
        'RTC_TURN_CREDENTIAL_TTL_SECONDS',
        'RTC_RING_TIMEOUT_SECONDS',
      ],
    ],
  ];

  const content = [
    '# Private Cloud Run environment. Never commit or paste this file into tickets/chats.',
    '# Cloud Run injects PORT automatically.',
    ...sections.flatMap(([title, names]) => [
      '',
      `# ${title}`,
      ...names.map((name) => `${name}=${quote(values[name] ?? '')}`),
    ]),
    '',
  ].join('\n');

  await writeFile(cloudPath, content, { encoding: 'utf8', mode: 0o600 });
  await chmod(cloudPath, 0o600);

  const pending = operationalPending(values);
  console.log('CLOUD_ENV_WRITTEN path=.env.cloudrun');
  console.log(
    pending.length === 0
      ? 'CLOUD_ENV_OPERATIONAL'
      : `CLOUD_ENV_PENDING names=${pending.join(',')}`,
  );
}
