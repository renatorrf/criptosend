import { resolve } from 'node:path';

import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config({ path: resolve(process.cwd(), '.env'), quiet: true });

const booleanFromString = z
  .enum(['true', 'false'])
  .default('false')
  .transform((value) => value === 'true');

const optionalUrl = z.preprocess(
  (value) => (value === '' ? undefined : value),
  z.url().optional(),
);

const optionalString = z.preprocess(
  (value) => (value === '' ? undefined : value),
  z.string().min(1).optional(),
);

const testVerificationCodesFromJson = z.preprocess((value) => {
  if (value === undefined || value === '') return {};
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return value;
  }
}, z
  .record(
    z.string().regex(/^\+[1-9]\d{7,14}$/),
    z.string().regex(/^\d{6}$/),
  )
  .refine((codes) => Object.keys(codes).length <= 10));

const iceServerSchema = z
  .object({
    urls: z.union([
      z.string().regex(/^(stun|stuns|turn|turns):/i),
      z.array(z.string().regex(/^(stun|stuns|turn|turns):/i)).min(1).max(8),
    ]),
    username: z.string().min(1).max(256).optional(),
    credential: z.string().min(1).max(512).optional(),
  })
  .strict()
  .refine(
    (server) => {
      const urls = Array.isArray(server.urls) ? server.urls : [server.urls];
      const usesTurn = urls.some((url) => /^turns?:/i.test(url));
      return !usesTurn || Boolean(server.username && server.credential);
    },
    { message: 'TURN servers require username and credential' },
  );

const iceServersFromJson = z.preprocess((value) => {
  if (value === undefined || value === '') {
    return [];
  }
  if (typeof value !== 'string') {
    return value;
  }
  let unescapedValue = value;
  while (unescapedValue.includes('\\"')) {
    unescapedValue = unescapedValue.replaceAll('\\"', '"');
  }
  const candidates = [
    value,
    unescapedValue,
    value.startsWith('"') && value.endsWith('"') ? value.slice(1, -1) : value,
    unescapedValue.startsWith('"') && unescapedValue.endsWith('"')
      ? unescapedValue.slice(1, -1)
      : unescapedValue,
  ];
  for (const candidate of candidates) {
    try {
      const parsed = JSON.parse(candidate) as unknown;
      if (typeof parsed === 'string') {
        return JSON.parse(parsed) as unknown;
      }
      return parsed;
    } catch {
      // Try the next representation. Older generated files escaped JSON twice.
    }
  }
  return value;
}, z.array(iceServerSchema).max(8));

const turnUrlsFromString = z
  .string()
  .default('')
  .transform((value) => value.split(',').map((url) => url.trim()).filter(Boolean))
  .pipe(z.array(z.string().regex(/^turns?:/i)).max(8));

const environmentSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65_535).default(3000),
  DATABASE_URL: z.string().min(1),
  SCHEMA: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/),
  APP_ORIGINS: z.string().default('http://localhost:8100'),
  DATABASE_SSL: booleanFromString,
  DATABASE_SSL_REJECT_UNAUTHORIZED: z
    .enum(['true', 'false'])
    .default('true')
    .transform((value) => value === 'true'),
  JWT_ACCESS_SECRET: z.string().min(32),
  JWT_REFRESH_SECRET: z.string().min(32),
  FIELD_ENCRYPTION_KEY: z.string().min(1),
  PHONE_LOOKUP_SECRET: z.string().min(32),
  VERIFICATION_CODE_SECRET: z.string().min(32),
  CONVERSATION_KEY_SECRET: z.string().min(32),
  AUTH_ACCESS_TTL_SECONDS: z.coerce.number().int().min(60).max(3_600).default(900),
  AUTH_REFRESH_TTL_SECONDS: z.coerce
    .number()
    .int()
    .min(3_600)
    .max(7_776_000)
    .default(2_592_000),
  AUTH_COOKIE_NAME: z.string().regex(/^[A-Za-z0-9_-]+$/).default('criptsend_refresh'),
  AUTH_COOKIE_SECURE: booleanFromString,
  VERIFICATION_TTL_SECONDS: z.coerce.number().int().min(120).max(1_800).default(600),
  PHONE_DEFAULT_COUNTRY: z.string().length(2).default('BR'),
  ARGON2_MEMORY_COST: z.coerce.number().int().min(19_456).default(19_456),
  ARGON2_TIME_COST: z.coerce.number().int().min(2).default(2),
  ARGON2_PARALLELISM: z.coerce.number().int().min(1).max(16).default(1),
  PHONE_VERIFICATION_WEBHOOK_URL: optionalUrl,
  PHONE_VERIFICATION_WEBHOOK_TOKEN: optionalString,
  PHONE_VERIFICATION_TEST_CODES_JSON: testVerificationCodesFromJson,
  TWILIO_ACCOUNT_SID: optionalString,
  TWILIO_AUTH_TOKEN: optionalString,
  TWILIO_FROM_NUMBER: z.preprocess(
    (value) => (value === '' ? undefined : value),
    z.string().regex(/^\+[1-9]\d{7,14}$/).optional(),
  ),
  RTC_ICE_SERVERS_JSON: iceServersFromJson,
  RTC_TURN_URLS: turnUrlsFromString,
  RTC_TURN_SHARED_SECRET: z.preprocess(
    (value) => (value === '' ? undefined : value),
    z.string().min(32).optional(),
  ),
  RTC_TURN_CREDENTIAL_TTL_SECONDS: z.coerce
    .number()
    .int()
    .min(300)
    .max(86_400)
    .default(3_600),
  RTC_RING_TIMEOUT_SECONDS: z.coerce.number().int().min(15).max(120).default(45),
});

const parsedEnvironment = environmentSchema.safeParse(process.env);

if (!parsedEnvironment.success) {
  const variableNames = parsedEnvironment.error.issues
    .map((issue) => issue.path.join('.'))
    .filter(Boolean)
    .join(', ');

  throw new Error(`Invalid or missing environment variables: ${variableNames}`);
}

if (
  parsedEnvironment.data.NODE_ENV === 'production' &&
  !parsedEnvironment.data.AUTH_COOKIE_SECURE
) {
  throw new Error('Invalid or missing environment variables: AUTH_COOKIE_SECURE');
}

if (
  (parsedEnvironment.data.RTC_TURN_URLS.length > 0) !==
  Boolean(parsedEnvironment.data.RTC_TURN_SHARED_SECRET)
) {
  throw new Error(
    'Invalid or missing environment variables: RTC_TURN_URLS, RTC_TURN_SHARED_SECRET',
  );
}

if (
  parsedEnvironment.data.NODE_ENV === 'production' &&
  (parsedEnvironment.data.RTC_TURN_URLS.length === 0 ||
    !parsedEnvironment.data.RTC_TURN_SHARED_SECRET)
) {
  throw new Error(
    'Invalid or missing environment variables: RTC_TURN_URLS, RTC_TURN_SHARED_SECRET',
  );
}

if (
  parsedEnvironment.data.NODE_ENV === 'production' &&
  parsedEnvironment.data.PHONE_VERIFICATION_WEBHOOK_URL &&
  !parsedEnvironment.data.PHONE_VERIFICATION_WEBHOOK_URL.startsWith('https://')
) {
  throw new Error(
    'Invalid or missing environment variables: PHONE_VERIFICATION_WEBHOOK_URL',
  );
}

const twilioConfiguration = [
  parsedEnvironment.data.TWILIO_ACCOUNT_SID,
  parsedEnvironment.data.TWILIO_AUTH_TOKEN,
  parsedEnvironment.data.TWILIO_FROM_NUMBER,
];
const configuredTwilioValues = twilioConfiguration.filter(Boolean).length;

if (configuredTwilioValues > 0 && configuredTwilioValues < twilioConfiguration.length) {
  throw new Error(
    'Invalid or missing environment variables: TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER',
  );
}

if (
  parsedEnvironment.data.NODE_ENV === 'production' &&
  configuredTwilioValues === 0 &&
  !parsedEnvironment.data.PHONE_VERIFICATION_WEBHOOK_URL
) {
  throw new Error(
    'Invalid or missing environment variables: Twilio credentials or PHONE_VERIFICATION_WEBHOOK_URL',
  );
}

export const env = {
  ...parsedEnvironment.data,
  APP_ORIGINS: parsedEnvironment.data.APP_ORIGINS.split(',')
    .map((origin) => origin.trim())
    .filter(Boolean),
  FIELD_ENCRYPTION_KEY: (() => {
    const key = Buffer.from(parsedEnvironment.data.FIELD_ENCRYPTION_KEY, 'base64');
    if (key.length !== 32) {
      throw new Error('Invalid or missing environment variables: FIELD_ENCRYPTION_KEY');
    }
    return key;
  })(),
};

export type Environment = typeof env;
