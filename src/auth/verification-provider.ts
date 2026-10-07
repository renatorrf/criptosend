import { env } from '../config/env.js';
import { AppError } from '../http/app-error.js';

export interface VerificationProvider {
  resolveCode?(phone: string, generatedCode: string): string;
  disclosedCode?(phone: string): string | undefined;
  sendCode(phone: string, code: string): Promise<void>;
}

export interface TwilioConfiguration {
  accountSid: string;
  authToken: string;
  fromNumber: string;
}

export class TwilioVerificationProvider implements VerificationProvider {
  constructor(private readonly configuration: TwilioConfiguration) {}

  async sendCode(phone: string, code: string): Promise<void> {
    const { accountSid, authToken, fromNumber } = this.configuration;
    const body = new URLSearchParams({
      Body: `Seu codigo de verificacao CriptSend e ${code}. Ele expira em ${String(Math.ceil(env.VERIFICATION_TTL_SECONDS / 60))} minutos.`,
      From: fromNumber,
      To: phone,
    });

    try {
      const response = await fetch(
        `https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(accountSid)}/Messages.json`,
        {
          method: 'POST',
          headers: {
            authorization: `Basic ${Buffer.from(`${accountSid}:${authToken}`, 'utf8').toString('base64')}`,
            'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
          },
          body,
          signal: AbortSignal.timeout(10_000),
        },
      );

      if (response.ok) {
        return;
      }
    } catch {
      // Keep the public response identical for transport and provider failures.
    }

    throw new AppError(503, 'PHONE_VERIFICATION_UNAVAILABLE');
  }
}

export class WebhookVerificationProvider implements VerificationProvider {
  async sendCode(phone: string, code: string): Promise<void> {
    if (!env.PHONE_VERIFICATION_WEBHOOK_URL) {
      throw new AppError(503, 'PHONE_VERIFICATION_UNAVAILABLE');
    }

    const headers: Record<string, string> = {
      'content-type': 'application/json',
    };
    if (env.PHONE_VERIFICATION_WEBHOOK_TOKEN) {
      headers.authorization = `Bearer ${env.PHONE_VERIFICATION_WEBHOOK_TOKEN}`;
    }

    try {
      const response = await fetch(env.PHONE_VERIFICATION_WEBHOOK_URL, {
        method: 'POST',
        headers,
        body: JSON.stringify({ phone, code }),
        signal: AbortSignal.timeout(10_000),
      });

      if (response.ok) {
        return;
      }
    } catch {
      // The public response is intentionally identical for provider failures.
    }

    throw new AppError(503, 'PHONE_VERIFICATION_UNAVAILABLE');
  }
}

export class TestNumberVerificationProvider implements VerificationProvider {
  constructor(
    private readonly delegate: VerificationProvider,
    private readonly testCodes: Record<string, string>,
  ) {}

  resolveCode(phone: string, generatedCode: string): string {
    return this.testCodes[phone] ?? generatedCode;
  }

  disclosedCode(phone: string): string | undefined {
    return this.testCodes[phone];
  }

  sendCode(phone: string, code: string): Promise<void> {
    if (this.testCodes[phone]) return Promise.resolve();
    return this.delegate.sendCode(phone, code);
  }
}

export function createVerificationProvider(): VerificationProvider {
  let provider: VerificationProvider;
  if (
    env.TWILIO_ACCOUNT_SID &&
    env.TWILIO_AUTH_TOKEN &&
    env.TWILIO_FROM_NUMBER
  ) {
    provider = new TwilioVerificationProvider({
      accountSid: env.TWILIO_ACCOUNT_SID,
      authToken: env.TWILIO_AUTH_TOKEN,
      fromNumber: env.TWILIO_FROM_NUMBER,
    });
  } else {
    provider = new WebhookVerificationProvider();
  }

  return Object.keys(env.PHONE_VERIFICATION_TEST_CODES_JSON).length > 0
    ? new TestNumberVerificationProvider(
        provider,
        env.PHONE_VERIFICATION_TEST_CODES_JSON,
      )
    : provider;
}
