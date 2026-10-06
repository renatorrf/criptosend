import { env } from '../config/env.js';
import { AppError } from '../http/app-error.js';

export interface VerificationProvider {
  sendCode(phone: string, code: string): Promise<void>;
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
