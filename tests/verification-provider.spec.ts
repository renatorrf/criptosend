import { afterEach, describe, expect, it, vi } from 'vitest';

import { TwilioVerificationProvider } from '../src/auth/verification-provider.js';

const configuration = {
  accountSid: `AC${'1'.repeat(32)}`,
  authToken: 'test-auth-token',
  fromNumber: '+15551234567',
};

describe('TwilioVerificationProvider', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends the verification code through the Twilio Messages API', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 201 }));
    vi.stubGlobal('fetch', fetchMock);

    const provider = new TwilioVerificationProvider(configuration);
    await provider.sendCode('+5511999999999', '123456');

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, request] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(
      `https://api.twilio.com/2010-04-01/Accounts/${configuration.accountSid}/Messages.json`,
    );
    expect(request.method).toBe('POST');
    expect(request.headers).toMatchObject({
      authorization: `Basic ${Buffer.from(`${configuration.accountSid}:${configuration.authToken}`, 'utf8').toString('base64')}`,
      'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
    });
    expect(request.body).toBeInstanceOf(URLSearchParams);
    const body = request.body as URLSearchParams;
    expect(body.get('From')).toBe(configuration.fromNumber);
    expect(body.get('To')).toBe('+5511999999999');
    expect(body.get('Body')).toContain('123456');
  });

  it('returns the generic provider error when Twilio rejects the request', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(null, { status: 401 })),
    );

    const provider = new TwilioVerificationProvider(configuration);

    await expect(provider.sendCode('+5511999999999', '123456')).rejects.toMatchObject({
      code: 'PHONE_VERIFICATION_UNAVAILABLE',
      statusCode: 503,
    });
  });
});
