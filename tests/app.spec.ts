import { afterEach, describe, expect, it } from 'vitest';

import { buildApp } from '../src/app.js';

describe('health routes', () => {
  const apps: Awaited<ReturnType<typeof buildApp>>[] = [];

  afterEach(async () => {
    await Promise.all(apps.splice(0).map(async (app) => app.close()));
  });

  it('reports the process health without exposing configuration', async () => {
    const app = await buildApp();
    apps.push(app);

    const response = await app.inject({ method: 'GET', url: '/health' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: 'ok' });
  });

  it('rejects malformed registration input without echoing it', async () => {
    const app = await buildApp();
    apps.push(app);

    const response = await app.inject({
      method: 'POST',
      url: '/auth/register',
      payload: { phone: '123' },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: 'INVALID_REQUEST' });
    expect(response.body).not.toContain('123');
  });

  it('rejects malformed unified access input without revealing an account state', async () => {
    const app = await buildApp();
    apps.push(app);

    const response = await app.inject({
      method: 'POST',
      url: '/auth/access/start',
      payload: { phone: '123', name: 'A' },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: 'INVALID_REQUEST' });
    expect(response.body).not.toContain('123');
  });

  it('rejects cross-origin refresh and logout requests', async () => {
    const app = await buildApp();
    apps.push(app);

    const [refresh, logout] = await Promise.all([
      app.inject({
        method: 'POST',
        url: '/auth/refresh',
        headers: { origin: 'https://untrusted.example' },
      }),
      app.inject({
        method: 'POST',
        url: '/auth/logout',
        headers: { origin: 'https://untrusted.example' },
      }),
    ]);

    expect(refresh.statusCode).toBe(403);
    expect(logout.statusCode).toBe(403);
  });

  it('protects conversation and message routes with authentication', async () => {
    const app = await buildApp();
    apps.push(app);

    const conversations = await app.inject({ method: 'GET', url: '/conversations' });
    const lookup = await app.inject({
      method: 'POST',
      url: '/users/lookup',
      payload: { phone: '34999999999' },
    });
    const messages = await app.inject({
      method: 'GET',
      url: '/conversations/1c39cf64-b652-4a5b-82b8-9dfec96b4695/messages',
    });

    expect(conversations.statusCode).toBe(401);
    expect(lookup.statusCode).toBe(401);
    expect(messages.statusCode).toBe(401);
  });

  it('protects receipts and privacy preferences with authentication', async () => {
    const app = await buildApp();
    apps.push(app);
    const messageId = '1c39cf64-b652-4a5b-82b8-9dfec96b4695';

    const [delivered, read, receipts, preferences] = await Promise.all([
      app.inject({ method: 'POST', url: `/messages/${messageId}/delivered` }),
      app.inject({ method: 'POST', url: `/messages/${messageId}/read` }),
      app.inject({ method: 'GET', url: `/messages/${messageId}/receipts` }),
      app.inject({
        method: 'PATCH',
        url: '/me',
        payload: { readReceiptsEnabled: true },
      }),
    ]);

    for (const response of [delivered, read, receipts, preferences]) {
      expect(response.statusCode).toBe(401);
    }
  });

  it('protects call configuration and history with authentication', async () => {
    const app = await buildApp();
    apps.push(app);
    const conversationId = '1c39cf64-b652-4a5b-82b8-9dfec96b4695';

    const [configuration, history] = await Promise.all([
      app.inject({ method: 'GET', url: '/calls/ice-config' }),
      app.inject({
        method: 'GET',
        url: `/conversations/${conversationId}/calls`,
      }),
    ]);

    expect(configuration.statusCode).toBe(401);
    expect(history.statusCode).toBe(401);
  });

  it('protects device media identities with authentication', async () => {
    const app = await buildApp();
    apps.push(app);
    const userId = '1c39cf64-b652-4a5b-82b8-9dfec96b4695';

    const [registration, identities] = await Promise.all([
      app.inject({
        method: 'PUT',
        url: '/keys/media-identity',
        payload: { publicKey: 'AA==' },
      }),
      app.inject({
        method: 'GET',
        url: `/keys/users/${userId}/media-identities`,
      }),
    ]);

    expect(registration.statusCode).toBe(401);
    expect(identities.statusCode).toBe(401);
  });

  it('protects platform management routes with authentication', async () => {
    const app = await buildApp();
    apps.push(app);

    const [invitations, users, phone, password] = await Promise.all([
      app.inject({ method: 'GET', url: '/management/invitations' }),
      app.inject({ method: 'GET', url: '/management/users' }),
      app.inject({ method: 'PATCH', url: '/me/phone', payload: { phone: '34999999999' } }),
      app.inject({
        method: 'PATCH',
        url: '/me/password',
        payload: { currentPassword: 'old-password', newPassword: 'new-password' },
      }),
    ]);

    for (const response of [invitations, users, phone, password]) {
      expect(response.statusCode).toBe(401);
    }
  });
});
