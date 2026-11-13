import { describe, expect, it } from 'vitest';

import { env } from '../config/env.js';
import { activityNotification, pushOpenUrl } from './push-service.js';

describe('pushOpenUrl', () => {
  it('uses the configured default destination when no route is provided', () => {
    expect(pushOpenUrl()).toBe(env.PUSH_DEFAULT_OPEN_URL);
  });

  it('opens conversation routes on the configured application origin', () => {
    const result = new URL(pushOpenUrl('/conversations/conversation-id'));
    const configured = new URL(env.PUSH_DEFAULT_OPEN_URL);

    expect(result.origin).toBe(configured.origin);
    expect(result.pathname).toBe('/conversations/conversation-id');
  });
});

describe('private push payload', () => {
  it.each([
    { kind: 'message' },
    { kind: 'call', mediaType: 'AUDIO', callerName: 'Ana' },
  ] as const)('omits participant and conversation IDs from $kind notifications', (activity) => {
    const { notification } = activityNotification(activity);
    expect(notification.tag).toBe(`spotifi-${activity.kind}`);
    expect(notification.data.onActionClick.default.url).toBe(pushOpenUrl('/conversations'));
    expect(Object.keys(notification.data)).toEqual(['onActionClick']);
  });

  it.each([
    ['AUDIO', 'Chamada de áudio'],
    ['VIDEO', 'Chamada de vídeo'],
  ] as const)('shows the caller name and call type for %s', (mediaType, title) => {
    const { notification } = activityNotification({ kind: 'call', mediaType, callerName: ' Ana Silva ' });
    expect(notification).toMatchObject({ title, body: 'Ana Silva está te chamando.', requireInteraction: true });
  });

  it('uses a call-specific fallback and keeps the message preview private', () => {
    expect(activityNotification({ kind: 'call', mediaType: 'AUDIO', callerName: undefined }).notification.body)
      .toBe('Abra o Spotifi para atender.');
    expect(activityNotification({ kind: 'message' }).notification).toMatchObject({
      title: 'Nova mensagem',
      body: 'Abra o Spotifi para ler.',
      requireInteraction: false,
    });
  });
});
