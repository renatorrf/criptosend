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
  it.each(['message', 'call'] as const)('sends a generic %s notification without participant or conversation IDs', (kind) => {
    const { notification } = activityNotification(kind);
    expect(notification.title).toBe('Spotifi');
    expect(notification.tag).toBe(`spotifi-${kind}`);
    expect(notification.data.onActionClick.default.url).toBe(pushOpenUrl('/conversations'));
    expect(Object.keys(notification.data)).toEqual(['onActionClick']);
  });
});
