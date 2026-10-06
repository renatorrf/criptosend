import { createHmac } from 'node:crypto';

import { env } from '../config/env.js';

export interface IceServerConfig {
  urls: string | string[];
  username?: string;
  credential?: string;
}

export function createTurnCredentials(
  userId: string,
  sharedSecret: string,
  expiresAtUnixSeconds: number,
): { username: string; credential: string } {
  const subject = createHmac('sha256', sharedSecret)
    .update(userId, 'utf8')
    .digest('base64url')
    .slice(0, 24);
  const username = `${String(expiresAtUnixSeconds)}:${subject}`;
  const credential = createHmac('sha1', sharedSecret)
    .update(username, 'utf8')
    .digest('base64');
  return { username, credential };
}

export function createIceServers(userId: string, now = new Date()): IceServerConfig[] {
  const servers: IceServerConfig[] = env.RTC_ICE_SERVERS_JSON.map((server) => ({
    urls: server.urls,
    ...(server.username ? { username: server.username } : {}),
    ...(server.credential ? { credential: server.credential } : {}),
  }));
  if (env.RTC_TURN_URLS.length > 0 && env.RTC_TURN_SHARED_SECRET) {
    const expiresAt =
      Math.floor(now.getTime() / 1_000) + env.RTC_TURN_CREDENTIAL_TTL_SECONDS;
    servers.push({
      urls: env.RTC_TURN_URLS,
      ...createTurnCredentials(userId, env.RTC_TURN_SHARED_SECRET, expiresAt),
    });
  }
  return servers;
}
