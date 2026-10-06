import type { Server as HttpServer } from 'node:http';

import { Server as SocketServer } from 'socket.io';
import { z } from 'zod';

import type { AuthService } from '../auth/auth-service.js';
import type { AuthContext } from '../auth/tokens.js';
import type { CallService, CallView } from '../calls/call-service.js';
import { env } from '../config/env.js';
import type { ConversationService } from '../conversations/conversation-service.js';
import { AppError } from '../http/app-error.js';

const conversationPayloadSchema = z.object({ conversationId: z.uuid() }).strict();
const callPayloadSchema = z.object({ callId: z.uuid() }).strict();
const offerSchema = z
  .object({
    callId: z.uuid(),
    description: z.object({ type: z.literal('offer'), sdp: z.string().max(131_072) }).strict(),
  })
  .strict();
const answerSchema = z
  .object({
    callId: z.uuid(),
    description: z.object({ type: z.literal('answer'), sdp: z.string().max(131_072) }).strict(),
  })
  .strict();
const iceCandidateSchema = z
  .object({
    callId: z.uuid(),
    candidate: z
      .object({
        candidate: z.string().max(4_096),
        sdpMid: z.string().max(256).nullable().optional(),
        sdpMLineIndex: z.number().int().min(0).max(65_535).nullable().optional(),
        usernameFragment: z.string().max(256).nullable().optional(),
      })
      .strict(),
  })
  .strict();
const keyExchangeSchema = z
  .object({
    callId: z.uuid(),
    exchangeId: z.uuid(),
    ephemeralPublicKey: z
      .string()
      .min(80)
      .max(512)
      .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/),
  })
  .strict();

interface SocketData {
  auth: AuthContext;
}

interface CallAcknowledge {
  ok: boolean;
  call?: CallView;
  error?: string;
}

interface ClientToServerEvents {
  'conversation:join': (
    payload: unknown,
    acknowledge?: (result: { ok: boolean }) => void,
  ) => void;
  'conversation:leave': (payload: unknown) => void;
  'typing:start': (payload: unknown) => void;
  'typing:stop': (payload: unknown) => void;
  'call:start': (payload: unknown, acknowledge?: (result: CallAcknowledge) => void) => void;
  'call:accept': (payload: unknown, acknowledge?: (result: CallAcknowledge) => void) => void;
  'call:decline': (payload: unknown, acknowledge?: (result: CallAcknowledge) => void) => void;
  'call:end': (payload: unknown, acknowledge?: (result: CallAcknowledge) => void) => void;
  'webrtc:offer': (payload: unknown) => void;
  'webrtc:answer': (payload: unknown) => void;
  'webrtc:ice-candidate': (payload: unknown) => void;
  'webrtc:key-offer': (payload: unknown) => void;
  'webrtc:key-answer': (payload: unknown) => void;
}

interface ServerToClientEvents {
  'auth:user': (payload: { authenticated: boolean }) => void;
  'conversation:created': (payload: Record<string, unknown>) => void;
  'message:received': (payload: Record<string, unknown>) => void;
  'message:deleted': (payload: Record<string, unknown>) => void;
  'message:delivered': (payload: Record<string, unknown>) => void;
  'message:read': (payload: Record<string, unknown>) => void;
  'typing:start': (payload: Record<string, unknown>) => void;
  'typing:stop': (payload: Record<string, unknown>) => void;
  'call:incoming': (payload: Record<string, unknown>) => void;
  'call:accepted': (payload: Record<string, unknown>) => void;
  'call:declined': (payload: Record<string, unknown>) => void;
  'call:ended': (payload: Record<string, unknown>) => void;
  'webrtc:offer': (payload: Record<string, unknown>) => void;
  'webrtc:answer': (payload: Record<string, unknown>) => void;
  'webrtc:ice-candidate': (payload: Record<string, unknown>) => void;
  'webrtc:key-offer': (payload: Record<string, unknown>) => void;
  'webrtc:key-answer': (payload: Record<string, unknown>) => void;
}

type RealtimeEvent = Exclude<keyof ServerToClientEvents, 'auth:user'>;

function callErrorCode(error: unknown): string {
  return error instanceof AppError ? error.code : 'CALL_OPERATION_FAILED';
}

export class RealtimeHub {
  private readonly io: SocketServer<
    ClientToServerEvents,
    ServerToClientEvents,
    Record<string, never>,
    SocketData
  >;

  constructor(
    server: HttpServer,
    authService: AuthService,
    conversations: ConversationService,
    calls: CallService,
  ) {
    this.io = new SocketServer(server, {
      cors: { origin: env.APP_ORIGINS, credentials: true },
      serveClient: false,
      transports: ['websocket'],
      maxHttpBufferSize: 256 * 1024,
    });

    this.io.use((socket, next) => {
      const authentication: unknown = socket.handshake.auth;
      const token =
        typeof authentication === 'object' &&
        authentication !== null &&
        'token' in authentication
          ? authentication.token
          : undefined;
      if (typeof token !== 'string') {
        next(new Error('UNAUTHORIZED'));
        return;
      }
      void authService
        .authenticate(`Bearer ${token}`)
        .then((auth) => {
          socket.data.auth = auth;
          next();
        })
        .catch(() => {
          next(new Error('UNAUTHORIZED'));
        });
    });

    this.io.on('connection', (socket) => {
      const auth = socket.data.auth;
      let lastTypingEventAt = 0;
      let signalWindowStartedAt = Date.now();
      let signalCount = 0;
      const socketCallIds = new Set<string>();
      void socket.join(`user:${auth.userId}`);
      socket.emit('auth:user', { authenticated: true });

      socket.on('conversation:join', async (payload, acknowledge) => {
        const parsed = conversationPayloadSchema.safeParse(payload);
        if (
          !parsed.success ||
          !(await conversations.isMember(auth.userId, parsed.data.conversationId))
        ) {
          acknowledge?.({ ok: false });
          return;
        }
        await socket.join(`conversation:${parsed.data.conversationId}`);
        acknowledge?.({ ok: true });
      });

      socket.on('conversation:leave', async (payload: unknown) => {
        const parsed = conversationPayloadSchema.safeParse(payload);
        if (parsed.success) {
          await socket.leave(`conversation:${parsed.data.conversationId}`);
        }
      });

      const relayTyping = async (
        event: 'typing:start' | 'typing:stop',
        payload: unknown,
      ): Promise<void> => {
        const parsed = conversationPayloadSchema.safeParse(payload);
        const now = Date.now();
        if (!parsed.success || now - lastTypingEventAt < 300) {
          return;
        }
        lastTypingEventAt = now;
        const recipients = await conversations.listTypingRecipients(
          auth.userId,
          parsed.data.conversationId,
        );
        for (const userId of recipients) {
          this.io.to(`user:${userId}`).emit(event, {
            conversationId: parsed.data.conversationId,
            userId: auth.userId,
          });
        }
      };

      socket.on('typing:start', (payload) => {
        void relayTyping('typing:start', payload);
      });
      socket.on('typing:stop', (payload) => {
        void relayTyping('typing:stop', payload);
      });

      socket.on('call:start', (payload, acknowledge) => {
        const parsed = conversationPayloadSchema.safeParse(payload);
        if (!parsed.success) {
          acknowledge?.({ ok: false, error: 'INVALID_REQUEST' });
          return;
        }
        void calls
          .start(auth.userId, parsed.data.conversationId)
          .then((call) => {
            socketCallIds.add(call.id);
            this.emitToUsers(
              call.participantUserIds.filter((userId) => userId !== auth.userId),
              'call:incoming',
              { ...call },
            );
            acknowledge?.({ ok: true, call });
          })
          .catch((error: unknown) => {
            acknowledge?.({ ok: false, error: callErrorCode(error) });
          });
      });

      const transitionCall = (
        action: 'accept' | 'decline' | 'end',
        event: 'call:accepted' | 'call:declined' | 'call:ended',
        payload: unknown,
        acknowledge?: (result: CallAcknowledge) => void,
      ): void => {
        const parsed = callPayloadSchema.safeParse(payload);
        if (!parsed.success) {
          acknowledge?.({ ok: false, error: 'INVALID_REQUEST' });
          return;
        }
        void calls[action](auth.userId, parsed.data.callId)
          .then((call) => {
            if (action === 'accept') {
              socketCallIds.add(call.id);
            } else {
              socketCallIds.delete(call.id);
            }
            this.emitToUsers(call.participantUserIds, event, {
              ...call,
              actionDeviceId: auth.deviceId,
            });
            acknowledge?.({ ok: true, call });
          })
          .catch((error: unknown) => {
            acknowledge?.({ ok: false, error: callErrorCode(error) });
          });
      };

      socket.on('call:accept', (payload, acknowledge) => {
        transitionCall('accept', 'call:accepted', payload, acknowledge);
      });
      socket.on('call:decline', (payload, acknowledge) => {
        transitionCall('decline', 'call:declined', payload, acknowledge);
      });
      socket.on('call:end', (payload, acknowledge) => {
        transitionCall('end', 'call:ended', payload, acknowledge);
      });

      const withinSignalRate = (): boolean => {
        const now = Date.now();
        if (now - signalWindowStartedAt >= 1_000) {
          signalWindowStartedAt = now;
          signalCount = 0;
        }
        signalCount += 1;
        return signalCount <= 120;
      };

      const relaySignal = async (
        event:
          | 'webrtc:offer'
          | 'webrtc:answer'
          | 'webrtc:ice-candidate'
          | 'webrtc:key-offer'
          | 'webrtc:key-answer',
        payload: {
          callId: string;
          description?: unknown;
          candidate?: unknown;
          exchangeId?: string;
          ephemeralPublicKey?: string;
        },
      ): Promise<void> => {
        if (!withinSignalRate()) {
          return;
        }
        const recipients = await calls.getRelayRecipients(auth.userId, payload.callId);
        for (const userId of recipients) {
          this.io.to(`user:${userId}`).emit(event, {
            ...payload,
            fromUserId: auth.userId,
            fromDeviceId: auth.deviceId,
          });
        }
      };

      socket.on('webrtc:offer', (payload) => {
        const parsed = offerSchema.safeParse(payload);
        if (parsed.success) {
          void relaySignal('webrtc:offer', parsed.data).catch(() => undefined);
        }
      });
      socket.on('webrtc:answer', (payload) => {
        const parsed = answerSchema.safeParse(payload);
        if (parsed.success) {
          void relaySignal('webrtc:answer', parsed.data).catch(() => undefined);
        }
      });
      socket.on('webrtc:ice-candidate', (payload) => {
        const parsed = iceCandidateSchema.safeParse(payload);
        if (parsed.success) {
          void relaySignal('webrtc:ice-candidate', parsed.data).catch(() => undefined);
        }
      });
      socket.on('webrtc:key-offer', (payload) => {
        const parsed = keyExchangeSchema.safeParse(payload);
        if (parsed.success) {
          void relaySignal('webrtc:key-offer', parsed.data).catch(() => undefined);
        }
      });
      socket.on('webrtc:key-answer', (payload) => {
        const parsed = keyExchangeSchema.safeParse(payload);
        if (parsed.success) {
          void relaySignal('webrtc:key-answer', parsed.data).catch(() => undefined);
        }
      });

      socket.on('disconnect', () => {
        for (const callId of socketCallIds) {
          void calls
            .end(auth.userId, callId)
            .then((call) => {
              this.emitToUsers(call.participantUserIds, 'call:ended', { ...call });
            })
            .catch(() => undefined);
        }
        socketCallIds.clear();
      });
    });
  }

  emitToUsers(
    userIds: string[],
    event: RealtimeEvent,
    payload: Record<string, unknown>,
  ): void {
    for (const userId of new Set(userIds)) {
      this.io.to(`user:${userId}`).emit(event, payload);
    }
  }

  async close(): Promise<void> {
    await this.io.close();
  }
}
