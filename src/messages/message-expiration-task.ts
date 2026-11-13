import type { FastifyBaseLogger } from 'fastify';

import type { ConversationService } from '../conversations/conversation-service.js';
import type { RealtimeHub } from '../realtime/realtime-hub.js';
import type { MessageService } from './message-service.js';

export class MessageExpirationTask {
  private timer: NodeJS.Timeout | null = null;
  private running = false;

  constructor(
    private readonly messages: MessageService,
    private readonly conversations: ConversationService,
    private readonly realtime: RealtimeHub,
    private readonly logger: FastifyBaseLogger,
  ) {}

  start(): void {
    this.timer = setInterval(() => {
      void this.run();
    }, 30_000);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private async run(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      const expired = await this.messages.expireDue();
      for (const message of expired) {
        const memberIds = await this.conversations.listMemberUserIds(
          message.conversationId,
        );
        this.realtime.emitToUsers(memberIds, 'message:deleted', {
          id: message.id,
          conversationId: message.conversationId,
          reason: 'EXPIRED',
        });
      }
    } catch (error) {
      this.logger.error(
        { err: { name: error instanceof Error ? error.name : 'Error' } },
        'MESSAGE_EXPIRATION_FAILED',
      );
    }
    try {
      await this.messages.protectStoredEnvelopes();
    } catch {
      this.logger.error('MESSAGE_ENVELOPE_BACKFILL_FAILED');
    } finally {
      this.running = false;
    }
  }
}
