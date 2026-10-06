import type { FastifyBaseLogger } from 'fastify';

import type { RealtimeHub } from '../realtime/realtime-hub.js';
import type { CallService } from './call-service.js';

export class CallTimeoutTask {
  private timer: NodeJS.Timeout | null = null;

  constructor(
    private readonly calls: CallService,
    private readonly realtime: RealtimeHub,
    private readonly logger: FastifyBaseLogger,
  ) {}

  start(): void {
    this.timer = setInterval(() => {
      void this.run();
    }, 5_000);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private async run(): Promise<void> {
    try {
      for (const call of await this.calls.expireRinging()) {
        this.realtime.emitToUsers(call.participantUserIds, 'call:ended', { ...call });
      }
    } catch (error) {
      this.logger.error(
        { err: { name: error instanceof Error ? error.name : 'Error' } },
        'CALL_TIMEOUT_FAILED',
      );
    }
  }
}
