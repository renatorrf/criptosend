import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import Fastify, {
  LogController,
  type FastifyError,
  type FastifyInstance,
} from 'fastify';

import { registerAuthRoutes } from './auth/auth-routes.js';
import { registerAccountAccessRoutes } from './auth/account-access-routes.js';
import { registerPlatformAccessRoutes } from './auth/platform-access-routes.js';
import {
  createVerificationProvider,
  type VerificationProvider,
} from './auth/verification-provider.js';
import { registerCallRoutes } from './calls/call-routes.js';
import { CallService } from './calls/call-service.js';
import { CallTimeoutTask } from './calls/call-timeout-task.js';
import { env } from './config/env.js';
import { registerConversationRoutes } from './conversations/conversation-routes.js';
import { ConversationService } from './conversations/conversation-service.js';
import { AppError } from './http/app-error.js';
import { registerKeyRoutes } from './keys/key-routes.js';
import { registerMessageRoutes } from './messages/message-routes.js';
import { MessageExpirationTask } from './messages/message-expiration-task.js';
import { MessageService } from './messages/message-service.js';
import { RealtimeHub } from './realtime/realtime-hub.js';
import { healthRoutes } from './routes/health.js';
import { registerUserRoutes } from './users/user-routes.js';

interface BuildAppOptions {
  verificationProvider?: VerificationProvider;
}

export async function buildApp(
  options: BuildAppOptions = {},
): Promise<FastifyInstance> {
  const app = Fastify({
    logger: {
      level: env.NODE_ENV === 'production' ? 'info' : 'debug',
      redact: {
        paths: [
          'req.headers.authorization',
          'req.headers.cookie',
          'res.headers.set-cookie',
          '*.phone',
          '*.message',
          '*.ciphertext',
          '*.token',
          '*.pin',
          '*.password',
          '*.code',
          '*.testCode',
          '*.identityPublicKey',
          '*.publicKey',
          '*.ephemeralPublicKey',
          '*.signature',
          '*.sdp',
          '*.candidate',
          '*.credential',
        ],
        censor: '[REDACTED]',
      },
    },
    logController: new LogController({ disableRequestLogging: true }),
  });

  await app.register(helmet, {
    contentSecurityPolicy: false,
  });
  await app.register(cors, {
    credentials: true,
    methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    origin: (origin, callback) => {
      if (!origin || env.APP_ORIGINS.includes(origin)) {
        callback(null, true);
        return;
      }

      callback(null, false);
    },
  });
  await app.register(healthRoutes);
  const verificationProvider =
    options.verificationProvider ?? createVerificationProvider();
  const authService = await registerAuthRoutes(
    app,
    verificationProvider,
  );
  registerAccountAccessRoutes(app, verificationProvider);
  registerPlatformAccessRoutes(app, authService);
  registerKeyRoutes(app, authService);
  registerUserRoutes(app, authService);
  const conversations = new ConversationService();
  const calls = new CallService(conversations);
  const realtime = new RealtimeHub(app.server, authService, conversations, calls);
  const messages = new MessageService(conversations);
  const expirationTask = new MessageExpirationTask(
    messages,
    conversations,
    realtime,
    app.log,
  );
  const callTimeoutTask = new CallTimeoutTask(calls, realtime, app.log);
  registerConversationRoutes(app, authService, conversations, realtime);
  registerMessageRoutes(app, authService, conversations, realtime, messages);
  registerCallRoutes(app, authService, calls);
  expirationTask.start();
  callTimeoutTask.start();
  app.addHook('onClose', async () => {
    expirationTask.stop();
    callTimeoutTask.stop();
    await realtime.close();
  });

  app.setErrorHandler((error: FastifyError, request, reply) => {
    if (error instanceof AppError) {
      if (error.statusCode >= 500) {
        request.log.error({ errorCode: error.code }, 'REQUEST_FAILED');
      }
      void reply.code(error.statusCode).send({
        error: error.code,
        requestId: request.id,
      });
      return;
    }

    request.log.error({ err: { name: error.name } }, 'REQUEST_FAILED');
    void reply.code(500).send({
      error: 'INTERNAL_SERVER_ERROR',
      requestId: request.id,
    });
  });

  return app;
}
