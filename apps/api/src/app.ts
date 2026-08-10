import Fastify, { type FastifyInstance } from 'fastify';

import { apiErrorResponseSchema } from '@kavrix/schemas';

import { rejectSecretFields } from './boundary.js';
import {
  ApiAttachmentConflictError,
  ApiAtomicPublicationConflictError,
  ApiAuthenticationError,
  ApiAuthorizationError,
  ApiConflictError,
  ApiHttpsRequiredError,
  ApiNotFoundError,
  ApiRateLimitError,
  ApiUnsupportedMediaTypeError,
  ApiValidationError,
} from './errors.js';
import type { ApiPorts } from './ports.js';
import type { RouteContext } from './route-context.js';
import { bootstrapRoutes } from './routes/bootstrap.js';
import { attachmentRoutes } from './routes/attachments.js';
import { deviceRoutes } from './routes/devices.js';
import { enrollmentRoutes } from './routes/enrollment.js';
import { healthRoutes } from './routes/health.js';
import { syncRoutes } from './routes/sync.js';
import { vaultRoutes } from './routes/vaults.js';
import { RequestSecurity, type ApiRatePolicy } from './security.js';
import { isExplicitIpOrCidr } from './trusted-proxy.js';

const DEFAULT_BODY_LIMIT = 24 * 1024 * 1024;

export interface BuildApiOptions {
  readonly ports: ApiPorts;
  readonly environment: 'development' | 'production' | 'test';
  readonly logStream?: { write(message: string): void };
  readonly bodyLimit?: number;
  readonly authenticatedRatePolicy?: ApiRatePolicy;
  readonly anonymousRatePolicy?: ApiRatePolicy;
  readonly sourceRatePolicy?: ApiRatePolicy;
  readonly enrollmentLifetimeSeconds?: number;
  readonly trustedProxy?: string | string[];
  readonly vaultBootstrapEnabled?: boolean;
}

export function buildApi(options: BuildApiOptions): FastifyInstance {
  assertTrustedProxy(options.trustedProxy);
  const bodyLimit = options.bodyLimit ?? DEFAULT_BODY_LIMIT;
  const authenticatedPolicy =
    options.authenticatedRatePolicy ?? ({ limit: 120, windowSeconds: 60 } as const);
  const anonymousPolicy =
    options.anonymousRatePolicy ?? ({ limit: 10, windowSeconds: 60 } as const);
  const sourcePolicy =
    options.sourceRatePolicy ?? ({ limit: 600, windowSeconds: 60 } as const);
  const enrollmentLifetimeSeconds = options.enrollmentLifetimeSeconds ?? 600;
  assertPositiveInteger(bodyLimit, 'body limit');
  assertRatePolicy(authenticatedPolicy);
  assertRatePolicy(anonymousPolicy);
  assertRatePolicy(sourcePolicy);
  if (
    !Number.isSafeInteger(enrollmentLifetimeSeconds) ||
    enrollmentLifetimeSeconds < 60 ||
    enrollmentLifetimeSeconds > 86_400
  ) {
    throw new Error('Enrollment lifetime must be between 60 and 86400 seconds');
  }
  const loggingEnabled =
    options.environment === 'production' || options.logStream !== undefined;
  const app = Fastify({
    bodyLimit,
    trustProxy: options.trustedProxy ?? false,
    logger: loggingEnabled
      ? {
          level: 'info',
          ...(options.logStream === undefined ? {} : { stream: options.logStream }),
          redact: {
            paths: [
              'req.headers.authorization',
              'req.headers.x-kavrix-successor-token',
              'request.headers.authorization',
              'request.headers.x-kavrix-successor-token',
              'headers.authorization',
              'headers.x-kavrix-successor-token',
            ],
            censor: '[REDACTED]',
          },
        }
      : false,
  });
  const security = new RequestSecurity(
    options.ports,
    authenticatedPolicy,
    anonymousPolicy,
    sourcePolicy,
  );
  const context: RouteContext = {
    ports: options.ports,
    security,
    enrollmentLifetimeSeconds,
  };

  app.addHook('onRequest', async (request, reply) => {
    reply.header('cache-control', 'no-store');
    await security.consumeSource(request);
    if (options.environment === 'production' && request.protocol !== 'https') {
      throw new ApiHttpsRequiredError();
    }
  });
  app.addHook('preValidation', (request, _reply, done) => {
    if (
      request.body !== undefined &&
      request.headers['content-type']?.split(';', 1)[0]?.trim().toLowerCase() !==
        'application/json'
    ) {
      done(new ApiUnsupportedMediaTypeError());
      return;
    }
    rejectSecretFields(request.body);
    done();
  });

  app.setNotFoundHandler((_request, reply) =>
    reply.status(404).send(
      apiErrorResponseSchema.parse({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      }),
    ),
  );
  app.setErrorHandler((error, request, reply) => {
    const mapped = mapError(error);
    if (mapped.statusCode >= 500) {
      request.log.error(
        { errorName: error instanceof Error ? error.name : 'UnknownError' },
        'request failed',
      );
    } else {
      request.log.warn(
        { code: mapped.body.error.code, statusCode: mapped.statusCode },
        'request rejected',
      );
    }
    return reply
      .status(mapped.statusCode)
      .send(apiErrorResponseSchema.parse(mapped.body));
  });

  void app.register(healthRoutes, context);
  if (options.vaultBootstrapEnabled === true) {
    void app.register(bootstrapRoutes, context);
  }
  void app.register(enrollmentRoutes, context);
  void app.register(vaultRoutes, context);
  void app.register(syncRoutes, context);
  void app.register(attachmentRoutes, context);
  void app.register(deviceRoutes, context);
  return app;
}

interface ApiErrorBody {
  readonly error: {
    readonly code: string;
    readonly message: string;
    readonly conflict?: {
      readonly entityType: 'vault' | 'group' | 'item' | 'attachment';
      readonly entityId: string;
      readonly expectedRevision: number | null;
      readonly currentRevision: number | null;
    };
  };
}

function mapError(error: unknown): {
  readonly statusCode: number;
  readonly body: ApiErrorBody;
} {
  if (error instanceof ApiAuthenticationError) {
    return response(401, 'AUTHENTICATION_FAILED', 'Authentication failed');
  }
  if (error instanceof ApiAuthorizationError) {
    return response(403, 'AUTHORIZATION_FAILED', 'Authorization failed');
  }
  if (error instanceof ApiValidationError) {
    return response(400, 'VALIDATION_FAILED', 'Request validation failed');
  }
  if (error instanceof ApiNotFoundError) {
    return response(404, 'NOT_FOUND', 'Resource not found');
  }
  if (error instanceof ApiRateLimitError) {
    return response(429, 'RATE_LIMITED', 'Rate limit exceeded');
  }
  if (error instanceof ApiHttpsRequiredError) {
    return response(426, 'HTTPS_REQUIRED', 'HTTPS is required');
  }
  if (error instanceof ApiUnsupportedMediaTypeError) {
    return response(415, 'UNSUPPORTED_MEDIA_TYPE', 'Unsupported media type');
  }
  if (error instanceof ApiAtomicPublicationConflictError) {
    return response(
      409,
      'SYNC_CONFLICT',
      'The opaque migration publication has a revision conflict',
    );
  }
  if (error instanceof ApiAttachmentConflictError) {
    return response(409, 'ATTACHMENT_CONFLICT', 'The attachment stream has a conflict');
  }
  if (error instanceof ApiConflictError) {
    return {
      statusCode: 409,
      body: {
        error: {
          code: 'SYNC_CONFLICT',
          message: 'The opaque record has a revision conflict',
          conflict: {
            entityType: error.entityType,
            entityId: error.entityId,
            expectedRevision: error.expectedRevision,
            currentRevision: error.currentRevision,
          },
        },
      },
    };
  }
  if (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'FST_ERR_CTP_BODY_TOO_LARGE'
  ) {
    return response(413, 'BODY_TOO_LARGE', 'Request body is too large');
  }
  if (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'FST_ERR_CTP_INVALID_JSON_BODY'
  ) {
    return response(400, 'VALIDATION_FAILED', 'Request validation failed');
  }
  if (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    error.code === 'FST_ERR_CTP_INVALID_MEDIA_TYPE'
  ) {
    return response(415, 'UNSUPPORTED_MEDIA_TYPE', 'Unsupported media type');
  }
  return response(500, 'INTERNAL_ERROR', 'Internal server error');
}

function response(
  statusCode: number,
  code: string,
  message: string,
): { readonly statusCode: number; readonly body: ApiErrorBody } {
  return { statusCode, body: { error: { code, message } } };
}

function assertRatePolicy(policy: ApiRatePolicy): void {
  assertPositiveInteger(policy.limit, 'rate limit');
  assertPositiveInteger(policy.windowSeconds, 'rate window');
}

function assertPositiveInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${name} must be a positive safe integer`);
  }
}

function assertTrustedProxy(
  value: unknown,
): asserts value is string | string[] | undefined {
  if (value === undefined) return;
  const entries = typeof value === 'string' ? [value] : value;
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error('Trusted proxies must be explicit IP addresses or CIDR ranges');
  }
  for (const entry of entries) {
    if (typeof entry !== 'string' || !isExplicitIpOrCidr(entry)) {
      throw new Error('Trusted proxies must be explicit IP addresses or CIDR ranges');
    }
  }
}
