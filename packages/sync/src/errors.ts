import type { RetryClassification } from './types.js';

export type SyncTransportFailureKind =
  | 'offline'
  | 'timeout'
  | 'rate-limited'
  | 'server'
  | 'unauthorized'
  | 'device-revoked'
  | 'conflict'
  | 'client';

export class SyncTransportFailure extends Error {
  readonly kind: SyncTransportFailureKind;
  readonly retryAfterMs: number | undefined;

  constructor(kind: SyncTransportFailureKind, retryAfterMs?: number) {
    super('The sync transport failed.');
    this.name = 'SyncTransportFailure';
    this.kind = kind;
    this.retryAfterMs = retryAfterMs;
  }
}

export class SyncProtocolError extends Error {
  constructor() {
    super('The sync service returned an invalid response.');
    this.name = 'SyncProtocolError';
  }
}

export class SyncRollbackError extends Error {
  constructor() {
    super('The server presented an older vault revision.');
    this.name = 'SyncRollbackError';
  }
}

export class SyncLocalStateError extends Error {
  constructor() {
    super('Protected or resumable local sync state is invalid.');
    this.name = 'SyncLocalStateError';
  }
}

export function classifySyncFailure(error: unknown): RetryClassification {
  if (error instanceof SyncTransportFailure) {
    switch (error.kind) {
      case 'offline':
        return { state: 'offline', code: 'network-unavailable', retryable: true };
      case 'timeout':
        return { state: 'error', code: 'transport-timeout', retryable: true };
      case 'rate-limited':
        return error.retryAfterMs === undefined
          ? { state: 'error', code: 'rate-limited', retryable: true }
          : {
              state: 'error',
              code: 'rate-limited',
              retryable: true,
              retryAfterMs: error.retryAfterMs,
            };
      case 'server':
        return { state: 'error', code: 'service-unavailable', retryable: true };
      case 'unauthorized':
        return { state: 'error', code: 'authorization-failed', retryable: false };
      case 'device-revoked':
        return { state: 'error', code: 'device-revoked', retryable: false };
      case 'conflict':
        return {
          state: 'error',
          code: 'atomic-publication-conflict',
          retryable: false,
        };
      case 'client':
        return { state: 'error', code: 'request-rejected', retryable: false };
    }
  }
  if (error instanceof SyncProtocolError) {
    return { state: 'error', code: 'protocol-invalid', retryable: false };
  }
  if (error instanceof SyncRollbackError) {
    return { state: 'error', code: 'rollback-detected', retryable: false };
  }
  if (error instanceof SyncLocalStateError) {
    return { state: 'error', code: 'local-state-invalid', retryable: false };
  }
  return { state: 'error', code: 'unexpected', retryable: false };
}
