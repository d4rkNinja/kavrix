import { SyncProtocolError, SyncTransportFailure } from '@kavrix/sync';

import { SecureFetchFailure } from './secure-fetch.js';

export function throwMappedSecureFetchError(error: unknown): never {
  if (!(error instanceof SecureFetchFailure)) throw error;
  if (error.kind === 'protocol') throw new SyncProtocolError();
  if (error.kind === 'unauthorized') throw new SyncTransportFailure('unauthorized');
  if (error.kind === 'forbidden') throw new SyncTransportFailure('device-revoked');
  if (error.kind === 'conflict') throw new SyncTransportFailure('conflict');
  if (error.kind === 'timeout') throw new SyncTransportFailure('timeout');
  if (error.kind === 'rate-limited') {
    throw new SyncTransportFailure('rate-limited', error.retryAfterMs);
  }
  if (error.kind === 'server') throw new SyncTransportFailure('server');
  if (error.kind === 'offline') throw new SyncTransportFailure('offline');
  throw new SyncTransportFailure('client');
}
