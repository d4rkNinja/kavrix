import { SyncLocalStateError } from '@kavrix/sync';

export function invalidState(): SyncLocalStateError {
  return new SyncLocalStateError();
}

export function normalizeFailure(error: unknown): SyncLocalStateError {
  return error instanceof SyncLocalStateError ? error : invalidState();
}
