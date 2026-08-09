import { describe, expect, it } from 'vitest';

import {
  AmbiguousNameError,
  BackupCorruptedError,
  CryptoAuthenticationError,
  DeviceRevokedError,
  KeyVersionUnsupportedError,
  LastUnlockSlotError,
  NetworkUnavailableError,
  NotFoundError,
  PermissionError,
  SchemaMigrationError,
  SyncConflictError,
  ValidationError,
  VaultLockedError,
  WrongPassphraseError,
} from '../src/index.js';

describe('safe domain errors', () => {
  it('exposes stable codes and safe messages for every public failure category', () => {
    const errors = [
      new VaultLockedError(),
      new WrongPassphraseError(),
      new CryptoAuthenticationError(),
      new KeyVersionUnsupportedError(),
      new SyncConflictError(),
      new NetworkUnavailableError(),
      new DeviceRevokedError(),
      new ValidationError(),
      new NotFoundError(),
      new PermissionError(),
      new BackupCorruptedError(),
      new SchemaMigrationError(),
      new LastUnlockSlotError(),
    ];
    expect(errors.map(({ code }) => code)).toEqual([
      'VAULT_LOCKED',
      'UNLOCK_FAILED',
      'CRYPTO_AUTHENTICATION_FAILED',
      'KEY_VERSION_UNSUPPORTED',
      'SYNC_CONFLICT',
      'NETWORK_UNAVAILABLE',
      'DEVICE_REVOKED',
      'VALIDATION_FAILED',
      'NOT_FOUND',
      'PERMISSION_DENIED',
      'BACKUP_CORRUPTED',
      'SCHEMA_MIGRATION_FAILED',
      'LAST_UNLOCK_SLOT',
    ]);
    expect(errors.every((error) => error.name === error.constructor.name)).toBe(true);
  });

  it('preserves causes without leaking them into public messages', () => {
    const canary = new Error('secret-cause-canary');
    const errors = [
      new CryptoAuthenticationError({ cause: canary }),
      new NetworkUnavailableError({ cause: canary }),
      new BackupCorruptedError({ cause: canary }),
      new ValidationError('Safe validation message', { cause: canary }),
      new SchemaMigrationError('Safe migration message', { cause: canary }),
    ];
    expect(errors.every((error) => error.cause === canary)).toBe(true);
    expect(errors.every((error) => !error.message.includes(canary.message))).toBe(true);
  });

  it('defensively copies ambiguous candidates', () => {
    const candidates = ['group.1', 'group.2'];
    const error = new AmbiguousNameError(candidates);
    candidates.push('group.3');
    expect(error.code).toBe('AMBIGUOUS_NAME');
    expect(error.candidateIds).toEqual(['group.1', 'group.2']);
    expect(Object.isFrozen(error.candidateIds)).toBe(true);
  });
});
