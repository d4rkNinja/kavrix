export type DomainErrorCode =
  | 'VAULT_LOCKED'
  | 'UNLOCK_FAILED'
  | 'CRYPTO_AUTHENTICATION_FAILED'
  | 'KEY_VERSION_UNSUPPORTED'
  | 'SYNC_CONFLICT'
  | 'NETWORK_UNAVAILABLE'
  | 'DEVICE_REVOKED'
  | 'VALIDATION_FAILED'
  | 'NOT_FOUND'
  | 'AMBIGUOUS_NAME'
  | 'PERMISSION_DENIED'
  | 'BACKUP_CORRUPTED'
  | 'SCHEMA_MIGRATION_FAILED'
  | 'LAST_UNLOCK_SLOT';

export abstract class DomainError extends Error {
  abstract readonly code: DomainErrorCode;
  readonly safe = true;

  protected constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class VaultLockedError extends DomainError {
  readonly code = 'VAULT_LOCKED' as const;
  constructor() {
    super('The vault is locked. Unlock it and retry.');
  }
}

export class WrongPassphraseError extends DomainError {
  readonly code = 'UNLOCK_FAILED' as const;
  constructor() {
    super('The vault could not be unlocked with the supplied credential.');
  }
}

export class CryptoAuthenticationError extends DomainError {
  readonly code = 'CRYPTO_AUTHENTICATION_FAILED' as const;
  constructor(options?: ErrorOptions) {
    super('Encrypted data could not be authenticated.', options);
  }
}

export class KeyVersionUnsupportedError extends DomainError {
  readonly code = 'KEY_VERSION_UNSUPPORTED' as const;
  constructor() {
    super('This key version is not supported. Upgrade the client and retry.');
  }
}

export class SyncConflictError extends DomainError {
  readonly code = 'SYNC_CONFLICT' as const;
  constructor() {
    super(
      'This record changed on another device. Resolve the conflict before continuing.',
    );
  }
}

export class NetworkUnavailableError extends DomainError {
  readonly code = 'NETWORK_UNAVAILABLE' as const;
  constructor(options?: ErrorOptions) {
    super('The sync service is unavailable. Check the connection and retry.', options);
  }
}

export class DeviceRevokedError extends DomainError {
  readonly code = 'DEVICE_REVOKED' as const;
  constructor() {
    super('This device is no longer authorized for the vault.');
  }
}

export class ValidationError extends DomainError {
  readonly code = 'VALIDATION_FAILED' as const;
  constructor(message = 'The supplied data is invalid.', options?: ErrorOptions) {
    super(message, options);
  }
}

export class NotFoundError extends DomainError {
  readonly code = 'NOT_FOUND' as const;
  constructor() {
    super('No matching record was found.');
  }
}

export class AmbiguousNameError extends DomainError {
  readonly code = 'AMBIGUOUS_NAME' as const;
  readonly candidateIds: readonly string[];

  constructor(candidateIds: readonly string[]) {
    super('More than one record matches. Use an opaque ID or a unique alias.');
    this.candidateIds = Object.freeze([...candidateIds]);
  }
}

export class PermissionError extends DomainError {
  readonly code = 'PERMISSION_DENIED' as const;
  constructor() {
    super('The operation was refused because secure access requirements were not met.');
  }
}

export class BackupCorruptedError extends DomainError {
  readonly code = 'BACKUP_CORRUPTED' as const;
  constructor(options?: ErrorOptions) {
    super('The backup is invalid or could not be authenticated.', options);
  }
}

export class SchemaMigrationError extends DomainError {
  readonly code = 'SCHEMA_MIGRATION_FAILED' as const;
  constructor(
    message = 'The template migration could not be applied safely.',
    options?: ErrorOptions,
  ) {
    super(message, options);
  }
}

export class LastUnlockSlotError extends DomainError {
  readonly code = 'LAST_UNLOCK_SLOT' as const;
  constructor() {
    super('The last active unlock method cannot be revoked.');
  }
}
