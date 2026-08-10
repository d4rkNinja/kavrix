export class VaultSessionConcurrencyError extends Error {
  readonly safe = true;

  constructor() {
    super('Another vault session operation is already in progress.');
    this.name = 'VaultSessionConcurrencyError';
  }
}

export class OpaqueSnapshotCapacityError extends Error {
  readonly safe = true;

  constructor() {
    super('The in-memory opaque snapshot exceeded its configured capacity.');
    this.name = 'OpaqueSnapshotCapacityError';
  }
}

export type ControlPlaneFailureKind =
  | 'protocol'
  | 'timeout'
  | 'aborted'
  | 'offline'
  | 'unauthorized'
  | 'forbidden'
  | 'not-found'
  | 'conflict'
  | 'rate-limited'
  | 'server'
  | 'client';

export class ControlPlaneFailure extends Error {
  readonly safe = true;
  readonly kind: ControlPlaneFailureKind;
  readonly retryAfterMs: number | undefined;

  constructor(kind: ControlPlaneFailureKind, retryAfterMs?: number) {
    super('The control-plane request failed.');
    this.name = 'ControlPlaneFailure';
    this.kind = kind;
    this.retryAfterMs = retryAfterMs;
  }
}

export class PortableKeyValidationError extends Error {
  readonly safe = true;

  constructor() {
    super('Portable key validation failed.');
    this.name = 'PortableKeyValidationError';
  }
}

export type VaultLifecycleFailureKind =
  | 'invalid-input'
  | 'confirmation-failed'
  | 'operation-unavailable'
  | 'operation-busy'
  | 'restart-required'
  | 'unsafe-cancel'
  | 'expired'
  | 'protected-storage'
  | 'profile'
  | 'journal'
  | 'protocol';

export class VaultLifecycleError extends Error {
  readonly safe = true;
  readonly kind: VaultLifecycleFailureKind;

  constructor(kind: VaultLifecycleFailureKind) {
    super('The vault lifecycle operation failed.');
    this.name = 'VaultLifecycleError';
    this.kind = kind;
  }
}

export type VaultClientSessionFailureKind =
  | 'invalid-input'
  | 'authentication'
  | 'protocol'
  | 'locked'
  | 'concurrency'
  | 'terminal-sync'
  | 'clipboard'
  | 'network-unavailable'
  | 'rate-limited'
  | 'server-unavailable';

export class VaultClientSessionError extends Error {
  readonly safe = true;
  readonly kind: VaultClientSessionFailureKind;
  readonly retryable: boolean;
  readonly retryAfterMs: number | undefined;

  constructor(kind: VaultClientSessionFailureKind, retryAfterMs?: number) {
    super('The vault session operation failed.');
    this.name = 'VaultClientSessionError';
    this.kind = kind;
    this.retryable =
      kind === 'network-unavailable' ||
      kind === 'rate-limited' ||
      kind === 'server-unavailable';
    this.retryAfterMs = kind === 'rate-limited' ? retryAfterMs : undefined;
  }
}

export type CredentialCopyFailureKind =
  | 'missing'
  | 'empty'
  | 'inapplicable'
  | 'unreadable'
  | 'orphaned'
  | 'not-copyable'
  | 'index-required'
  | 'index-inapplicable'
  | 'index-out-of-range'
  | 'used'
  | 'authorization-required'
  | 'authorization-denied'
  | 'authorization-failed'
  | 'clipboard-failed';

export class CredentialCopyError extends Error {
  readonly safe = true;
  readonly kind: CredentialCopyFailureKind;

  constructor(kind: CredentialCopyFailureKind) {
    super(copyFailureMessage(kind));
    this.name = 'CredentialCopyError';
    this.kind = kind;
  }
}

function copyFailureMessage(kind: CredentialCopyFailureKind): string {
  switch (kind) {
    case 'missing':
      return 'The selected field is missing.';
    case 'empty':
      return 'The selected field is empty.';
    case 'inapplicable':
      return 'The selected field is inapplicable.';
    case 'unreadable':
      return 'The selected field is unreadable.';
    case 'orphaned':
      return 'Archived or orphaned fields cannot be copied.';
    case 'not-copyable':
      return 'The selected field cannot be copied.';
    case 'index-required':
      return 'A repeatable field requires an element index.';
    case 'index-inapplicable':
      return 'An element index applies only to a repeatable field.';
    case 'index-out-of-range':
      return 'The element index is outside the available range.';
    case 'used':
      return 'The selected one-time element is no longer available.';
    case 'authorization-required':
      return 'Copy authorization is required.';
    case 'authorization-denied':
      return 'Copy authorization was denied.';
    case 'authorization-failed':
      return 'Copy authorization failed.';
    case 'clipboard-failed':
      return 'The clipboard operation failed.';
  }
}
