import { DomainError } from '@kavrix/core';

import type { BackupErrorCode } from '@kavrix/import-export';
import type { SessionExpiryReason } from '@kavrix/schemas';
import { CliUnsupportedRuntimeError } from './runtime-preflight.js';

export const CLI_EXIT_CODES = Object.freeze({
  success: 0,
  failure: 1,
  usage: 2,
  notFound: 3,
  ambiguous: 4,
  unavailable: 5,
} as const);

export type CliFeature =
  | 'status'
  | 'unlock'
  | 'lock'
  | 'show'
  | 'copy'
  | 'init'
  | 'totp'
  | 'totp code'
  | 'key create'
  | 'key slot list'
  | 'key slot create'
  | 'key slot disable'
  | 'key slot revoke'
  | 'key rotate'
  | 'key rotate resume'
  | 'key rotate list'
  | 'key rekey'
  | 'device invite create'
  | 'device invite list'
  | 'device invite revoke'
  | 'device invite join'
  | 'device list'
  | 'device revoke'
  | 'device remember'
  | 'device forget'
  | 'device join'
  | 'template'
  | 'template list'
  | 'template inspect'
  | 'template create'
  | 'template edit'
  | 'template archive'
  | 'template restore'
  | 'template delete'
  | 'template migrate'
  | 'template migrate plan'
  | 'template migrate apply'
  | 'template migrate status'
  | 'group'
  | 'group create'
  | 'group list'
  | 'group rename'
  | 'group archive'
  | 'group restore'
  | 'group delete'
  | 'credential create'
  | 'credential list'
  | 'credential rename'
  | 'credential archive'
  | 'credential restore'
  | 'credential delete'
  | 'field add'
  | 'field set'
  | 'field generate'
  | 'field update'
  | 'field archive'
  | 'field restore'
  | 'field remove'
  | 'note add'
  | 'note list'
  | 'note update'
  | 'note archive'
  | 'note restore'
  | 'note remove'
  | 'reference'
  | 'reference list'
  | 'reference add'
  | 'reference remove'
  | 'purge'
  | 'purge preview'
  | 'purge fields'
  | 'purge notes'
  | 'attachment'
  | 'attachment list'
  | 'attachment upload'
  | 'attachment download'
  | 'attachment delete'
  | 'history'
  | 'history list'
  | 'history show'
  | 'history diff'
  | 'history restore'
  | 'audit'
  | 'audit list'
  | 'audit show'
  | 'recovery'
  | 'recovery list'
  | 'recovery use'
  | 'recovery reveal'
  | 'recovery copy'
  | 'run'
  | 'reveal'
  | 'search'
  | 'get'
  | 'set'
  | 'update'
  | 'sync'
  | 'sync conflicts list'
  | 'sync conflicts resolve'
  | 'connect'
  | 'recover'
  | 'backup create'
  | 'backup verify'
  | 'backup restore'
  | 'transfer export'
  | 'transfer import';

export class CliUsageError extends Error {
  readonly code = 'CLI_USAGE' as const;
  readonly safe = true;

  constructor(message: string) {
    super(message);
    this.name = 'CliUsageError';
  }
}

export class CliUnavailableError extends Error {
  readonly code = 'CLI_UNAVAILABLE' as const;
  readonly safe = true;
  readonly feature: CliFeature;

  constructor(feature: CliFeature) {
    super(
      `${feature} is unavailable because its production use-case adapter is not configured.`,
    );
    this.name = 'CliUnavailableError';
    this.feature = feature;
  }
}

/**
 * Raised after a guarded child process ends in any state other than a clean
 * exit code zero. The rendered result already reports the child's own exit
 * code, signal, and termination reason; this error only keeps the CLI from
 * presenting a failed child as a successful command.
 */
export class CliRunFailedError extends Error {
  readonly code = 'RUN_CHILD_FAILED' as const;
  readonly safe = true;

  constructor(termination: string, exitCode: number | null) {
    super(
      exitCode === null
        ? `The command did not complete normally (${termination}).`
        : `The command exited with code ${String(exitCode)}.`,
    );
    this.name = 'CliRunFailedError';
  }
}

/**
 * Raised when an unlocked session stopped before the command could report a
 * result. Every reason is terminal, so the message tells the operator to unlock
 * again rather than implying the command can be resumed. The code distinguishes
 * the reasons for scripting without revealing anything about the vault: which
 * deadline fired, or which signal arrived, is not secret.
 */
export class CliSessionEndedError extends Error {
  readonly code: CliSessionEndedCode;
  readonly safe = true;
  readonly reason: SessionExpiryReason;

  constructor(reason: SessionExpiryReason) {
    super(SESSION_ENDED_MESSAGES[reason]);
    this.name = 'CliSessionEndedError';
    this.reason = reason;
    this.code = SESSION_ENDED_CODES[reason];
  }
}

const SESSION_ENDED_CODES = Object.freeze({
  'invocation-timeout': 'SESSION_TIMEOUT',
  'idle-timeout': 'SESSION_IDLE_TIMEOUT',
  interrupted: 'SESSION_INTERRUPTED',
  terminated: 'SESSION_TERMINATED',
  hangup: 'SESSION_TERMINATED',
  'clock-regression': 'SESSION_CLOCK_UNUSABLE',
} as const satisfies Readonly<Record<SessionExpiryReason, string>>);

const SESSION_ENDED_MESSAGES = Object.freeze({
  'invocation-timeout':
    'The vault session reached its time limit and was locked. Unlock again to retry.',
  'idle-timeout':
    'The vault session was locked after the inactivity limit. Unlock again to retry.',
  interrupted: 'The vault session was cancelled and locked.',
  terminated: 'The vault session was terminated and locked.',
  hangup: 'The vault session was terminated and locked.',
  'clock-regression':
    'The vault session was locked because the monotonic clock moved backward.',
} as const satisfies Readonly<Record<SessionExpiryReason, string>>);

export type CliSessionEndedCode =
  (typeof SESSION_ENDED_CODES)[keyof typeof SESSION_ENDED_CODES];

export class CliKeyFileCreationError extends Error {
  readonly code = 'KEY_FILE_CREATE_FAILED' as const;

  constructor() {
    super('The portable key file could not be created.');
    this.name = 'CliKeyFileCreationError';
  }
}

export class CliBackupCreationError extends Error {
  readonly code = 'BACKUP_CREATE_FAILED' as const;

  constructor() {
    super('The encrypted backup could not be created.');
    this.name = 'CliBackupCreationError';
  }
}

export class CliBackupVerificationError extends Error {
  readonly code: BackupErrorCode;
  readonly safe = true;

  constructor(code: BackupErrorCode = 'BACKUP_AUTHENTICATION_FAILED') {
    super('The encrypted backup could not be verified.');
    this.name = 'CliBackupVerificationError';
    this.code = code;
  }
}

export class CliBackupRestoreError extends Error {
  readonly code: BackupErrorCode;
  readonly safe = true;

  constructor(code: BackupErrorCode = 'BACKUP_AUTHENTICATION_FAILED') {
    super(
      code === 'BACKUP_COMMIT_UNCERTAIN'
        ? 'The backup restore outcome is uncertain. Preserve the archive and isolated target; retry the same archive only.'
        : 'The encrypted backup could not be restored.',
    );
    this.name = 'CliBackupRestoreError';
    this.code = code;
  }
}

/**
 * Raised when a guarded encrypted transfer cannot be produced. The message
 * stays deliberately uniform so it never reveals which document, field, or
 * policy stopped the export.
 */
export class CliTransferExportError extends Error {
  readonly code = 'TRANSFER_EXPORT_FAILED' as const;
  readonly safe = true;

  constructor() {
    super('The encrypted transfer could not be exported.');
    this.name = 'CliTransferExportError';
  }
}

/**
 * Raised when a guarded encrypted transfer cannot be applied. The transfer is
 * authenticated in full before anything is created, so this error means nothing
 * was imported unless the message says the outcome is uncertain.
 */
export class CliTransferImportError extends Error {
  readonly code: BackupErrorCode;
  readonly safe = true;

  constructor(code: BackupErrorCode = 'BACKUP_AUTHENTICATION_FAILED') {
    super(
      code === 'BACKUP_COMMIT_UNCERTAIN'
        ? 'The encrypted transfer outcome is uncertain. Review the vault before retrying the same file.'
        : 'The encrypted transfer could not be imported.',
    );
    this.name = 'CliTransferImportError';
    this.code = code;
  }
}

export type CliErrorPresentation = Readonly<{
  exitCode: number;
  code: string;
  message: string;
}>;

export function presentCliError(error: unknown): CliErrorPresentation {
  if (error instanceof CliUsageError) {
    return { exitCode: CLI_EXIT_CODES.usage, code: error.code, message: error.message };
  }
  if (error instanceof CliUnsupportedRuntimeError) {
    return {
      exitCode: CLI_EXIT_CODES.unavailable,
      code: error.code,
      message: error.message,
    };
  }
  if (error instanceof CliUnavailableError) {
    return {
      exitCode: CLI_EXIT_CODES.unavailable,
      code: error.code,
      message: error.message,
    };
  }
  if (error instanceof CliRunFailedError) {
    return {
      exitCode: CLI_EXIT_CODES.failure,
      code: error.code,
      message: error.message,
    };
  }
  if (error instanceof CliSessionEndedError) {
    return {
      exitCode: CLI_EXIT_CODES.failure,
      code: error.code,
      message: error.message,
    };
  }
  if (error instanceof CliKeyFileCreationError) {
    return {
      exitCode: CLI_EXIT_CODES.failure,
      code: error.code,
      message: error.message,
    };
  }
  if (error instanceof CliBackupCreationError) {
    return {
      exitCode: CLI_EXIT_CODES.failure,
      code: error.code,
      message: error.message,
    };
  }
  if (error instanceof CliBackupVerificationError) {
    return {
      exitCode: CLI_EXIT_CODES.failure,
      code: error.code,
      message: error.message,
    };
  }
  if (error instanceof CliBackupRestoreError) {
    return {
      exitCode: CLI_EXIT_CODES.failure,
      code: error.code,
      message: error.message,
    };
  }
  if (error instanceof CliTransferExportError) {
    return {
      exitCode: CLI_EXIT_CODES.failure,
      code: error.code,
      message: error.message,
    };
  }
  if (error instanceof CliTransferImportError) {
    return {
      exitCode: CLI_EXIT_CODES.failure,
      code: error.code,
      message: error.message,
    };
  }
  if (error instanceof DomainError) {
    return {
      exitCode: domainExitCode(error.code),
      code: error.code,
      message: error.message,
    };
  }
  return {
    exitCode: CLI_EXIT_CODES.failure,
    code: 'UNEXPECTED_FAILURE',
    message: 'The command failed without exposing internal details.',
  };
}

export async function presentCliCommandError(
  error: unknown,
): Promise<CliErrorPresentation> {
  const presentation = presentCliError(error);
  if (presentation.code !== 'UNEXPECTED_FAILURE') return presentation;

  const { VaultLifecycleError } = await import('@kavrix/client');
  if (error instanceof VaultLifecycleError) {
    return {
      exitCode: CLI_EXIT_CODES.failure,
      code: 'VAULT_LIFECYCLE_FAILED',
      message: 'The vault lifecycle operation failed.',
    };
  }
  return presentation;
}

function domainExitCode(code: DomainError['code']): number {
  switch (code) {
    case 'VALIDATION_FAILED':
      return CLI_EXIT_CODES.usage;
    case 'NOT_FOUND':
      return CLI_EXIT_CODES.notFound;
    case 'AMBIGUOUS_NAME':
      return CLI_EXIT_CODES.ambiguous;
    case 'NETWORK_UNAVAILABLE':
      return CLI_EXIT_CODES.unavailable;
    default:
      return CLI_EXIT_CODES.failure;
  }
}
