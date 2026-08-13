import { DomainError } from '@kavrix/core';

import type { BackupErrorCode } from '@kavrix/import-export';
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
  | 'key create'
  | 'key slot list'
  | 'key slot create'
  | 'key slot disable'
  | 'key slot revoke'
  | 'key rotate'
  | 'key rotate resume'
  | 'key rotate list'
  | 'device invite create'
  | 'device invite list'
  | 'device invite revoke'
  | 'device invite join'
  | 'device list'
  | 'device revoke'
  | 'device remember'
  | 'device forget'
  | 'device join'
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
  | 'reveal'
  | 'get'
  | 'sync'
  | 'sync conflicts list'
  | 'sync conflicts resolve'
  | 'connect'
  | 'recover'
  | 'backup create'
  | 'backup verify';

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
