import {
  EncryptedDatabaseStoreError,
  EncryptedVaultStoreError,
  FileLocalVaultError,
} from '@kavrix/storage';
import { PortableKeyFileError } from '@kavrix/key-files';

import { LocalCliError } from './cli-error.js';
import { DatabaseFlatCommandError } from './database-flat-commands.js';
import { DatabaseMigrationError } from './database-migration.js';
import { DatabaseMigrationCommandError } from './database-migration-command.js';
import { DatabaseSessionError } from './database-session.js';
import { DatastoreProfileError } from './datastore-profiles.js';
import { InitOnboardingCancelledError } from './init-onboarding.js';

/** Commander raises this shape whenever an override intercepts parsing. */
interface CommanderErrorLike {
  readonly name: string;
  readonly code: string;
  readonly exitCode: number;
  readonly message: string;
}

function isCommanderError(error: unknown): error is CommanderErrorLike {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === 'CommanderError' &&
    typeof (error as { code?: unknown }).code === 'string' &&
    typeof (error as { exitCode?: unknown }).exitCode === 'number'
  );
}

function portableKeyFileExitCode(error: PortableKeyFileError): number {
  switch (error.code) {
    case 'KEY_FILE_NOT_FOUND':
      return 11;
    case 'KEY_FILE_ALREADY_EXISTS':
    case 'KEY_FILE_INVALID_PATH':
    case 'KEY_FILE_UNSAFE':
      return 14;
    default:
      // BUSY and OPERATION_FAILED are protected-file transport problems.
      return 15;
  }
}

/**
 * Maps one thrown failure to its stable documented presentation: a single
 * sanitized line plus the exit-code contract from the CLI reference
 * (0 ok · 1 generic · 2 usage · 10 auth · 11 missing · 12 denied ·
 * 13 grant · 14 configuration · 15 datastore · 16 integrity · 17 confirm).
 * Unknown failures stay generic and never leak raw error text.
 */
export function classifyCliFailure(error: unknown): Readonly<{
  message: string;
  exitCode: number;
}> {
  if (isCommanderError(error)) {
    // Help (`--help`, `--version`) exits successfully after commander has
    // already written its output through the configured streams.
    if (
      error.code === 'commander.help' ||
      error.code === 'commander.helpDisplayed' ||
      error.code === 'commander.version'
    ) {
      return { message: '', exitCode: 0 };
    }
    // Commander has already rendered the sanitized error and command-local
    // usage through the configured output stream. Returning no second message
    // prevents duplicate error lines while preserving the documented exit 2.
    return { message: '', exitCode: 2 };
  }
  if (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === 'CodedCliError' &&
    typeof (error as { exitCode?: unknown }).exitCode === 'number'
  ) {
    const coded = error as Error & { exitCode: number };
    return { message: coded.message, exitCode: coded.exitCode };
  }
  if (error instanceof DatabaseSessionError) {
    return { message: error.message, exitCode: error.cliExitCode };
  }
  if (error instanceof DatabaseMigrationError) {
    // Migration input problems are configuration mistakes; verification and
    // ambiguous-commit outcomes are integrity/datastore failures.
    const exitCode =
      error.code === 'invalid'
        ? 14
        : error.code === 'authentication'
          ? 10
          : error.code === 'conflict'
            ? 15
            : 16;
    return { message: error.message, exitCode };
  }
  if (
    error instanceof DatabaseMigrationCommandError ||
    error instanceof DatabaseFlatCommandError
  ) {
    return {
      message: error.message,
      exitCode: 14,
    };
  }
  if (error instanceof DatastoreProfileError) {
    // Profile routing failures are operator configuration mistakes.
    return { message: error.message, exitCode: 14 };
  }
  if (
    error instanceof FileLocalVaultError ||
    error instanceof EncryptedDatabaseStoreError ||
    error instanceof EncryptedVaultStoreError
  ) {
    return { message: error.message, exitCode: 15 };
  }
  if (error instanceof PortableKeyFileError) {
    return { message: error.message, exitCode: portableKeyFileExitCode(error) };
  }
  // Secret-input framing problems are operator usage mistakes.
  if (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === 'LocalSecretInputError'
  ) {
    return { message: (error as Error).message, exitCode: 2 };
  }
  if (error instanceof AggregateError) {
    return { message: error.message, exitCode: 1 };
  }
  if (error instanceof InitOnboardingCancelledError) {
    return { message: error.message, exitCode: 1 };
  }
  if (error instanceof LocalCliError) {
    return { message: error.message, exitCode: 1 };
  }
  return { message: 'Kavrix command failed.', exitCode: 1 };
}
