import {
  EncryptedDatabaseStoreError,
  EncryptedVaultStoreError,
  FileLocalVaultError,
} from '@kavrix/storage';
import { PortableKeyFileError } from '@kavrix/key-files';
import { CLI_EXIT_CODES } from '@kavrix/schemas/cli-exit-codes';

import { LocalCliError } from './cli-error.js';
import {
  commanderExitCode,
  databaseMigrationExitCode,
  portableKeyFileExitCode,
  sessionUnlockExitCode,
} from './cli-exit-mapping.js';
import { keyFileGuidance } from './key-file-guidance.js';
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

/**
 * Maps one thrown failure to its stable documented presentation: a single
 * sanitized line plus the exit-code contract from the CLI reference
 * (0 ok · 1 generic · 2 usage · 10 auth · 11 missing · 12 denied ·
 * 13 grant · 14 configuration · 15 datastore · 16 integrity · 17 confirm ·
 * 18 execution/spawn).
 * Unknown failures stay generic and never leak raw error text, except
 * short module-load diagnostics that cannot carry vault secrets.
 */
export function classifyCliFailure(error: unknown): Readonly<{
  message: string;
  exitCode: number;
}> {
  if (isCommanderError(error)) {
    // Commander has already rendered help, version, or the sanitized usage
    // error through the configured streams; a second message would duplicate it.
    return { message: '', exitCode: commanderExitCode(error.code) };
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
    return { message: error.message, exitCode: databaseMigrationExitCode(error.code) };
  }
  if (
    error instanceof DatabaseMigrationCommandError ||
    error instanceof DatabaseFlatCommandError
  ) {
    return { message: error.message, exitCode: CLI_EXIT_CODES.invalidConfiguration };
  }
  if (error instanceof DatastoreProfileError) {
    // Profile routing failures are operator configuration mistakes.
    return { message: error.message, exitCode: CLI_EXIT_CODES.invalidConfiguration };
  }
  if (
    error instanceof FileLocalVaultError ||
    error instanceof EncryptedDatabaseStoreError ||
    error instanceof EncryptedVaultStoreError
  ) {
    return { message: error.message, exitCode: CLI_EXIT_CODES.datastoreFailure };
  }
  if (error instanceof PortableKeyFileError) {
    const message =
      error.code === 'KEY_FILE_NOT_FOUND'
        ? 'The portable key file was not found.'
        : error.code === 'KEY_FILE_UNSAFE'
          ? keyFileGuidance(error)
          : error.message;
    return { message, exitCode: portableKeyFileExitCode(error.code) };
  }
  // Secret-input framing problems are operator usage mistakes.
  if (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === 'LocalSecretInputError'
  ) {
    return { message: (error as Error).message, exitCode: CLI_EXIT_CODES.usageError };
  }
  if (
    error instanceof AggregateError ||
    error instanceof InitOnboardingCancelledError ||
    error instanceof LocalCliError
  ) {
    return { message: error.message, exitCode: CLI_EXIT_CODES.unclassifiedFailure };
  }
  if (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === 'SessionUnlockError' &&
    typeof (error as { code?: unknown }).code === 'string'
  ) {
    return {
      message: (error as Error).message,
      exitCode: sessionUnlockExitCode((error as { code: string }).code),
    };
  }
  // Bundle/runtime module-load failures are safe to surface: they never carry
  // vault secrets and otherwise collapse to a generic line that hides the fix.
  if (
    error instanceof Error &&
    error.message.length > 0 &&
    error.message.length <= 200 &&
    /^(Dynamic require of |Cannot find module )/u.test(error.message)
  ) {
    return {
      message: `Kavrix command failed: ${error.message}`,
      exitCode: CLI_EXIT_CODES.unclassifiedFailure,
    };
  }
  return {
    message: 'Kavrix command failed.',
    exitCode: CLI_EXIT_CODES.unclassifiedFailure,
  };
}
