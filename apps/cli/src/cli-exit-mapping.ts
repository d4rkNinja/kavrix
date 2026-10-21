/**
 * Startup-safe exit-code mapping for failure classes that both the light
 * startup classifier and the full classifier recognise. Every value is read
 * from the canonical `CLI_EXIT_CODES` leaf, so the classifiers cannot drift
 * from the documented contract.
 */
import { CLI_EXIT_CODES } from '@kavrix/schemas/cli-exit-codes';

const COMMANDER_SUCCESS_CODES: ReadonlySet<string> = new Set([
  'commander.help',
  'commander.helpDisplayed',
  'commander.version',
]);

/** Help and version output succeed; every other parse failure is usage. */
export function commanderExitCode(code: string): number {
  return COMMANDER_SUCCESS_CODES.has(code)
    ? CLI_EXIT_CODES.ok
    : CLI_EXIT_CODES.usageError;
}

/**
 * Tampering is integrity; an unavailable OS credential store degrades to the
 * datastore class; expiry and every other setup problem is configuration.
 */
export function sessionUnlockExitCode(code: string): number {
  if (code === 'tampered') return CLI_EXIT_CODES.securityIntegrityFailure;
  if (code === 'keychain-unavailable') return CLI_EXIT_CODES.datastoreFailure;
  return CLI_EXIT_CODES.invalidConfiguration;
}

/**
 * Migration input problems are configuration mistakes; verification and
 * ambiguous-commit outcomes are integrity failures.
 */
export function databaseMigrationExitCode(code: string): number {
  if (code === 'invalid') return CLI_EXIT_CODES.invalidConfiguration;
  if (code === 'authentication') return CLI_EXIT_CODES.authenticationFailed;
  if (code === 'conflict') return CLI_EXIT_CODES.datastoreFailure;
  return CLI_EXIT_CODES.securityIntegrityFailure;
}

/** BUSY and OPERATION_FAILED are protected-file transport problems. */
export function portableKeyFileExitCode(code: string): number {
  switch (code) {
    case 'KEY_FILE_NOT_FOUND':
      return CLI_EXIT_CODES.credentialMissing;
    case 'KEY_FILE_ALREADY_EXISTS':
    case 'KEY_FILE_INVALID_PATH':
    case 'KEY_FILE_UNSAFE':
      return CLI_EXIT_CODES.invalidConfiguration;
    default:
      return CLI_EXIT_CODES.datastoreFailure;
  }
}
