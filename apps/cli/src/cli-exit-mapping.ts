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

/** One mapped failure: a sanitized line plus its stable exit code. */
export type ClassifiedCliFailure = Readonly<{
  message: string;
  exitCode: number;
}>;

/** Rendered when nothing specific is known; never names member details. */
export const GENERIC_CLI_FAILURE_MESSAGE = 'Kavrix command failed.';

const AGGREGATE_MESSAGE_LIMIT = 480;

/**
 * Classifies an aggregate failure by its members. Aggregates raised by the
 * redacted cleanup paths (database session, database migration) wrap coded
 * members with stable exit codes that must not degrade to the generic class,
 * and the aggregate's own message is usually only the cleanup summary — so
 * the rendered message combines the meaningful member messages, staying
 * redacted (members come from the caller's reviewed classifier) and bounded.
 * The first member classifying to a non-generic exit code decides the exit
 * code; members the classifier cannot map are skipped.
 */
export function classifyAggregateFailure(
  error: AggregateError,
  classifyMember: (member: unknown) => ClassifiedCliFailure | undefined,
): ClassifiedCliFailure {
  const memberMessages: string[] = [];
  let exitCode: number = CLI_EXIT_CODES.unclassifiedFailure;
  for (const member of error.errors) {
    const classified = classifyMember(member);
    if (classified === undefined) continue;
    if (
      exitCode === CLI_EXIT_CODES.unclassifiedFailure &&
      classified.exitCode !== CLI_EXIT_CODES.unclassifiedFailure
    ) {
      exitCode = classified.exitCode;
    }
    if (
      classified.message.length > 0 &&
      classified.message !== GENERIC_CLI_FAILURE_MESSAGE &&
      !memberMessages.includes(classified.message)
    ) {
      memberMessages.push(classified.message);
    }
  }
  return {
    message: boundedAggregateMessage(error.message, memberMessages),
    exitCode,
  };
}

function boundedAggregateMessage(
  aggregateMessage: string,
  memberMessages: readonly string[],
): string {
  const parts: string[] = [];
  for (const part of [aggregateMessage, ...memberMessages]) {
    if (part.length > 0 && !parts.includes(part)) parts.push(part);
  }
  if (parts.length === 0) return GENERIC_CLI_FAILURE_MESSAGE;
  let message = parts[0] ?? '';
  for (const part of parts.slice(1)) {
    const candidate = `${message}; ${part}`;
    if (candidate.length > AGGREGATE_MESSAGE_LIMIT) break;
    message = candidate;
  }
  return message.length > AGGREGATE_MESSAGE_LIMIT
    ? `${message.slice(0, AGGREGATE_MESSAGE_LIMIT)}...`
    : message;
}
