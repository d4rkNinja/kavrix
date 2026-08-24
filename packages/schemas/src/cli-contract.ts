import { z } from 'zod';

/**
 * Stable machine-readable CLI contract. Automation reads exit codes and the
 * JSON error envelope; it must never need to parse human-readable text.
 */
export const CLI_EXIT_CODES = Object.freeze({
  ok: 0,
  unclassifiedFailure: 1,
  usageError: 2,
  authenticationFailed: 10,
  credentialMissing: 11,
  authorizationDenied: 12,
  grantInvalid: 13,
  invalidConfiguration: 14,
  datastoreFailure: 15,
  securityIntegrityFailure: 16,
  confirmationRequired: 17,
} as const);

export type CliExitCode = (typeof CLI_EXIT_CODES)[keyof typeof CLI_EXIT_CODES];

export const CLI_ERROR_CODES = [
  'OK',
  'UNCLASSIFIED_FAILURE',
  'USAGE_ERROR',
  'AUTHENTICATION_FAILED',
  'CREDENTIAL_MISSING',
  'AUTHORIZATION_DENIED',
  'GRANT_INVALID',
  'INVALID_CONFIGURATION',
  'DATASTORE_FAILURE',
  'SECURITY_INTEGRITY_FAILURE',
  'CONFIRMATION_REQUIRED',
] as const;

export const cliErrorCodeSchema = z.enum(CLI_ERROR_CODES);

export type CliErrorCode = z.infer<typeof cliErrorCodeSchema>;

const CLI_ERROR_EXIT_CODES: Readonly<Record<CliErrorCode, number>> = Object.freeze({
  OK: CLI_EXIT_CODES.ok,
  UNCLASSIFIED_FAILURE: CLI_EXIT_CODES.unclassifiedFailure,
  USAGE_ERROR: CLI_EXIT_CODES.usageError,
  AUTHENTICATION_FAILED: CLI_EXIT_CODES.authenticationFailed,
  CREDENTIAL_MISSING: CLI_EXIT_CODES.credentialMissing,
  AUTHORIZATION_DENIED: CLI_EXIT_CODES.authorizationDenied,
  GRANT_INVALID: CLI_EXIT_CODES.grantInvalid,
  INVALID_CONFIGURATION: CLI_EXIT_CODES.invalidConfiguration,
  DATASTORE_FAILURE: CLI_EXIT_CODES.datastoreFailure,
  SECURITY_INTEGRITY_FAILURE: CLI_EXIT_CODES.securityIntegrityFailure,
  CONFIRMATION_REQUIRED: CLI_EXIT_CODES.confirmationRequired,
});

/** Maps one stable error code to its stable process exit code. */
export function exitCodeForCliError(code: CliErrorCode): number {
  return CLI_ERROR_EXIT_CODES[code];
}

export const cliErrorEnvelopeSchema = z
  .object({
    error: z
      .object({
        code: cliErrorCodeSchema,
        exitCode: z.number().int().min(0).max(255),
        message: z.string().min(1).max(1024),
      })
      .strict(),
  })
  .strict();

export type CliErrorEnvelope = z.infer<typeof cliErrorEnvelopeSchema>;
