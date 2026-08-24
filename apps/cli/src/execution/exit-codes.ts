import {
  CLI_EXIT_CODES,
  cliErrorCodeSchema,
  exitCodeForCliError,
  type CliErrorEnvelope,
  type CliErrorCode,
  type CliExitCode,
} from '@kavrix/schemas';

export { CLI_EXIT_CODES };

/** One failure carrying a stable machine-readable code and exit code. */
export class CodedCliError extends Error {
  public override readonly name = 'CodedCliError';

  public constructor(
    public readonly errorCode: CliErrorCode,
    message: string,
  ) {
    super(message);
  }

  public get exitCode(): number {
    return exitCodeForCliError(this.errorCode);
  }
}

export function authenticationFailure(message = 'Vault unlock failed.'): CodedCliError {
  return new CodedCliError('AUTHENTICATION_FAILED', message);
}

export function credentialMissing(name?: string): CodedCliError {
  return new CodedCliError(
    'CREDENTIAL_MISSING',
    name === undefined
      ? 'Credential was not found.'
      : `Credential '${name}' was not found.`,
  );
}

export function authorizationDenied(message: string): CodedCliError {
  return new CodedCliError('AUTHORIZATION_DENIED', message);
}

export function grantInvalid(message: string): CodedCliError {
  return new CodedCliError('GRANT_INVALID', message);
}

export function invalidConfiguration(message: string): CodedCliError {
  return new CodedCliError('INVALID_CONFIGURATION', message);
}

export function datastoreFailure(message: string): CodedCliError {
  return new CodedCliError('DATASTORE_FAILURE', message);
}

export function securityIntegrityFailure(message: string): CodedCliError {
  return new CodedCliError('SECURITY_INTEGRITY_FAILURE', message);
}

export function confirmationRequired(message: string): CodedCliError {
  return new CodedCliError('CONFIRMATION_REQUIRED', message);
}

export function isCodedCliError(error: unknown): error is CodedCliError {
  return (
    error instanceof Error &&
    error.name === 'CodedCliError' &&
    'errorCode' in error &&
    cliErrorCodeSchema.safeParse((error as CodedCliError).errorCode).success
  );
}

export function codedExitCode(error: unknown): number | undefined {
  return isCodedCliError(error) ? error.exitCode : undefined;
}

export const DEFAULT_FAILURE_EXIT: CliExitCode = CLI_EXIT_CODES.unclassifiedFailure;

/** Builds the stable JSON error envelope for automation consumers. */
export function toErrorEnvelope(code: CliErrorCode, message: string): CliErrorEnvelope {
  return {
    error: {
      code,
      exitCode: exitCodeForCliError(code),
      message,
    },
  };
}
