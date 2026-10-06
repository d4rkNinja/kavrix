import { cliErrorCodeSchema } from '@kavrix/schemas';

import type { CodedCliError } from './exit-codes.js';

/**
 * True when a thrown value carries the stable coded-CLI shape: the marker
 * class name, an explicit `errorCode` field, and an error code the schema
 * actually defines. Implemented here so the light CLI startup path does not
 * need the validation graph; every consumer of this guard is a command
 * implementation or the failure reporter, which already load heavy modules.
 */
export function isCodedCliError(error: unknown): error is CodedCliError {
  return (
    error instanceof Error &&
    error.name === 'CodedCliError' &&
    'errorCode' in error &&
    cliErrorCodeSchema.safeParse((error as CodedCliError).errorCode).success
  );
}

/** Stable exit code for a coded error, or undefined for anything else. */
export function codedExitCode(error: unknown): number | undefined {
  return isCodedCliError(error) ? error.exitCode : undefined;
}
