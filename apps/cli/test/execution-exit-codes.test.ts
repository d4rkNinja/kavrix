import { describe, expect, it } from 'vitest';

import {
  DEFAULT_FAILURE_EXIT,
  CLI_EXIT_CODES,
  authenticationFailure,
  authorizationDenied,
  codedExitCode,
  confirmationRequired,
  credentialMissing,
  datastoreFailure,
  grantInvalid,
  invalidConfiguration,
  isCodedCliError,
  securityIntegrityFailure,
  toErrorEnvelope,
} from '../src/execution/exit-codes.js';

describe('coded CLI errors', () => {
  it('exposes one factory per stable code with matching exit codes', () => {
    const cases = [
      [authenticationFailure(), 'AUTHENTICATION_FAILED', 10],
      [authenticationFailure('bad passphrase'), 'AUTHENTICATION_FAILED', 10],
      [credentialMissing('a/b'), 'CREDENTIAL_MISSING', 11],
      [credentialMissing(), 'CREDENTIAL_MISSING', 11],
      [authorizationDenied('x'), 'AUTHORIZATION_DENIED', 12],
      [grantInvalid('x'), 'GRANT_INVALID', 13],
      [invalidConfiguration('x'), 'INVALID_CONFIGURATION', 14],
      [datastoreFailure('x'), 'DATASTORE_FAILURE', 15],
      [securityIntegrityFailure('x'), 'SECURITY_INTEGRITY_FAILURE', 16],
      [confirmationRequired('x'), 'CONFIRMATION_REQUIRED', 17],
    ] as const;
    for (const [error, code, exit] of cases) {
      expect(isCodedCliError(error)).toBe(true);
      expect(error.errorCode).toBe(code);
      expect(error.exitCode).toBe(exit);
      expect(codedExitCode(error)).toBe(exit);
    }
  });

  it('rejects foreign errors and emits the JSON envelope', () => {
    expect(codedExitCode(new Error('plain'))).toBeUndefined();
    expect(isCodedCliError(null)).toBe(false);
    expect(DEFAULT_FAILURE_EXIT).toBe(CLI_EXIT_CODES.unclassifiedFailure);
    const envelope = toErrorEnvelope('AUTHORIZATION_DENIED', 'denied');
    expect(envelope.error).toEqual({
      code: 'AUTHORIZATION_DENIED',
      exitCode: 12,
      message: 'denied',
    });
  });
});
