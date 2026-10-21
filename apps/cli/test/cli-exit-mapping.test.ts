import { describe, expect, it } from 'vitest';

import { CLI_EXIT_CODES } from '@kavrix/schemas/cli-exit-codes';

import {
  commanderExitCode,
  databaseMigrationExitCode,
  portableKeyFileExitCode,
  sessionUnlockExitCode,
} from '../src/cli-exit-mapping.js';

const DOCUMENTED = new Set<number>(Object.values(CLI_EXIT_CODES));

describe('shared CLI exit-code mapping', () => {
  it('maps every known failure class onto the documented contract', () => {
    expect(commanderExitCode('commander.help')).toBe(CLI_EXIT_CODES.ok);
    expect(commanderExitCode('commander.version')).toBe(CLI_EXIT_CODES.ok);
    expect(commanderExitCode('commander.unknownOption')).toBe(
      CLI_EXIT_CODES.usageError,
    );

    expect(sessionUnlockExitCode('tampered')).toBe(
      CLI_EXIT_CODES.securityIntegrityFailure,
    );
    expect(sessionUnlockExitCode('keychain-unavailable')).toBe(
      CLI_EXIT_CODES.datastoreFailure,
    );
    expect(sessionUnlockExitCode('expired')).toBe(CLI_EXIT_CODES.invalidConfiguration);

    expect(databaseMigrationExitCode('invalid')).toBe(
      CLI_EXIT_CODES.invalidConfiguration,
    );
    expect(databaseMigrationExitCode('authentication')).toBe(
      CLI_EXIT_CODES.authenticationFailed,
    );
    expect(databaseMigrationExitCode('conflict')).toBe(CLI_EXIT_CODES.datastoreFailure);
    expect(databaseMigrationExitCode('verification')).toBe(
      CLI_EXIT_CODES.securityIntegrityFailure,
    );

    expect(portableKeyFileExitCode('KEY_FILE_NOT_FOUND')).toBe(
      CLI_EXIT_CODES.credentialMissing,
    );
    for (const code of [
      'KEY_FILE_ALREADY_EXISTS',
      'KEY_FILE_INVALID_PATH',
      'KEY_FILE_UNSAFE',
    ]) {
      expect(portableKeyFileExitCode(code)).toBe(CLI_EXIT_CODES.invalidConfiguration);
    }
    expect(portableKeyFileExitCode('KEY_FILE_BUSY')).toBe(
      CLI_EXIT_CODES.datastoreFailure,
    );
  });

  it('never returns a code outside the documented table', () => {
    for (const code of ['', 'unknown', 'commander.help', 'tampered', 'KEY_FILE_X']) {
      for (const mapping of [
        commanderExitCode,
        sessionUnlockExitCode,
        databaseMigrationExitCode,
        portableKeyFileExitCode,
      ]) {
        expect(DOCUMENTED.has(mapping(code))).toBe(true);
      }
    }
  });
});
