import { describe, expect, it } from 'vitest';

import { CLI_EXIT_CODES } from '@kavrix/schemas/cli-exit-codes';

import { classifyCliFailure } from '../src/cli-errors.js';
import { DatabaseMigrationError } from '../src/database-migration.js';
import { DatabaseSessionError } from '../src/database-session.js';
import {
  classifyAggregateFailure,
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

describe('aggregate failure classification', () => {
  it('reports the wrapped migration failure exit code and message', () => {
    // The redacted migration cleanup aggregate used to degrade to generic
    // exit 1 before its members were inspected.
    const result = classifyCliFailure(
      new AggregateError(
        [
          new DatabaseMigrationError('authentication'),
          new DatabaseMigrationError('ambiguous-commit'),
        ],
        'Migration cleanup failed.',
      ),
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.authenticationFailed);
    expect(result.message).toContain('Migration cleanup failed.');
    expect(result.message).toContain('Legacy vault migration authentication failed');
  });

  it('reports the wrapped session failure exit code and message', () => {
    const result = classifyCliFailure(
      new AggregateError(
        [new DatabaseSessionError('busy'), new DatabaseSessionError('operation')],
        'Database cleanup failed.',
      ),
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.datastoreFailure);
    expect(result.message).toContain('Database cleanup failed.');
    expect(result.message).toContain('locked by another Kavrix process');
  });

  it('stays generic when no member classifies, keeping the aggregate summary', () => {
    const result = classifyCliFailure(
      new AggregateError([new Error('unmapped internal failure')], 'Cleanup failed.'),
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.unclassifiedFailure);
    expect(result.message).toBe('Cleanup failed.');
  });

  it('prefers the first member with a non-generic exit code', () => {
    const result = classifyAggregateFailure(
      new AggregateError(
        [
          new Error('unclassifiable'),
          new DatabaseSessionError('invalid'),
          new DatabaseSessionError('busy'),
        ],
        'Database cleanup failed.',
      ),
      (member) =>
        member instanceof DatabaseSessionError
          ? { message: member.message, exitCode: member.cliExitCode }
          : undefined,
    );
    expect(result.exitCode).toBe(CLI_EXIT_CODES.invalidConfiguration);
    expect(result.message).toContain('The database operation is invalid.');
  });

  it('bounds the combined member messages', () => {
    const result = classifyCliFailure(
      new AggregateError([new DatabaseSessionError('busy')], 'D'.repeat(600)),
    );
    expect(result.message.length).toBeLessThanOrEqual(500);
    expect(result.message.startsWith('DDDD')).toBe(true);
  });
});
