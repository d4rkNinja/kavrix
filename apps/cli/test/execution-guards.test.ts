import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeFile } from 'node:fs/promises';

import { afterEach, describe, expect, it } from 'vitest';

import {
  createExecutionFixture,
  destroyFixture,
  passphraseFrame,
  runCli,
  type ExecutionFixture,
} from './execution-helpers.js';

let fixture: ExecutionFixture;

afterEach(async () => {
  if (fixture !== undefined) await destroyFixture(fixture);
});

describe('agent run argument guards', () => {
  it('rejects missing commands and non-database routing', async () => {
    fixture = await createExecutionFixture({});
    try {
      const noCommand = await runCli(
        [
          'agent',
          'run',
          '--agent',
          'bot',
          '--config',
          join(fixture.directory, 'cfg.json'),
          ...fixture.routingArgs,
          '--passphrase-stdin',
        ],
        passphraseFrame(),
      );
      expect(noCommand.exitCode).toBe(14);
      expect(noCommand.stderr).toContain('An agent command is required');

      const result = await runCli(
        [
          'agent',
          'run',
          '--agent',
          'bot',
          ...fixture.routingArgs,
          '--passphrase-stdin',
          '--',
          process.execPath,
          '-e',
          'process.exit(0)',
        ],
        passphraseFrame(),
      );
      expect(result.exitCode).toBe(14);
    } finally {
      await destroyFixture(fixture);
      fixture = undefined as unknown as ExecutionFixture;
    }
  });

  it('reports spawn failures when the resolved agent cannot start', async () => {
    fixture = await createExecutionFixture({ 'a/b': 'unused' });
    try {
      const configFile = join(fixture.directory, 'agents.json');
      await writeFile(
        configFile,
        JSON.stringify({
          version: 1,
          agents: {
            bot: {
              permissions: {
                noop: { secret: 'a/b', commands: ['node'], env: 'NOOP' },
              },
            },
          },
        }),
      );
      // A regular file that resolves but cannot start as a process.
      const bogus = join(fixture.directory, 'bogus-agent');
      await writeFile(bogus, 'definitely not an executable\n');

      const result = await runCli(
        [
          'agent',
          'run',
          '--agent',
          'bot',
          '--config',
          configFile,
          ...fixture.routingArgs,
          '--passphrase-stdin',
          '--',
          bogus,
        ],
        passphraseFrame(),
      );
      // Either the runner refuses or the CLI maps the spawn failure; both
      // fail closed with a nonzero code and a sanitized message.
      expect(result.exitCode).not.toBe(0);
      expect(
        result.stderr.includes('could not be started') ||
          result.stderr.includes('Kavrix'),
      ).toBe(true);
    } finally {
      await destroyFixture(fixture);
      fixture = undefined as unknown as ExecutionFixture;
    }
  });
});

describe('grant and state error guards', () => {
  it('maps unknown grant ids and malformed ids to stable codes', async () => {
    fixture = await createExecutionFixture({ 'a/b': 'value' });
    try {
      const revokedUnknown = await runCli(
        [
          'grant',
          'revoke',
          'grant_does-not-exist',
          ...fixture.routingArgs,
          '--passphrase-stdin',
        ],
        passphraseFrame(),
      );
      expect(revokedUnknown.exitCode).toBe(13);

      const malformed = await runCli(
        ['grant', 'revoke', 'bad id!', ...fixture.routingArgs, '--passphrase-stdin'],
        passphraseFrame(),
      );
      expect(malformed.exitCode).toBe(14);
    } finally {
      await destroyFixture(fixture);
      fixture = undefined as unknown as ExecutionFixture;
    }
  });
});

describe('grant option parsing guards', () => {
  it('rejects invalid ttl and malformed hashes with the stable code', async () => {
    fixture = await createExecutionFixture({});
    try {
      const badTtl = await runCli(
        [
          'grant',
          'create',
          'a/b',
          '--command',
          'x',
          '--ttl',
          '31d',
          ...fixture.routingArgs,
          '--passphrase-stdin',
        ],
        passphraseFrame(),
      );
      expect(badTtl.exitCode).toBe(14);
      expect(badTtl.stderr).toContain('--ttl is invalid or too large');

      const badHash = await runCli(
        [
          'policy',
          'create',
          'bad-hash',
          ...fixture.routingArgs,
          '--passphrase-stdin',
          '--secret',
          'a/b',
          '--command',
          'x',
          '--hash',
          'noparse',
        ],
        passphraseFrame(),
      );
      expect(badHash.exitCode).toBe(14);
      expect(badHash.stderr).toContain('--hash expects');
    } finally {
      await destroyFixture(fixture);
      fixture = undefined as unknown as ExecutionFixture;
    }
  });
});

describe('policy option parsing guards', () => {
  it('rejects non-numeric max-uses with the stable configuration code', async () => {
    fixture = await createExecutionFixture({});
    try {
      const result = await runCli(
        [
          'policy',
          'create',
          'bad-max-uses',
          ...fixture.routingArgs,
          '--passphrase-stdin',
          '--secret',
          'a/b',
          '--command',
          'x',
          '--max-uses',
          'abc',
        ],
        passphraseFrame(),
      );
      expect(result.exitCode).toBe(14);
      expect(result.stderr).toContain('--max-uses expects a positive whole number');
    } finally {
      await destroyFixture(fixture);
      fixture = undefined as unknown as ExecutionFixture;
    }
  });
});
