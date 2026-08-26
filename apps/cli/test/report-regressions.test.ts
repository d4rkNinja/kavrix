import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  createExecutionFixture,
  destroyFixture,
  EXEC_PASSPHRASE,
  passphraseFrame,
  runCli,
  type ExecutionFixture,
} from './execution-helpers.js';
import { createSecureTestDirectory as mkdtemp } from '../../../packages/key-files/test/secure-temporary-directory.js';

const PASSPHRASE = `${EXEC_PASSPHRASE}\n`;

let container: ExecutionFixture;
let legacyDirectory: string;

async function legacyPaths() {
  const directory = await mkdtemp(join(tmpdir(), 'kavrix-report-'));
  return {
    directory,
    data: join(directory, 'vault.data'),
    key: join(directory, 'vault.key'),
  };
}

beforeAll(async () => {
  container = await createExecutionFixture({
    'github/token': 'e2e-canary-secret-value',
    'production/database': 'db-canary-passphrase',
  });
  legacyDirectory = await mkdtemp(join(tmpdir(), 'kavrix-report-legacy-'));
}, 120_000);

afterAll(async () => {
  await destroyFixture(container);
});

/** Owner routing for `db` subcommands: keep the profile, drop the flat --vault. */
function ownerRoutingArgs(): string[] {
  const args = [...container.routingArgs];
  const vaultIndex = args.indexOf('--vault');
  if (vaultIndex >= 0) args.splice(vaultIndex, 2);
  return args;
}

describe('documented exit codes', () => {
  it('exits 10 for a wrong passphrase on the legacy path', async () => {
    const target = await legacyPaths();
    const init = await runCli(
      [
        'init',
        '--datastore',
        'file',
        '--data-file',
        target.data,
        '--key-file',
        target.key,
        '--passphrase-stdin',
      ],
      `${PASSPHRASE}${PASSPHRASE}`,
    );
    expect(init.exitCode).toBe(0);
    const wrong = await runCli(
      [
        'get',
        'anything',
        '--datastore',
        'file',
        '--data-file',
        target.data,
        '--key-file',
        target.key,
        '--passphrase-stdin',
      ],
      'definitely-not-the-passphrase\n',
    );
    expect(wrong.exitCode).toBe(10);
    expect(wrong.stderr).toContain('Vault unlock failed.');
  });

  it('exits 11 for a missing credential', async () => {
    const result = await runCli(
      [
        'get',
        'no/such-credential',
        ...container.routingArgs,
        '--passphrase-stdin',
        '--json',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(11);
  });

  it('exits 2 for usage errors instead of the generic failure', async () => {
    const unknownOption = await runCli(['list', '--definitely-not-a-flag'], '');
    expect(unknownOption.exitCode).toBe(2);
    const unknownCommand = await runCli(['definitely-not-a-command'], '');
    expect(unknownCommand.exitCode).toBe(2);
    const missingArgument = await runCli(['get'], '');
    expect(missingArgument.exitCode).toBe(2);
  });

  it('reports an unknown database vault id as not found', async () => {
    const result = await runCli(
      [
        'db',
        'vault',
        'status',
        'vault_doesnotexist',
        ...ownerRoutingArgs(),
        '--secrets-stdin',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(11);
    expect(result.stderr).toContain('The requested vault was not found.');
  });
});

describe('multi-line and empty values via base64 frames', () => {
  it('stores and reveals multi-line and empty values byte-exact', async () => {
    const target = await legacyPaths();
    const init = await runCli(
      [
        'init',
        '--datastore',
        'file',
        '--data-file',
        target.data,
        '--key-file',
        target.key,
        '--passphrase-stdin',
      ],
      `${PASSPHRASE}${PASSPHRASE}`,
    );
    expect(init.exitCode).toBe(0);

    const multiline = Buffer.from('line-one\nline-two\n🔐-日本語', 'utf8').toString(
      'base64',
    );
    const putMulti = await runCli(
      [
        'put',
        'notes/multiline',
        '--datastore',
        'file',
        '--data-file',
        target.data,
        '--key-file',
        target.key,
        '--passphrase-stdin',
        '--value-stdin-base64',
        '--json',
      ],
      `${PASSPHRASE}${multiline}\n`,
    );
    expect(putMulti.exitCode).toBe(0);

    const revealed = await runCli(
      [
        'get',
        'notes/multiline',
        '--reveal',
        '--datastore',
        'file',
        '--data-file',
        target.data,
        '--key-file',
        target.key,
        '--passphrase-stdin',
      ],
      PASSPHRASE,
    );
    expect(revealed.stdout).toBe('line-one\nline-two\n🔐-日本語\n');

    const putEmpty = await runCli(
      [
        'put',
        'placeholders/empty',
        '--datastore',
        'file',
        '--data-file',
        target.data,
        '--key-file',
        target.key,
        '--passphrase-stdin',
        '--value-stdin-base64',
        '--json',
      ],
      `${PASSPHRASE}\n`,
    );
    expect(putEmpty.exitCode).toBe(0);
    const revealedEmpty = await runCli(
      [
        'get',
        'placeholders/empty',
        '--reveal',
        '--datastore',
        'file',
        '--data-file',
        target.data,
        '--key-file',
        target.key,
        '--passphrase-stdin',
      ],
      PASSPHRASE,
    );
    expect(revealedEmpty.stdout).toBe('\n');

    const invalidBase64 = await runCli(
      [
        'put',
        'bad/base64',
        '--datastore',
        'file',
        '--data-file',
        target.data,
        '--key-file',
        target.key,
        '--passphrase-stdin',
        '--value-stdin-base64',
        '--json',
      ],
      `${PASSPHRASE}not!base64!!\n`,
    );
    expect(invalidBase64.exitCode).toBe(2);
  });
});

describe('credential-name hardening', () => {
  it('rejects whitespace, slash abuse, dot segments, and control characters', async () => {
    for (const name of [
      'has space',
      '/leading',
      'trailing/',
      'a//b',
      '.',
      '..',
      'bad\tname',
      'esc\u001bin',
    ]) {
      const result = await runCli(
        [
          'put',
          name,
          ...container.routingArgs,
          '--passphrase-stdin',
          '--value-stdin',
          '--json',
        ],
        `${PASSPHRASE}value\n`,
      );
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain('Credential names must');
    }
  });
});

describe('search semantics', () => {
  it('matches globs case-insensitively by default and substrings literally', async () => {
    const glob = await runCli(
      ['search', 'git*', ...container.routingArgs, '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    expect(glob.exitCode).toBe(0);
    const globResult = JSON.parse(glob.stdout.trim()) as {
      matches: { name: string }[];
    };
    expect(globResult.matches.map((match) => match.name)).toContain('github/token');

    const starWrapped = await runCli(
      ['search', '*TOKEN*', ...container.routingArgs, '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    const starResult = JSON.parse(starWrapped.stdout.trim()) as {
      matches: { name: string }[];
    };
    expect(starResult.matches.map((match) => match.name)).toContain('github/token');

    const sensitive = await runCli(
      [
        'search',
        'GIT*',
        '--case-sensitive',
        ...container.routingArgs,
        '--passphrase-stdin',
        '--json',
      ],
      passphraseFrame(),
    );
    const sensitiveResult = JSON.parse(sensitive.stdout.trim()) as { count: number };
    expect(sensitiveResult.count).toBe(0);
  });
});

describe('reserved vault identifiers at init', () => {
  it('refuses prototype-polluting identifiers with reviewed messages', async () => {
    for (const reserved of ['__proto__', 'constructor', 'prototype']) {
      const target = await legacyPaths();
      const result = await runCli(
        [
          'init',
          '--datastore',
          'file',
          '--vault',
          reserved,
          '--data-file',
          target.data,
          '--key-file',
          target.key,
          '--passphrase-stdin',
        ],
        `${PASSPHRASE}${PASSPHRASE}`,
      );
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain('reserved');
    }
    const invalidTarget = await legacyPaths();
    const invalid = await runCli(
      [
        'init',
        '--datastore',
        'file',
        '--vault',
        '_underscore-leading',
        '--data-file',
        invalidTarget.data,
        '--key-file',
        invalidTarget.key,
        '--passphrase-stdin',
      ],
      `${PASSPHRASE}${PASSPHRASE}`,
    );
    expect(invalid.exitCode).toBe(1);
    expect(invalid.stderr).toContain('Vault identifier is invalid.');
  });
});

describe('stdin frame reference and status', () => {
  it('lists frame contracts and resolves single commands', async () => {
    const all = await runCli(['frames'], '');
    expect(all.exitCode).toBe(0);
    expect(all.stdout).toContain('kavrix db init');
    expect(all.stdout).toContain('destroy');
    const single = await runCli(['frames', 'put'], '');
    expect(single.exitCode).toBe(0);
    expect(single.stdout).toContain('passphrase, value');
    const help = await runCli(['db', 'vault', 'create', '--help'], '');
    expect(help.exitCode).toBe(0);
    expect(help.stdout).toContain('Stdin frames: [mongodb-url,]');
    expect(help.stdout).toContain('passphrase, label.');
    const unknown = await runCli(['frames', 'teleport'], '');
    expect(unknown.exitCode).toBe(2);
  });

  it('reports routing mode and selected profile as JSON', async () => {
    // A non-existent config dir keeps the ambient registry out of the way.
    const absentConfigDir = join(legacyDirectory, 'absent-profiles');
    const bare = await runCli(
      ['status', '--json', '--profile-config-dir', absentConfigDir],
      '',
    );
    expect(bare.exitCode).toBe(0);
    const parsed = JSON.parse(bare.stdout.trim()) as { routing: string };
    expect(parsed.routing).toBe('legacy-v2');
    expect(parsed.version).toBeTruthy();
  });
});

describe('owner-visible vault labels', () => {
  it('redacts by default and reveals labels with --show-labels', async () => {
    const redacted = await runCli(
      ['db', 'vault', 'list', ...ownerRoutingArgs(), '--secrets-stdin', '--json'],
      passphraseFrame(),
    );
    expect(redacted.exitCode).toBe(0);
    const redactedList = JSON.parse(redacted.stdout.trim()) as {
      vaults: { label: string }[];
    };
    expect(redactedList.vaults.length).toBeGreaterThan(0);
    for (const entry of redactedList.vaults) expect(entry.label).toBe('[REDACTED]');

    const shown = await runCli(
      [
        'db',
        'vault',
        'list',
        ...ownerRoutingArgs(),
        '--secrets-stdin',
        '--show-labels',
        '--json',
      ],
      passphraseFrame(),
    );
    expect(shown.exitCode).toBe(0);
    const shownList = JSON.parse(shown.stdout.trim()) as {
      vaults: { id: string; label: string }[];
    };
    expect(shownList.vaults.map((entry) => entry.label)).toContain('main');
  });
});
