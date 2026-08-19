import { timestampSchema, vaultIdSchema, vaultRevisionSchema } from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import {
  buildLocalCli,
  renderSearchResult,
  renderVaultStats,
  renderVaultView,
} from '../src/local-vault-cli.js';

const document = {
  id: vaultIdSchema.parse('team'),
  revision: vaultRevisionSchema.parse(3),
  updatedAt: timestampSchema.parse('2026-08-18T10:20:30.000Z'),
};

const entries = [
  [
    'github-token',
    {
      value: 'super-secret-token',
      updatedAt: timestampSchema.parse('2026-08-18T09:20:30.000Z'),
    },
  ],
] as const;

describe('local vault command surface', () => {
  it('registers working view, search, and stats commands', () => {
    const cli = buildLocalCli();
    const commandNames = cli.commands.map((command) => command.name());
    expect(commandNames).toEqual(
      expect.arrayContaining([
        'db',
        'view',
        'search',
        'stats',
        'recovery',
        'vault',
        'key',
        'put',
        'get',
        'remove',
        'has',
        'rename',
        'doctor',
      ]),
    );
    const db = cli.commands.find((command) => command.name() === 'db');
    const profile = db?.commands.find((command) => command.name() === 'profile');
    expect(profile?.commands.map((command) => command.name())).toEqual([
      'add',
      'list',
      'use',
      'status',
      'remove',
    ]);
    const profileAdd = profile?.commands.find((command) => command.name() === 'add');
    expect(profileAdd?.options.map((option) => option.long)).toEqual(
      expect.arrayContaining([
        '--config-dir',
        '--datastore',
        '--database-id',
        '--database',
        '--database-collection',
        '--vault-collection',
        '--data-file',
        '--key-file',
      ]),
    );
    expect(profileAdd?.options.map((option) => option.long)).not.toContain(
      '--database-url-stdin',
    );
    const doctor = cli.commands.find((command) => command.name() === 'doctor');
    expect(doctor?.commands.map((command) => command.name())).toContain('health');
    const health = doctor?.commands.find((command) => command.name() === 'health');
    expect(health?.options.map((option) => option.long)).toContain('--accept-current');
    expect(cli.helpInformation()).not.toContain('destroy');
    const destroy = cli.commands.find((command) => command.name() === 'destroy');
    expect(destroy).toBeDefined();
    expect(destroy?.options.map((option) => option.long)).not.toContain('--help');
  });

  it('renders a masked vault view without leaking credential values', () => {
    const output = renderVaultView(document, entries, false);
    expect(output).toContain('KAVRIX / VAULT VIEW');
    expect(output).toContain('github-token');
    expect(output).toContain('[REDACTED]');
    expect(output).not.toContain('super-secret-token');
    expect(output).not.toContain('\u001b');
  });

  it('renders one explicitly revealed credential as a card', () => {
    const output = renderVaultView(document, entries, true);
    expect(output).toContain('Credential: github-token');
    expect(output).toContain('super-secret-token');
  });

  it('replaces terminal control characters before rendering a revealed value', () => {
    const output = renderVaultView(
      document,
      [
        [
          'hostile\u001b[31m-name',
          {
            value: 'secret\u0007\u001b]8;;https://example.invalid\u0007',
            updatedAt: timestampSchema.parse('2026-08-18T09:20:30.000Z'),
          },
        ],
      ],
      true,
    );
    expect(output).not.toContain('\u001b');
    expect(output).toContain('[CONTROL]');
    expect(output).toContain('https://example.invalid');
  });

  it('renders empty search and vault statistics safely', () => {
    const search = renderSearchResult({
      vaultId: 'team',
      revision: 3,
      pattern: 'missing',
      count: 0,
      truncated: false,
      matches: [],
    });
    expect(search).toContain('No credential names matched.');
    expect(search).not.toContain('\u001b');

    const stats = renderVaultStats({
      vaultId: 'team',
      revision: 3,
      currentKeyVersion: 1,
      credentialCount: 1,
      oldestCredentialAt: '2026-08-18T09:20:30.000Z',
      newestCredentialAt: '2026-08-18T09:20:30.000Z',
      updatedAt: '2026-08-18T10:20:30.000Z',
    });
    expect(stats).toContain('Credentials:        1');
    expect(stats).not.toContain('super-secret-token');
    expect(stats).not.toContain('\u001b');
  });
});
