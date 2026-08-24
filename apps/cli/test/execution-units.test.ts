import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  executionFlatOptions,
  extractMergedOptions,
} from '../src/execution/cli-options.js';
import type { Command } from 'commander';
import {
  environmentMappings,
  loadProjectConfig,
  projectPolicies,
} from '../src/execution/project-config.js';
import {
  createExecutionFixture,
  destroyFixture,
  passphraseFrame,
  runCli,
} from './execution-helpers.js';

let fixture: Awaited<ReturnType<typeof createExecutionFixture>>;

async function createDenyPolicy(): Promise<void> {
  const result = await runCli(
    [
      'policy',
      'create',
      'rendered-deny',
      ...fixture.routingArgs,
      '--passphrase-stdin',
      '--json',
      '--deny',
      '--secret',
      'production/database',
    ],
    passphraseFrame(),
  );
  expect(result.exitCode).toBe(0);
}

describe('cli option extraction', () => {
  it('applies defaults and explicit overrides predictably', () => {
    const fake = {
      opts: () => ({ vault: 'vault_custom', profile: 'p', jsonFlag: true }),
      getOptionValueSource: (_key: string) => 'explicit',
      parent: null,
    } as unknown as Command;
    const merged = extractMergedOptions(fake);
    expect(merged['vault']).toBe('vault_custom');
    const flat = executionFlatOptions(merged);
    expect(flat.vault).toBe('vault_custom');
    expect(flat.profile).toBe('p');
    expect(flat.databaseUrlStdin).toBe(false);
    const defaulted = executionFlatOptions({} as Readonly<Record<string, unknown>>);
    expect(defaulted.vault).toBe('default');
  });
});

describe('project configuration loading', () => {
  it('parses YAML documents including snake_case aliases', async () => {
    fixture = await createExecutionFixture({});
    try {
      const yamlPath = join(fixture.directory, 'kavrix.yaml');
      await writeFile(
        yamlPath,
        [
          'version: 1',
          'project: yaml-project',
          'environments:',
          '  ci:',
          '    secrets:',
          '      TOKEN_ENV: github/token',
          'policies:',
          '  gh:',
          '    secret: github/token',
          '    commands: [gh]',
          '    max_uses: 4',
          'agents:',
          '  bot:',
          '    permissions:',
          '          ghperm:',
          '            secret: github/token',
          '            commands: [gh]',
          '            env: GITHUB_TOKEN',
          '',
        ].join('\n'),
      );
      const { document } = await loadProjectConfig(yamlPath);
      expect(document.project).toBe('yaml-project');
      expect(environmentMappings(document, 'ci')).toEqual([
        ['TOKEN_ENV', 'github/token'],
      ]);
      const policies = projectPolicies(document);
      expect(policies.get('gh')?.maxUses).toBe(4);
      expect(projectPolicies(document).size).toBe(1);
    } finally {
      await destroyFixture(fixture);
    }
  });

  it('fails closed on malformed or foreign documents', async () => {
    fixture = await createExecutionFixture({});
    try {
      const bad = join(fixture.directory, 'kavrix.json');
      await writeFile(bad, '{ not json');
      await expect(loadProjectConfig(bad)).rejects.toThrow(/valid JSON/u);

      const unknownKey = join(fixture.directory, 'k2.json');
      await writeFile(
        unknownKey,
        JSON.stringify({ version: 1, plaintextSecret: 'nope' }),
      );
      await expect(loadProjectConfig(unknownKey)).rejects.toThrow(/invalid/u);

      const wrongVersion = join(fixture.directory, 'k3.json');
      await writeFile(wrongVersion, JSON.stringify({ version: 9 }));
      await expect(loadProjectConfig(wrongVersion)).rejects.toThrow(/invalid/u);

      const doc = await loadProjectConfig(join(fixture.directory, 'k4.json')).catch(
        () => null,
      );
      expect(doc).toBeNull();
      void passphraseFrame;
    } finally {
      await destroyFixture(fixture);
    }
  });

  it('rejects mappings for undefined environments', async () => {
    fixture = await createExecutionFixture({});
    try {
      const configFile = join(fixture.directory, 'k5.json');
      await writeFile(configFile, JSON.stringify({ version: 1 }));
      const { document } = await loadProjectConfig(configFile);
      expect(() => environmentMappings(document, 'missing-env')).toThrow(
        /not defined/u,
      );
    } finally {
      await destroyFixture(fixture);
    }
  });
});

describe('human-rendered command output', () => {
  it('renders policies, grants, and audit without --json', async () => {
    fixture = await createExecutionFixture({
      'github/token': 'renderer-canary',
    });
    try {
      const created = await runCli(
        [
          'policy',
          'create',
          'rendered-policy',
          ...fixture.routingArgs,
          '--passphrase-stdin',
          '--secret',
          'github/token',
          '--command',
          'node',
          '--ttl',
          '15m',
          '--reveal',
        ],
        passphraseFrame(),
      );
      expect(created.exitCode).toBe(0);
      await createDenyPolicy();
      const listed = await runCli(
        ['policy', 'list', ...fixture.routingArgs, '--passphrase-stdin'],
        passphraseFrame(),
      );
      expect(listed.stdout).toContain('rendered-policy');
      expect(listed.stdout).toContain('node');
      expect(listed.stdout).toContain('reveal=true');
      expect(listed.stdout).toContain('ttl=15m');
      expect(listed.stdout).toContain('DENY');

      const granted = await runCli(
        [
          'grant',
          'create',
          'github/token',
          '--command',
          'node',
          '--ttl',
          '1h',
          ...fixture.routingArgs,
          '--passphrase-stdin',
        ],
        passphraseFrame(),
      );
      expect(granted.exitCode).toBe(0);
      const grants = await runCli(
        ['grant', 'list', ...fixture.routingArgs, '--passphrase-stdin'],
        passphraseFrame(),
      );
      expect(grants.stdout).toContain('status=active');

      const audit = await runCli(
        ['audit', '--limit', '10', ...fixture.routingArgs, '--passphrase-stdin'],
        passphraseFrame(),
      );
      expect(audit.stdout).toContain('policy-created');
      expect(audit.stdout).toContain('actor=user');
      expect(audit.stdout).not.toContain('renderer-canary');

      // Default limit branch plus show/remove/revoke human renderers.
      const defaultAudit = await runCli(
        ['audit', ...fixture.routingArgs, '--passphrase-stdin'],
        passphraseFrame(),
      );
      expect(defaultAudit.exitCode).toBe(0);
      const shown = await runCli(
        [
          'policy',
          'show',
          'rendered-policy',
          ...fixture.routingArgs,
          '--passphrase-stdin',
        ],
        passphraseFrame(),
      );
      expect(shown.stdout).toContain('rendered-policy');
      const removed = await runCli(
        [
          'policy',
          'remove',
          'rendered-policy',
          ...fixture.routingArgs,
          '--passphrase-stdin',
        ],
        passphraseFrame(),
      );
      expect(removed.stdout).toContain('rendered-policy');
    } finally {
      await destroyFixture(fixture);
    }
  });

  it('rejects invalid limits and bare grants without secrets', async () => {
    fixture = await createExecutionFixture({});
    try {
      const badLimit = await runCli(
        ['audit', '--limit', '0', ...fixture.routingArgs, '--passphrase-stdin'],
        passphraseFrame(),
      );
      expect(badLimit.exitCode).toBe(14);
      expect(badLimit.stderr).toContain('--limit expects');

      const bareGrant = await runCli(['grant'], passphraseFrame());
      expect(bareGrant.exitCode).toBe(2);
      expect(bareGrant.stderr).toContain('Specify a secret');

      const noTtl = await runCli(
        [
          'grant',
          'create',
          'some/secret',
          '--command',
          'x',
          ...fixture.routingArgs,
          '--passphrase-stdin',
        ],
        passphraseFrame(),
      );
      expect(noTtl.exitCode).toBe(14);
      expect(noTtl.stderr).toContain('--ttl is required');
    } finally {
      await destroyFixture(fixture);
    }
  });
});
