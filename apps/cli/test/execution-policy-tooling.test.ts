import { access, readFile } from 'node:fs/promises';

import { authorizationStatePath } from '@kavrix/key-files';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  createExecutionFixture,
  destroyFixture,
  passphraseFrame,
  runCli,
  type ExecutionFixture,
} from './execution-helpers.js';

let fixture: ExecutionFixture;

beforeEach(async () => {
  fixture = await createExecutionFixture({
    'github/token': 'policy-tooling-plaintext-canary',
    'production/database': 'policy-binding-secondary-canary',
  });
});

afterEach(async () => {
  await destroyFixture(fixture);
});

function metadataRouting(): string[] {
  const args = [...fixture.routingArgs];
  const vaultIndex = args.indexOf('--vault');
  if (vaultIndex >= 0) args.splice(vaultIndex, 2);
  return args;
}

function parseJson(stdout: string): Record<string, unknown> {
  return JSON.parse(stdout.trim().split('\n').at(-1) ?? '{}') as Record<
    string,
    unknown
  >;
}

async function createPolicy(
  id: string,
  definitionArgs: readonly string[],
): Promise<void> {
  const result = await runCli(
    [
      'policy',
      'create',
      id,
      ...metadataRouting(),
      '--passphrase-stdin',
      '--json',
      ...definitionArgs,
    ],
    passphraseFrame(),
  );
  expect(result.exitCode, result.stderr).toBe(0);
  expect(parseJson(result.stdout)['saved']).toBe(true);
}

async function auditTotal(): Promise<number> {
  const result = await runCli(
    ['audit', ...metadataRouting(), '--passphrase-stdin', '--json'],
    passphraseFrame(),
  );
  expect(result.exitCode, result.stderr).toBe(0);
  return Number(parseJson(result.stdout)['total']);
}

describe('read-only policy developer tooling', () => {
  it('treats a missing sidecar as empty without creating it', async () => {
    const stateFile = authorizationStatePath(fixture.keyFile);
    await expect(access(stateFile)).rejects.toBeDefined();

    const linted = await runCli(
      ['policy', 'lint', ...metadataRouting(), '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );

    expect(linted.exitCode, linted.stderr).toBe(0);
    expect(parseJson(linted.stdout)).toMatchObject({
      checkedPolicies: 0,
      checkedGrants: 0,
      errors: 0,
      warnings: 0,
      findings: [],
    });
    await expect(access(stateFile)).rejects.toBeDefined();
  });

  it('checks, explains, lints, and diffs without reading or mutating credentials', async () => {
    await createPolicy('node-only', [
      '--secret',
      'github/token',
      '--command',
      'node',
      '--ttl',
      '30s',
      '--require-confirmation',
      'deploy',
    ]);
    const stateFile = authorizationStatePath(fixture.keyFile);
    const beforeState = await readFile(stateFile);
    const beforeAudit = await auditTotal();

    const allowed = await runCli(
      [
        'policy',
        'check',
        'node-only',
        ...metadataRouting(),
        '--passphrase-stdin',
        '--json',
        '--',
        process.execPath,
        'status',
      ],
      passphraseFrame(),
    );
    expect(allowed.exitCode, allowed.stderr).toBe(0);
    expect(parseJson(allowed.stdout)).toMatchObject({
      outcome: 'allow',
      reason: 'policy-allowed',
      credentialRead: false,
      executionWindowMs: 30_000,
    });

    const confirmation = await runCli(
      [
        'policy',
        'check',
        'node-only',
        ...metadataRouting(),
        '--passphrase-stdin',
        '--json',
        '--',
        process.execPath,
        'deploy',
      ],
      passphraseFrame(),
    );
    expect(confirmation.exitCode).toBe(17);
    expect(parseJson(confirmation.stdout)).toMatchObject({
      outcome: 'confirm',
      reason: 'confirmation-required',
      credentialRead: false,
    });

    const denied = await runCli(
      [
        'policy',
        'check',
        'node-only',
        ...metadataRouting(),
        '--passphrase-stdin',
        '--json',
        '--',
        'definitely-not-a-real-executable',
      ],
      passphraseFrame(),
    );
    expect(denied.exitCode).toBe(12);
    expect(parseJson(denied.stdout)).toMatchObject({
      outcome: 'deny',
      reason: 'executable-unresolved',
      credentialRead: false,
    });

    const deniedExplanation = await runCli(
      [
        'policy',
        'explain',
        'node-only',
        ...metadataRouting(),
        '--passphrase-stdin',
        '--json',
        '--',
        'definitely-not-a-real-executable',
      ],
      passphraseFrame(),
    );
    expect(deniedExplanation.exitCode, deniedExplanation.stderr).toBe(0);
    expect(parseJson(deniedExplanation.stdout)['decision']).toMatchObject({
      outcome: 'deny',
      reason: 'executable-unresolved',
    });

    const explained = await runCli(
      [
        'policy',
        'explain',
        'node-only',
        ...metadataRouting(),
        '--passphrase-stdin',
        '--json',
        '--',
        process.execPath,
        'status',
      ],
      passphraseFrame(),
    );
    expect(explained.exitCode, explained.stderr).toBe(0);
    const explanation = parseJson(explained.stdout);
    expect(explanation['credentialRead']).toBe(false);
    expect(
      (explanation['checks'] as Array<Record<string, unknown>>).map(
        (check) => check['kind'],
      ),
    ).toEqual(['deny', 'command', 'hash', 'directory', 'ttl', 'confirmation']);

    const diffed = await runCli(
      [
        'policy',
        'diff',
        'node-only',
        ...metadataRouting(),
        '--passphrase-stdin',
        '--json',
        '--secret',
        'github/token',
        '--command',
        'node',
        '--command',
        'git',
        '--ttl',
        '30s',
        '--require-confirmation',
        'deploy',
      ],
      passphraseFrame(),
    );
    expect(diffed.exitCode, diffed.stderr).toBe(0);
    expect(parseJson(diffed.stdout)).toMatchObject({
      operation: 'replace',
      changed: true,
    });
    expect(
      (parseJson(diffed.stdout)['changes'] as Array<Record<string, unknown>>).find(
        (change) => change['field'] === 'commands',
      ),
    ).toMatchObject({ impact: 'widens' });

    const linted = await runCli(
      ['policy', 'lint', ...metadataRouting(), '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    expect(linted.exitCode, linted.stderr).toBe(0);
    expect(parseJson(linted.stdout)['checkedPolicies']).toBe(1);

    const suggested = await runCli(
      ['policy', 'suggest', ...metadataRouting(), '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    expect(suggested.exitCode, suggested.stderr).toBe(0);
    expect(parseJson(suggested.stdout)).toMatchObject({
      reviewOnly: true,
      suggestions: [],
    });

    const shown = await runCli(
      [
        'policy',
        'show',
        'node-only',
        ...metadataRouting(),
        '--passphrase-stdin',
        '--json',
      ],
      passphraseFrame(),
    );
    expect(parseJson(shown.stdout)['commands']).toEqual(['node']);
    expect(await auditTotal()).toBe(beforeAudit);
    await expect(readFile(stateFile)).resolves.toEqual(beforeState);
    expect(
      [
        allowed.stdout,
        confirmation.stdout,
        denied.stdout,
        deniedExplanation.stdout,
        explained.stdout,
        diffed.stdout,
        linted.stdout,
        suggested.stdout,
        shown.stdout,
      ].join(''),
    ).not.toContain('policy-tooling-plaintext-canary');
  });

  it('returns CI-visible lint errors for shadowed policies', async () => {
    await createPolicy('allowed', ['--secret', 'github/token', '--command', 'node']);
    await createPolicy('blocked', ['--secret', 'github/token', '--deny']);

    const linted = await runCli(
      ['policy', 'lint', ...metadataRouting(), '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    const result = parseJson(linted.stdout);

    expect(linted.exitCode).toBe(14);
    expect(result['errors']).toBeGreaterThan(0);
    expect(result['findings']).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'credential-covered-by-deny',
          targetId: 'allowed',
        }),
      ]),
    );
  });
});

describe('grant inspection and least-privilege suggestions', () => {
  it('shows remaining uses, expiry, and effective restrictions', async () => {
    const created = await runCli(
      [
        'grant',
        'create',
        'github/token',
        ...metadataRouting(),
        '--passphrase-stdin',
        '--json',
        '--command',
        'node',
        '--ttl',
        '1h',
        '--max-uses',
        '3',
      ],
      passphraseFrame(),
    );
    expect(created.exitCode, created.stderr).toBe(0);
    const grantId = String(parseJson(created.stdout)['grantId']);

    const shown = await runCli(
      ['grant', 'show', grantId, ...metadataRouting(), '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    const inspection = parseJson(shown.stdout);

    expect(shown.exitCode, shown.stderr).toBe(0);
    expect(inspection).toMatchObject({
      grantId,
      status: 'active',
      usedCount: 0,
      maxUses: 3,
      remainingUses: 3,
    });
    expect(inspection['expiresInMs']).toBeGreaterThan(0);
    expect(inspection['restrictions']).toMatchObject({
      actor: 'user',
      commands: ['node'],
      remainingUses: 3,
      revoked: false,
    });
  });

  it('suggests only review-only narrowing from successful sanitized events', async () => {
    await createPolicy('node-tools', ['--secret', 'github/token', '--command', 'node']);
    const ran = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--secret',
        'SERVICE_TOKEN=github/token',
        '--policy',
        'node-tools',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(ran.exitCode, ran.stderr).toBe(0);
    await createPolicy('node-tools', [
      '--secret',
      'github/token',
      '--command',
      'node',
      '--command',
      'git',
    ]);

    const suggested = await runCli(
      ['policy', 'suggest', ...metadataRouting(), '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    const result = parseJson(suggested.stdout);
    const suggestions = result['suggestions'] as Array<Record<string, unknown>>;

    expect(suggested.exitCode, suggested.stderr).toBe(0);
    expect(result).toMatchObject({
      reviewOnly: true,
      coverage: 'incomplete-bounded-audit-ring',
    });
    expect(suggestions).toEqual([
      expect.objectContaining({
        policyId: 'node-tools',
        currentCommands: ['node', 'git'],
        proposedCommands: ['node'],
        reviewRequired: true,
        confidence: 'low',
      }),
    ]);
    expect(suggested.stdout).not.toContain('policy-tooling-plaintext-canary');
  });

  it('keeps policy simulation and execution aligned with covering denies', async () => {
    await createPolicy('allow-a', ['--secret', 'github/token', '--command', 'node']);
    await createPolicy('deny-a', ['--secret', 'github/token', '--deny']);

    const checked = await runCli(
      [
        'policy',
        'check',
        'allow-a',
        ...metadataRouting(),
        '--passphrase-stdin',
        '--json',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    const executed = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--policy',
        'allow-a',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );

    expect(checked.exitCode, checked.stderr).toBe(12);
    expect(parseJson(checked.stdout)).toMatchObject({
      outcome: 'deny',
      reason: 'policy-denied',
      matchedPolicyId: 'deny-a',
    });
    expect(executed.exitCode).toBe(12);
    expect(executed.stderr).toContain("'deny-a'");
  });

  it('rejects explicit credentials not covered by selected policies', async () => {
    await createPolicy('allow-a', ['--secret', 'github/token', '--command', 'node']);

    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--secret',
        'DB_PASSWORD=production/database',
        '--policy',
        'allow-a',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );

    expect(result.exitCode).toBe(12);
    expect(result.stderr).toContain('not covered by a selected policy');
  });
});
