import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

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
    'github/token': 'policy-canary-token',
    'production/database': 'policy-canary-db',
  });
});

afterEach(async () => {
  await destroyFixture(fixture);
});

function routing(): string[] {
  return [...fixture.routingArgs];
}

interface JsonLine {
  saved?: boolean;
  granted?: boolean;
  grantId?: string;
  id?: string;
  removed?: boolean;
  revoked?: boolean;
  policies?: unknown[];
  grants?: unknown[];
  events?: Array<Record<string, unknown>>;
  total?: number;
  error?: { code: string; exitCode: number; message: string };
}

function parseLast(output: string): JsonLine {
  const line = output.trim().split('\n').at(-1) ?? '';
  return JSON.parse(line) as JsonLine;
}

async function createPolicy(id: string, args: readonly string[]): Promise<void> {
  const result = await runCli(
    ['policy', 'create', id, ...routing(), '--passphrase-stdin', '--json', ...args],
    passphraseFrame(),
  );
  expect(
    result.exitCode,
    `policy create failed | out=${result.stdout.slice(0, 300)} | err=${result.stderr.slice(0, 300)}`,
  ).toBe(0);
  expect(parseLast(result.stdout).saved).toBe(true);
}

describe('stored policy lifecycle', () => {
  it('creates, lists, shows, replaces, and removes policies', async () => {
    await createPolicy('gh-only', [
      '--secret',
      'github/token',
      '--command',
      'gh',
      '--command',
      'git',
    ]);

    const listed = await runCli(
      ['policy', 'list', ...routing(), '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    const policies = parseLast(listed.stdout).policies as Array<
      Record<string, unknown>
    >;
    expect(policies.map((entry) => entry['id'])).toEqual(['gh-only']);
    expect(policies[0]?.['commands']).toEqual(['gh', 'git']);

    const shown = await runCli(
      ['policy', 'show', 'gh-only', ...routing(), '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    expect(parseLast(shown.stdout).id).toBe('gh-only');

    // Replacement is explicit and complete.
    await createPolicy('gh-only', ['--secret', 'github/token', '--command', 'gh']);
    const relisted = JSON.parse(
      (
        await runCli(
          ['policy', 'list', ...routing(), '--passphrase-stdin', '--json'],
          passphraseFrame(),
        )
      ).stdout
        .trim()
        .split('\n')
        .at(-1) ?? '{}',
    ) as JsonLine;
    expect(
      (relisted.policies as Array<Record<string, unknown>>)[0]?.['commands'],
    ).toEqual(['gh']);

    const removed = await runCli(
      ['policy', 'remove', 'gh-only', ...routing(), '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    expect(parseLast(removed.stdout).removed).toBe(true);

    const missing = await runCli(
      ['policy', 'show', 'gh-only', ...routing(), '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    expect(missing.exitCode).toBe(13);
    expect(missing.stderr).toContain('was not found');
  });

  it('shows every optional field a fully-specified policy carries', async () => {
    await createPolicy('full-spec', [
      '--secret',
      'github/token',
      '--command',
      'gh',
      '--hash',
      `gh=${'a'.repeat(64)}`,
      '--env',
      'GITHUB_TOKEN',
      '--ttl',
      '30m',
      '--max-uses',
      '5',
      '--require-confirmation',
      'push,pr',
    ]);
    const shown = await runCli(
      ['policy', 'show', 'full-spec', ...routing(), '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    const record = parseLast(shown.stdout);
    expect(record.id).toBe('full-spec');
    expect(record.commands).toEqual(['gh']);
    expect(record.env).toBe('GITHUB_TOKEN');
    expect(record.ttl).toBe('30m');
    expect(record.maxUses).toBe(5);
    expect(record.requireConfirmation).toEqual(['push', 'pr']);
  });

  it('rejects incomplete policy definitions without leaking values', async () => {
    const result = await runCli(
      [
        'policy',
        'create',
        'broken',
        ...routing(),
        '--passphrase-stdin',
        '--secret',
        'policy-canary-token',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(14);
    expect(result.stderr).toContain('incomplete or invalid');
    expect(result.stderr).not.toContain('policy-canary-token');
  });
});

describe('temporary grants', () => {
  it('issues a grant through the documented bare form and consumes one use per run', async () => {
    const created = await runCli(
      [
        'grant',
        'github/token',
        '--command',
        'node',
        '--ttl',
        '1h',
        '--max-uses',
        '2',
        ...routing(),
        '--passphrase-stdin',
        '--json',
      ],
      passphraseFrame(),
    );
    expect(
      created.exitCode,
      `bare grant failed | out=${created.stdout.slice(0, 300)} | err=${created.stderr.slice(0, 300)}`,
    ).toBe(0);
    const grantId = parseLast(created.stdout).grantId ?? '';
    expect(grantId.startsWith('grant_')).toBe(true);

    const firstRun = await runCli(
      [
        'run',
        '--grant',
        grantId,
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(firstRun.exitCode).toBe(0);

    const listAfterOne = parseLast(
      (
        await runCli(
          ['grant', 'list', ...routing(), '--passphrase-stdin', '--json'],
          passphraseFrame(),
        )
      ).stdout,
    );
    expect(
      (listAfterOne.grants as Array<Record<string, unknown>>)[0]?.['usedCount'],
    ).toBe(1);

    const secondRun = await runCli(
      [
        'run',
        '--grant',
        grantId,
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(secondRun.exitCode).toBe(0);

    const exhausted = await runCli(
      [
        'run',
        '--grant',
        grantId,
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(exhausted.exitCode).toBe(13);
    expect(exhausted.stderr).toContain('no remaining uses');
  });

  it('resolves grants by credential name and denies unlisted executables', async () => {
    const created = await runCli(
      [
        'grant',
        'create',
        'github/token',
        '--command',
        'curl',
        '--ttl',
        '1h',
        ...routing(),
        '--passphrase-stdin',
        '--json',
      ],
      passphraseFrame(),
    );
    expect(
      created.exitCode,
      `named-create | out=${created.stdout.slice(0, 250)} | err=${created.stderr.slice(0, 250)}`,
    ).toBe(0);
    expect(parseLast(created.stdout).granted).toBe(true);

    const denied = await runCli(
      [
        'run',
        '--grant',
        'github/token',
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(
      denied.exitCode,
      `denied-run | out=${denied.stdout.slice(0, 250)} | err=${denied.stderr.slice(0, 250)}`,
    ).toBe(12);
    expect(denied.stderr).toContain('does not allow this executable');
  });

  it('expires grants after their ttl and reports expiry distinctly', async () => {
    const created = await runCli(
      [
        'grant',
        'create',
        'github/token',
        '--command',
        'node',
        '--ttl',
        '1s',
        ...routing(),
        '--passphrase-stdin',
        '--json',
      ],
      passphraseFrame(),
    );
    const grantId = parseLast(created.stdout).grantId ?? '';
    await new Promise((resolve) => setTimeout(resolve, 1400));

    const expired = await runCli(
      [
        'run',
        '--grant',
        grantId,
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(expired.exitCode).toBe(13);
    expect(expired.stderr).toContain('expired');
  });

  it('revokes grants so later runs are denied', async () => {
    const created = await runCli(
      [
        'grant',
        'create',
        'github/token',
        '--command',
        'node',
        '--ttl',
        '1h',
        ...routing(),
        '--passphrase-stdin',
        '--json',
      ],
      passphraseFrame(),
    );
    const grantId = parseLast(created.stdout).grantId ?? '';

    const revoked = await runCli(
      ['grant', 'revoke', grantId, ...routing(), '--passphrase-stdin', '--json'],
      passphraseFrame(),
    );
    expect(parseLast(revoked.stdout).revoked).toBe(true);

    const afterRevoke = await runCli(
      [
        'run',
        '--grant',
        grantId,
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    // Revoked, like expired and exhausted, maps to the stable grant-invalid code.
    expect(
      afterRevoke.exitCode,
      `post-revoke | err=${afterRevoke.stderr.slice(0, 250)}`,
    ).toBe(13);
    expect(afterRevoke.stderr).toContain('revoked');
  });

  it('enforces grant hash pins end to end', async () => {
    const created = await runCli(
      [
        'grant',
        'create',
        'github/token',
        '--command',
        'node',
        '--hash',
        `node=${'e'.repeat(64)}`,
        '--ttl',
        '1h',
        ...routing(),
        '--passphrase-stdin',
        '--json',
      ],
      passphraseFrame(),
    );
    expect(created.exitCode).toBe(0);

    const mismatch = await runCli(
      [
        'run',
        '--grant',
        parseLast(created.stdout).grantId ?? '',
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(mismatch.exitCode).toBe(12);
    expect(mismatch.stderr).toContain('does not match the grant pin');
  });

  it('rejects grant env destinations that conflict with explicit mappings', async () => {
    const created = await runCli(
      [
        'grant',
        'create',
        'github/token',
        '--command',
        'node',
        '--env',
        'CONFLICT_VAR',
        '--ttl',
        '1h',
        ...routing(),
        '--passphrase-stdin',
        '--json',
      ],
      passphraseFrame(),
    );
    expect(created.exitCode).toBe(0);

    const conflicted = await runCli(
      [
        'run',
        '--secret',
        'CONFLICT_VAR=production/database',
        '--grant',
        parseLast(created.stdout).grantId ?? '',
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(conflicted.exitCode).toBe(14);
    expect(conflicted.stderr).toContain('CONFLICT_VAR');
  });

  it('fails closed when a grant reference matches nothing', async () => {
    const result = await runCli(
      [
        'run',
        '--grant',
        'absent-or-expired',
        ...routing(),
        '--passphrase-stdin',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(13);
    expect(result.stderr).toContain('No active grant matches');
  });
});
