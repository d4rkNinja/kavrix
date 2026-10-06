import { rm, stat, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  createExecutionFixture,
  destroyFixture,
  EXEC_PASSPHRASE,
  runCli,
  type ExecutionFixture,
} from './execution-helpers.js';
import { createSecureTestDirectory as mkdtemp } from '../../../packages/key-files/test/secure-temporary-directory.js';
import { parseEnvDocument } from '../src/import-env-command-impl.js';

const PASSPHRASE = `${EXEC_PASSPHRASE}\n`;

let container: ExecutionFixture;
let directory: string;

beforeAll(async () => {
  container = await createExecutionFixture({
    'existing/credential': 'untouched-value',
  });
  directory = await mkdtemp(join(tmpdir(), 'kavrix-import-env-'));
});

afterAll(async () => {
  await destroyFixture(container);
  await rm(directory, { force: true, recursive: true });
});

function routing(): readonly string[] {
  return [...container.routingArgs, '--passphrase-stdin'];
}

describe('kavrix import env', () => {
  it('imports every variable and reveals them back under the chosen prefix', async () => {
    const envPath = join(directory, 'team.env');
    await writeFile(
      envPath,
      [
        '# team secrets',
        '',
        'AWS_KEY=aws-canary-value',
        'export DATABASE_URL=postgres-canary-value',
        'SLACK_WEBHOOK=https://hooks.example/svc',
        '',
      ].join('\n'),
      'utf8',
    );
    const result = await runCli(
      ['import', 'env', '--file', envPath, '--prefix', 'team/', '--json', ...routing()],
      PASSPHRASE,
    );
    expect(result.exitCode).toBe(0);
    const envelope = JSON.parse(result.stdout) as {
      imported: number;
      names: string[];
      sourceDeleted: boolean;
    };
    expect(envelope.imported).toBe(3);
    expect(envelope.names).toEqual([
      'team/AWS_KEY',
      'team/DATABASE_URL',
      'team/SLACK_WEBHOOK',
    ]);
    // Non-TTY run never prompts for deletion; the file stays.
    expect(envelope.sourceDeleted).toBe(false);
    await expect(stat(envPath)).resolves.toBeTruthy();

    for (const [name, expected] of [
      ['team/AWS_KEY', 'aws-canary-value'],
      ['team/DATABASE_URL', 'postgres-canary-value'],
      ['team/SLACK_WEBHOOK', 'https://hooks.example/svc'],
    ] as const) {
      const get = await runCli(
        ['get', name, '--reveal', '--json', ...routing()],
        PASSPHRASE,
      );
      expect(get.exitCode).toBe(0);
      expect((JSON.parse(get.stdout) as { value: string }).value).toBe(expected);
    }

    // The pre-existing credential is untouched.
    const existing = await runCli(
      ['get', 'existing/credential', '--reveal', '--json', ...routing()],
      PASSPHRASE,
    );
    expect((JSON.parse(existing.stdout) as { value: string }).value).toBe(
      'untouched-value',
    );
  });

  it('refuses conflicts without --overwrite and succeeds with it', async () => {
    const envPath = join(directory, 'conflict.env');
    await writeFile(envPath, 'AWS_KEY=replacement-value\n', 'utf8');
    const conflict = await runCli(
      ['import', 'env', '--file', envPath, '--prefix', 'team/', '--json', ...routing()],
      PASSPHRASE,
    );
    expect(conflict.exitCode).toBe(1);
    expect(conflict.stderr).toContain('Credential already exists');
    expect(conflict.stderr).toContain('--overwrite');

    const overwrite = await runCli(
      [
        'import',
        'env',
        '--file',
        envPath,
        '--prefix',
        'team/',
        '--overwrite',
        '--json',
        ...routing(),
      ],
      PASSPHRASE,
    );
    expect(overwrite.exitCode).toBe(0);
    const get = await runCli(
      ['get', 'team/AWS_KEY', '--reveal', '--json', ...routing()],
      PASSPHRASE,
    );
    expect((JSON.parse(get.stdout) as { value: string }).value).toBe(
      'replacement-value',
    );
  });

  it('fails closed on malformed files before requesting any secret', async () => {
    const badPath = join(directory, 'broken.env');
    await writeFile(badPath, 'GOOD_KEY=1\nthis line has no equals\n', 'utf8');
    const result = await runCli(
      ['import', 'env', '--file', badPath, '--json', ...routing()],
      '',
    );
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('Line 2');

    const duplicate = join(directory, 'duplicate.env');
    await writeFile(duplicate, 'A=1\nA=2\n', 'utf8');
    const dup = await runCli(
      ['import', 'env', '--file', duplicate, '--json', ...routing()],
      '',
    );
    expect(dup.exitCode).toBe(1);
    expect(dup.stderr).toContain('duplicate variable "A"');
  });

  it('rejects reserved and hostile names from variables and prefixes', async () => {
    const proto = join(directory, 'proto.env');
    await writeFile(proto, '__proto__=bad\n', 'utf8');
    const reserved = await runCli(
      ['import', 'env', '--file', proto, '--json', ...routing()],
      '',
    );
    expect(reserved.exitCode).toBe(1);
    expect(reserved.stderr).toContain('reserved');

    const spaced = join(directory, 'spaced.env');
    await writeFile(spaced, 'BAD NAME=bad\n', 'utf8');
    const invalid = await runCli(
      ['import', 'env', '--file', spaced, '--json', ...routing()],
      '',
    );
    expect(invalid.exitCode).toBe(1);
    expect(invalid.stderr).toContain('whitespace');
  });

  it('shreds and deletes the source only with --delete-source', async () => {
    const envPath = join(directory, 'shred.env');
    await writeFile(envPath, 'SHREDDED_KEY=shred-canary\n', 'utf8');
    const result = await runCli(
      ['import', 'env', '--file', envPath, '--delete-source', '--json', ...routing()],
      PASSPHRASE,
    );
    expect(result.exitCode).toBe(0);
    expect(
      (JSON.parse(result.stdout) as { sourceDeleted: boolean }).sourceDeleted,
    ).toBe(true);
    expect(existsSync(envPath)).toBe(false);

    const get = await runCli(
      ['get', 'SHREDDED_KEY', '--reveal', '--json', ...routing()],
      PASSPHRASE,
    );
    expect((JSON.parse(get.stdout) as { value: string }).value).toBe('shred-canary');
  });

  it('keeps values out of every rendered surface', async () => {
    const envPath = join(directory, 'canary.env');
    const secret = 'render-canary-secret-value';
    await writeFile(envPath, `CANARY_KEY=${secret}\n`, 'utf8');
    const result = await runCli(
      ['import', 'env', '--file', envPath, '--json', ...routing()],
      PASSPHRASE,
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout).not.toContain(secret);
    expect(result.stderr).not.toContain(secret);
  });

  it('parses strict documents in unit form', () => {
    const entries = parseEnvDocument(
      [
        '# header',
        '',
        'export A=1',
        'B = spaced key is invalid later',
        'C=has=equals',
      ].join('\n'),
    );
    expect(entries.map((entry) => entry.key)).toEqual(['A', 'B', 'C']);
    expect(entries[2]?.value).toBe('has=equals');
    expect(() => parseEnvDocument('NO_EQUALS\n')).toThrow('Line 1');
    expect(() => parseEnvDocument('')).toThrow('no KEY=value entries');
  });
});
