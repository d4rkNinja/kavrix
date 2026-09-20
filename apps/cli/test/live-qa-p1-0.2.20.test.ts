import { writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import {
  createExecutionFixture,
  destroyFixture,
  EXEC_PASSPHRASE,
  passphraseFrame,
  runCli,
  type ExecutionFixture,
} from './execution-helpers.js';

const directories: string[] = [];

afterEach(async () => {
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

async function scratch(label: string): Promise<string> {
  const directory = await createSecureTestDirectory(
    join(tmpdir(), `kavrix-0220-${label}-`),
  );
  directories.push(directory);
  return directory;
}

describe('0.2.20 live-qa P1: run --json auth envelope', () => {
  let fixture: ExecutionFixture;

  afterEach(async () => {
    if (fixture !== undefined) await destroyFixture(fixture);
  });

  it('emits AUTHENTICATION_FAILED JSON on wrong passphrase with --json', async () => {
    fixture = await createExecutionFixture({ alpha: 'canary-alpha' });
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--json',
        '--secret',
        'ALPHA=alpha',
        '--',
        process.execPath,
        '-e',
        'process.stdout.write(process.env.ALPHA ?? "")',
      ],
      'wrong-passphrase!!!!\n',
    );
    expect(result.exitCode).toBe(10);
    const line = result.stdout.trim().split('\n').at(-1) ?? '';
    expect(line.length).toBeGreaterThan(0);
    const body = JSON.parse(line) as {
      error: { code: string; exitCode: number; message: string };
    };
    expect(body.error.code).toBe('AUTHENTICATION_FAILED');
    expect(body.error.exitCode).toBe(10);
    expect(body.error.message).toMatch(/authentication failed/i);
  });
});

describe('0.2.20 live-qa P1: --environment fail-closed / bad cwd yaml', () => {
  let fixture: ExecutionFixture;
  let previousCwd: string;

  afterEach(async () => {
    if (previousCwd !== undefined) process.chdir(previousCwd);
    if (fixture !== undefined) await destroyFixture(fixture);
  });

  it('fails closed when --environment is set without a project file', async () => {
    fixture = await createExecutionFixture({ alpha: 'canary-alpha' });
    const cwd = await scratch('no-project');
    previousCwd = process.cwd();
    process.chdir(cwd);
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--secret',
        'ALPHA=alpha',
        '--environment',
        'staging',
        '--',
        process.execPath,
        '-e',
        'process.stdout.write(process.env.ALPHA ?? "<unset>")',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(14);
    expect(result.stderr).toMatch(/requires a project file|kavrix\.yaml/i);
  });

  it('ignores invalid cwd kavrix.yaml for pure --secret runs', async () => {
    fixture = await createExecutionFixture({ alpha: 'canary-alpha' });
    const cwd = await scratch('bad-yaml');
    await writeFile(join(cwd, 'kavrix.yaml'), 'version: 2\n', 'utf8');
    previousCwd = process.cwd();
    process.chdir(cwd);
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--json',
        '--secret',
        'ALPHA=alpha',
        '--',
        process.execPath,
        '-e',
        'process.stdout.write(process.env.ALPHA ?? "")',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(0);
    // Must not fail closed on cwd kavrix.yaml (exit 14). --json redacts secret bytes.
    expect(result.stderr).not.toMatch(/Project configuration is invalid|Only version 1/i);
    const line = result.stdout.trim().split('\n').at(-1) ?? '';
    const body = JSON.parse(line) as { ran?: boolean; stdout?: string };
    expect(body.ran).toBe(true);
    expect((body.stdout ?? '').length).toBe('canary-alpha'.length);
  });

  it('documents --no-config on run --help', async () => {
    const result = await runCli(['run', '--help'], '');
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toMatch(/--no-config/);
    expect(result.stdout).toMatch(/kavrix\.yaml|Ignore cwd/i);
  });
});

describe('0.2.20 live-qa P1: put missing --value-stdin', () => {
  let fixture: ExecutionFixture;

  afterEach(async () => {
    if (fixture !== undefined) await destroyFixture(fixture);
  });

  it('names Missing --value-stdin when only passphrase-stdin is set', async () => {
    fixture = await createExecutionFixture({ alpha: 'canary-alpha' });
    const result = await runCli(
      ['put', 'beta', ...fixture.routingArgs, '--passphrase-stdin'],
      `${EXEC_PASSPHRASE}\n`,
    );
    expect(result.exitCode).toBe(14);
    expect(result.stderr).toMatch(/Missing --value-stdin/);
  });
});
