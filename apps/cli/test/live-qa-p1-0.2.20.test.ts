import { writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

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
const originalCwd = process.cwd();

afterEach(async () => {
  process.chdir(originalCwd);
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) =>
      rm(directory, { force: true, recursive: true }).catch(() => undefined),
    ),
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

  beforeAll(async () => {
    fixture = await createExecutionFixture({ alpha: 'canary-alpha' });
  }, 180_000);

  afterAll(async () => {
    process.chdir(originalCwd);
    if (fixture !== undefined) await destroyFixture(fixture);
  });

  afterEach(() => {
    process.chdir(originalCwd);
  });

  it('fails closed when --environment is set without a project file', async () => {
    const cwd = await scratch('no-project');
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
    const cwd = await scratch('bad-yaml');
    await writeFile(join(cwd, 'kavrix.yaml'), 'version: 2\n', 'utf8');
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
    expect(result.stderr).not.toMatch(
      /Project configuration is invalid|Only version 1/i,
    );
    const line = result.stdout.trim().split('\n').at(-1) ?? '';
    const body = JSON.parse(line) as { ran?: boolean; stdout?: string };
    expect(body.ran).toBe(true);
    expect((body.stdout ?? '').length).toBe('canary-alpha'.length);
  });

  it('documents --no-config on run --help', async () => {
    const result = await runCli(['run', '--help'], '');
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toMatch(/--no-config\s+Skip project configuration:/);
  });

  it('fails closed when --no-config is combined with --environment', async () => {
    const cwd = await scratch('no-config-env');
    await writeFile(join(cwd, 'kavrix.yaml'), 'version: 2\n', 'utf8');
    process.chdir(cwd);
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--no-config',
        '--environment',
        'staging',
        '--secret',
        'ALPHA=alpha',
        '--',
        process.execPath,
        '-e',
        'process.stdout.write(process.env.ALPHA ?? "<unset>")',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).not.toBe(0);
    expect(result.exitCode).toBe(14);
    expect(result.stderr).toMatch(
      /--environment requires a project file|cannot be combined with --no-config/i,
    );
    expect(result.stdout).not.toContain('canary-alpha');
  });

  it('emits INVALID_CONFIGURATION JSON when --no-config is combined with --environment', async () => {
    const cwd = await scratch('no-config-env-json');
    process.chdir(cwd);
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--json',
        '--no-config',
        '--environment',
        'staging',
        '--secret',
        'ALPHA=alpha',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(14);
    const line = result.stdout.trim().split('\n').at(-1) ?? '';
    expect(line.length).toBeGreaterThan(0);
    const body = JSON.parse(line) as {
      error: { code: string; exitCode: number; message: string };
    };
    expect(body.error.code).toBe('INVALID_CONFIGURATION');
    expect(body.error.exitCode).toBe(14);
    expect(body.error.message).toMatch(
      /--environment requires a project file|cannot be combined with --no-config/i,
    );
    expect(result.stderr.trim()).toBe('');
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

describe('0.2.20 live-qa P2: spawn miss, reserved dest, unlock length, json channel', () => {
  let fixture: ExecutionFixture;

  afterEach(async () => {
    if (fixture !== undefined) await destroyFixture(fixture);
  });

  it('emits EXECUTION_FAILED JSON for a missing child without AUTHORIZATION_DENIED', async () => {
    fixture = await createExecutionFixture({ alpha: 'canary-alpha' });
    const missing = join(tmpdir(), 'kavrix-no-such-bin', 'missing-child');
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--json',
        '--secret',
        'ALPHA=alpha',
        '--',
        missing,
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(18);
    const line = result.stdout.trim().split('\n').at(-1) ?? '';
    const body = JSON.parse(line) as {
      error: { code: string; exitCode: number };
    };
    expect(body.error.code).toBe('EXECUTION_FAILED');
    expect(body.error.exitCode).toBe(18);
    expect(result.stderr).not.toMatch(/authorization denied|AUTHORIZATION_DENIED/i);
    expect(result.stderr.trim()).toBe('');
  });

  it('fails closed when a secret destination would overwrite USER', async () => {
    fixture = await createExecutionFixture({ alpha: 'canary-alpha' });
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--secret',
        'USER=alpha',
        '--',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(14);
    expect(result.stderr).toMatch(/protected/i);
  });

  it('maps a short wrong unlock passphrase to auth failure, not length usage', async () => {
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
        'process.exit(0)',
      ],
      'short\n',
    );
    expect(result.exitCode).toBe(10);
    const line = result.stdout.trim().split('\n').at(-1) ?? '';
    const body = JSON.parse(line) as {
      error: { code: string; exitCode: number };
    };
    expect(body.error.code).toBe('AUTHENTICATION_FAILED');
    expect(result.stderr.trim()).toBe('');
  });

  it('runs the child without requiring `--`', async () => {
    fixture = await createExecutionFixture({ alpha: 'canary-alpha' });
    const result = await runCli(
      [
        'run',
        ...fixture.routingArgs,
        '--passphrase-stdin',
        '--json',
        '--secret',
        'ALPHA=alpha',
        process.execPath,
        '-e',
        'process.exit(0)',
      ],
      passphraseFrame(),
    );
    expect(result.exitCode).toBe(0);
    const line = result.stdout.trim().split('\n').at(-1) ?? '';
    const body = JSON.parse(line) as { ran?: boolean; exitCode?: number };
    expect(body.ran).toBe(true);
    expect(body.exitCode).toBe(0);
  });

  it('keeps --json auth failure on stdout only (no human duplicate)', async () => {
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
        'process.exit(0)',
      ],
      'wrong-passphrase!!!!\n',
    );
    expect(result.exitCode).toBe(10);
    expect(result.stdout).toMatch(/AUTHENTICATION_FAILED/);
    expect(result.stderr.trim()).toBe('');
  });
});

describe('0.2.20 live-qa P1: vault-read --json auth envelope', () => {
  let fixture: ExecutionFixture;

  beforeAll(async () => {
    fixture = await createExecutionFixture({ alpha: 'canary-alpha' });
  }, 180_000);

  afterAll(async () => {
    if (fixture !== undefined) await destroyFixture(fixture);
  });

  it.each([
    ['list', ['list']],
    ['get', ['get', 'alpha']],
    ['has', ['has', 'alpha']],
    ['search', ['search', 'alp*']],
  ] as const)(
    'emits AUTHENTICATION_FAILED JSON on wrong passphrase for %s --json',
    async (_label, command) => {
      const wrongPassphrase = 'wrong-passphrase!!!!';
      const result = await runCli(
        [...command, ...fixture.routingArgs, '--passphrase-stdin', '--json'],
        `${wrongPassphrase}\n`,
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
      expect(body.error.message).not.toContain(wrongPassphrase);
      expect(result.stdout).not.toContain(wrongPassphrase);
      expect(result.stderr).not.toContain(wrongPassphrase);
      expect(result.stderr.trim()).toBe('');
    },
    180_000,
  );
});
