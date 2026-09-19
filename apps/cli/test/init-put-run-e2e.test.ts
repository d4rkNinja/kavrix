import { rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import { runLocalCli } from '../src/local-vault-cli.js';

const PASSPHRASE = 'init-put-run-e2e-passphrase';
const SECRET = 'init-put-run-secret-value';
const directories: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

async function scratch(label: string): Promise<string> {
  const directory = await createSecureTestDirectory(
    join(tmpdir(), `kavrix-init-put-run-${label}-`),
  );
  directories.push(directory);
  return directory;
}

async function runCli(
  args: readonly string[],
  input = '',
): Promise<{ stdout: string; stderr: string; exitCode: number | undefined }> {
  const originalStdin = process.stdin;
  const originalExit = process.exitCode;
  const output: string[] = [];
  const errors: string[] = [];
  Object.defineProperty(process, 'stdin', {
    configurable: true,
    value: Readable.from([input]),
  });
  const write = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
    output.push(String(chunk));
    return true;
  });
  const writeErr = vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
    errors.push(String(chunk));
    return true;
  });
  process.exitCode = undefined;
  try {
    await runLocalCli(['node', 'kavrix', ...args]);
    return {
      stdout: output.join(''),
      stderr: errors.join(''),
      exitCode: process.exitCode ?? 0,
    };
  } finally {
    write.mockRestore();
    writeErr.mockRestore();
    Object.defineProperty(process, 'stdin', {
      configurable: true,
      value: originalStdin,
    });
    process.exitCode = originalExit;
  }
}

describe('scripted init → put → run', () => {
  it(
    'init --json file leaves a vault that put and run can use',
    async () => {
      const directory = await scratch('happy');
      const dataFile = join(directory, 'db.kavrix');
      const keyFile = join(directory, 'owner.key');
      const configDir = join(directory, 'config');
      const scriptPath = join(directory, 'print-env.mjs');
      await writeFile(
        scriptPath,
        'process.stdout.write(process.env.DEMO_SECRET ?? "");\n',
        'utf8',
      );

      const init = await runCli(
        [
          'init',
          '--json',
          '--datastore',
          'file',
          '--data-file',
          dataFile,
          '--key-file',
          keyFile,
          '--profile-config-dir',
          configDir,
          '--passphrase-stdin',
        ],
        `${PASSPHRASE}\n${PASSPHRASE}\n`,
      );
      expect(init.exitCode, init.stderr || init.stdout).toBe(0);
      const initJson = JSON.parse(init.stdout) as Record<string, unknown>;
      expect(initJson).toMatchObject({
        initialized: true,
        kind: 'database-container',
        datastore: 'file',
        recoveryReady: false,
      });
      expect(typeof initJson.vaultId).toBe('string');
      expect(typeof initJson.profileId).toBe('string');

      const put = await runCli(
        [
          'put',
          'demo/token',
          '--profile-config-dir',
          configDir,
          '--passphrase-stdin',
          '--value-stdin',
        ],
        `${PASSPHRASE}\n${SECRET}\n`,
      );
      expect(put.exitCode).toBe(0);
      expect(JSON.parse(put.stdout)).toMatchObject({ saved: true, name: 'demo/token' });

      const run = await runCli(
        [
          'run',
          '--json',
          '--profile-config-dir',
          configDir,
          '--passphrase-stdin',
          '--secret',
          'DEMO_SECRET=demo/token',
          '--',
          process.execPath,
          scriptPath,
        ],
        `${PASSPHRASE}\n`,
      );
      expect(run.exitCode).toBe(0);
      const runJson = JSON.parse(run.stdout) as {
        ran?: boolean;
        exitCode?: number | null;
        stdout?: string;
      };
      expect(runJson.ran).toBe(true);
      expect(runJson.exitCode).toBe(0);
      // --json redacts injected secret material; length proves injection happened.
      expect(runJson.stdout ?? '').toHaveLength(SECRET.length);
      expect(runJson.stdout ?? '').not.toContain(SECRET);
    },
    process.platform === 'win32' ? 600_000 : 120_000,
  );
});
