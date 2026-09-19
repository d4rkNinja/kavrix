import { access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { Readable } from 'node:stream';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import { runLocalCli } from '../src/local-vault-cli.js';

const PASSPHRASE = 'relative-path-init-passphrase';
const directories: string[] = [];
const previousCwd = process.cwd();

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  process.chdir(previousCwd);
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

async function scratch(label: string): Promise<string> {
  const directory = await createSecureTestDirectory(
    join(tmpdir(), `kavrix-rel-path-${label}-`),
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

describe('init relative path persistence', () => {
  it(
    'resolves relative --data-file/--key-file to absolute paths so get works after chdir',
    async () => {
      const project = await scratch('project');
      const elsewhere = await scratch('elsewhere');
      const configDir = join(project, 'config');
      process.chdir(project);

      const init = await runCli(
        [
          'init',
          '--json',
          '--data-file',
          './vault.kavrix',
          '--key-file',
          './custom.key',
          '--profile-config-dir',
          configDir,
          '--passphrase-stdin',
        ],
        `${PASSPHRASE}\n${PASSPHRASE}\n`,
      );
      expect(init.exitCode).toBe(0);
      const initJson = JSON.parse(init.stdout) as Record<string, unknown>;
      expect(initJson).toMatchObject({ initialized: true, kind: 'database-container' });
      expect(typeof initJson.dataFile).toBe('string');
      expect(typeof initJson.keyFile).toBe('string');
      expect(isAbsolute(String(initJson.dataFile))).toBe(true);
      expect(isAbsolute(String(initJson.keyFile))).toBe(true);
      expect(String(initJson.dataFile)).toBe(resolve(project, 'vault.kavrix'));
      expect(String(initJson.keyFile)).toBe(resolve(project, 'custom.key'));
      await expect(access(join(project, 'vault.kavrix'))).resolves.toBeUndefined();
      await expect(access(join(project, 'custom.key'))).resolves.toBeUndefined();

      const put = await runCli(
        [
          'put',
          'CANARY',
          '--profile-config-dir',
          configDir,
          '--passphrase-stdin',
          '--value-stdin',
          '--json',
        ],
        `${PASSPHRASE}\ncanary\n`,
      );
      expect(put.exitCode).toBe(0);

      process.chdir(elsewhere);
      const get = await runCli(
        [
          'get',
          'CANARY',
          '--reveal',
          '--profile-config-dir',
          configDir,
          '--passphrase-stdin',
          '--json',
        ],
        `${PASSPHRASE}\n`,
      );
      expect(get.exitCode).toBe(0);
      expect(JSON.parse(get.stdout)).toMatchObject({ name: 'CANARY', value: 'canary' });
    },
    process.platform === 'win32' ? 600_000 : 120_000,
  );

  it(
    'honors explicit --key-file ./kavrix.key in cwd instead of relocating to ~/.kavrix',
    async () => {
      const project = await scratch('explicit-default-key');
      const fakeHome = await scratch('explicit-key-home');
      const configDir = join(project, 'config');
      vi.stubEnv('HOME', fakeHome);
      if (process.platform === 'win32') vi.stubEnv('USERPROFILE', fakeHome);
      process.chdir(project);

      const init = await runCli(
        [
          'init',
          '--json',
          '--data-file',
          './vault.kavrix',
          '--key-file',
          './kavrix.key',
          '--profile-config-dir',
          configDir,
          '--passphrase-stdin',
        ],
        `${PASSPHRASE}\n${PASSPHRASE}\n`,
      );
      expect(init.exitCode).toBe(0);
      const initJson = JSON.parse(init.stdout) as Record<string, unknown>;
      expect(String(initJson.keyFile)).toBe(resolve(project, 'kavrix.key'));
      expect(String(initJson.dataFile)).toBe(resolve(project, 'vault.kavrix'));
      await expect(access(join(project, 'kavrix.key'))).resolves.toBeUndefined();
      await expect(access(join(project, 'vault.kavrix'))).resolves.toBeUndefined();
      await expect(access(join(fakeHome, '.kavrix', 'kavrix.key'))).rejects.toMatchObject({
        code: 'ENOENT',
      });
    },
    process.platform === 'win32' ? 600_000 : 120_000,
  );

  it(
    'bare init without path flags still stores under ~/.kavrix',
    async () => {
      const project = await scratch('bare-home-default');
      const configDir = join(project, 'config');
      // Isolate HOME so we do not touch the operator's real ~/.kavrix.
      const fakeHome = await scratch('fake-home');
      vi.stubEnv('HOME', fakeHome);
      if (process.platform === 'win32') {
        vi.stubEnv('USERPROFILE', fakeHome);
      }
      process.chdir(project);

      const init = await runCli(
        ['init', '--json', '--profile-config-dir', configDir, '--passphrase-stdin'],
        `${PASSPHRASE}\n${PASSPHRASE}\n`,
      );
      expect(init.exitCode).toBe(0);
      const initJson = JSON.parse(init.stdout) as Record<string, unknown>;
      const expectedVault = join(fakeHome, '.kavrix', 'kavrix.vault');
      const expectedKey = join(fakeHome, '.kavrix', 'kavrix.key');
      expect(String(initJson.dataFile)).toBe(expectedVault);
      expect(String(initJson.keyFile)).toBe(expectedKey);
      await expect(access(expectedVault)).resolves.toBeUndefined();
      await expect(access(expectedKey)).resolves.toBeUndefined();
    },
    process.platform === 'win32' ? 600_000 : 120_000,
  );
});
