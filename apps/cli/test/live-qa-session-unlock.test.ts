import { spawn } from 'node:child_process';
import { readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';

const directories: string[] = [];

afterEach(async () => {
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) =>
      rm(directory, { force: true, recursive: true }).catch(() => undefined),
    ),
  );
});

async function scratch(label: string): Promise<string> {
  const directory = await createSecureTestDirectory(
    join(tmpdir(), `kavrix-session-qa-${label}-`),
  );
  directories.push(directory);
  return directory;
}

const BIN = resolve('apps/cli/dist/bin.js');

function expectOk(
  result: { stdout: string; stderr: string; code: number | null },
  label: string,
): void {
  expect(result.code, `${label} stderr: ${result.stderr}`).toBe(0);
}
const PASSPHRASE = 'SessionQaPassphrase22!';

function live(env: NodeJS.ProcessEnv) {
  return (
    args: readonly string[],
    frames: readonly string[] = [],
  ): Promise<{ stdout: string; stderr: string; code: number | null }> =>
    new Promise((resolvePromise, rejectPromise) => {
      const child = spawn(process.execPath, [BIN, ...args], {
        env: { ...process.env, ...env },
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      });
      const stdout: Buffer[] = [];
      const stderr: Buffer[] = [];
      child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
      child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
      child.stdin.end(frames.map((frame) => `${frame}\n`).join(''), 'utf8');
      child.on('error', rejectPromise);
      child.on('close', (exitCode) => {
        resolvePromise({
          stdout: Buffer.concat(stdout).toString('utf8'),
          stderr: Buffer.concat(stderr).toString('utf8'),
          code: exitCode,
        });
      });
    });
}

// The journey drives the real OS credential store: Windows PasswordVault is
// the verified live path. macOS `security` and Linux `secret-tool` are not
// guaranteed on hosted runners; the shared session logic is covered by the
// platform-independent crypto/router/backend suites, and the POSIX keychain
// scripts await their own live verification.
describe.skipIf(process.platform !== 'win32')(
  '0.2.24 live session unlock (real OS keychain)',
  () => {
    it(
      'enables, unlocks without the passphrase, revokes, and fails closed afterwards',
      async () => {
        const home = await scratch('journey');
        const env: NodeJS.ProcessEnv = { HOME: home, USERPROFILE: home };
        const configDir = join(home, 'config');
        const routing = ['--profile', 'default', '--profile-config-dir', configDir];
        const run = live(env);

        // Hardened kavrix home + profile + initialized database + vault.
        const { ensureSecureDirectory } = await import('@kavrix/key-files');
        await ensureSecureDirectory(join(home, '.kavrix'));
        const add = await run([
          'db',
          'profile',
          'add',
          'default',
          '--datastore',
          'file',
          '--data-file',
          join(home, '.kavrix', 'kavrix.vault'),
          '--key-file',
          join(home, '.kavrix', 'kavrix.key'),
          '--profile-config-dir',
          configDir,
          '--json',
        ]);
        expect(add.code, `stderr: ${add.stderr}`).toBe(0);
        expectOk(
          await run([
            'db',
            'profile',
            'use',
            'default',
            '--profile-config-dir',
            configDir,
            '--json',
          ]),
          'profile use',
        );
        expect(
          (
            await run(
              ['db', 'init', ...routing, '--passphrase-stdin', '--json'],
              ['lab', PASSPHRASE, PASSPHRASE],
            )
          ).code,
        ).toBe(0);
        const created = JSON.parse(
          (
            await run(
              ['db', 'vault', 'create', ...routing, '--passphrase-stdin', '--json'],
              [PASSPHRASE, 'session-qa'],
            )
          ).stdout,
        ) as { vaultId?: string };
        expect(typeof created.vaultId).toBe('string');
        expect(
          (
            await run(
              [
                'db',
                'vault',
                'use',
                String(created.vaultId),
                ...routing,
                '--passphrase-stdin',
              ],
              [PASSPHRASE],
            )
          ).code,
        ).toBe(0);

        // Status before enable: not enabled.
        const before = JSON.parse(
          (await run(['session', 'status', ...routing, '--json'])).stdout,
        ) as { enabled?: boolean };
        expect(before.enabled).toBe(false);

        // Enable stores the wrapping key in the OS keychain and seals the file.
        const enabledRun = await run(
          ['session', 'enable', ...routing, '--passphrase-stdin', '--json'],
          [PASSPHRASE],
        );
        expect(enabledRun.code, `stderr: ${enabledRun.stderr}`).toBe(0);
        const enabled = JSON.parse(enabledRun.stdout) as {
          enabled?: boolean;
          ttlHours?: number | null;
        };
        expect(enabled.enabled).toBe(true);
        expect(enabled.ttlHours).toBe(12);
        const sessionFile = await readFile(
          join(home, '.kavrix', 'kavrix.key.session'),
          'utf8',
        );
        expect(sessionFile).not.toContain(PASSPHRASE);
        expect(JSON.parse(sessionFile).envelope.ciphertext).toBeTruthy();

        // Status reports enabled.
        const after = JSON.parse(
          (await run(['session', 'status', ...routing, '--json'])).stdout,
        ) as { enabled?: boolean; expired?: boolean };
        expect(after.enabled).toBe(true);
        expect(after.expired).toBe(false);

        // THE feature: a full command run unlocks with NO passphrase at all.
        const sessionRun = await run(['list', ...routing, '--session', '--json']);
        expect(sessionRun.code, `stderr: ${sessionRun.stderr}`).toBe(0);
        expect(JSON.parse(sessionRun.stdout)).toHaveProperty('names');

        // A wrong passphrase still fails (session is additive, not weakening).
        const wrong = await run(
          ['list', ...routing, '--passphrase-stdin', '--json'],
          ['definitely-wrong-passphrase'],
        );
        expect(wrong.code).not.toBe(0);

        // Revoke removes both halves; --session then fails closed.
        const revoked = JSON.parse(
          (await run(['session', 'revoke', ...routing, '--json'])).stdout,
        ) as { revoked?: boolean };
        expect(revoked.revoked).toBe(true);
        const denied = await run(['list', ...routing, '--session', '--json']);
        expect(denied.code).not.toBe(0);
        // Linux CI without secret-tool reports the store as unavailable;
        // Windows reports no-session. Both fail closed.
        expect(`${denied.stderr}\n${denied.stdout}`).toMatch(
          /no session unlock|credential store is unavailable/i,
        );

        // The passphrase remains fully functional after revocation.
        const manual = await run(
          ['list', ...routing, '--passphrase-stdin', '--json'],
          [PASSPHRASE],
        );
        expect(manual.code).toBe(0);
      },
      process.platform === 'win32' ? 600_000 : 300_000,
    );
  },
);
