import { spawn } from 'node:child_process';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { createSecureTestDirectory } from '../../../packages/key-files/test/secure-temporary-directory.js';
import { createCliTuiBackend } from '../src/tui-session.js';

const directories: string[] = [];
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const BIN = join(repoRoot, 'apps', 'cli', 'dist', 'bin.js');

afterEach(async () => {
  const pending = directories.splice(0);
  await Promise.all(
    pending.map((directory) =>
      rm(directory, { force: true, recursive: true }).catch(() => undefined),
    ),
  );
});

interface Call {
  readonly args: readonly string[];
  readonly frames: readonly string[];
}

/**
 * Live commandRunner: spawns the real built CLI exactly like the default
 * tui-session spawn, but pins HOME/USERPROFILE to the scratch directory so
 * the run never touches the operator's real Kavrix home.
 */
function liveRunner(env: NodeJS.ProcessEnv, calls: Call[]) {
  return async (
    args: readonly string[],
    frames: readonly string[],
  ): Promise<string> => {
    calls.push({ args, frames });
    const child = spawn(process.execPath, [BIN, ...args], {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    const payload = frames.map((frame) => `${frame}\n`).join('');
    child.stdin.end(payload, 'utf8');
    const code = await new Promise<number | null>((res, rej) => {
      child.on('error', rej);
      child.on('close', (exitCode) => res(exitCode));
    });
    if (code !== 0) {
      const detail =
        Buffer.concat(stderr).toString('utf8').trim() ||
        Buffer.concat(stdout).toString('utf8').trim();
      throw new Error(
        `CLI failed (${String(code)}): ${(detail.split('\n')[0] ?? 'CLI failed.').slice(0, 300)} [kavrix ${args.join(' ')}]`,
      );
    }
    return Buffer.concat(stdout).toString('utf8');
  };
}

async function scratch(label: string): Promise<string> {
  const directory = await createSecureTestDirectory(
    join(tmpdir(), `kavrix-tui-crud-${label}-`),
  );
  directories.push(directory);
  return directory;
}

const PASSPHRASE = 'LiveQaPassphrase22!';

describe('0.2.22 live TUI CRUD journey (real CLI, isolated home)', () => {
  it(
    'creates a profile, then exercises credential/policy/grant/recovery/run CRUD end to end',
    async () => {
      const home = await scratch('journey');
      const configDir = join(home, 'config');
      const env: NodeJS.ProcessEnv = { HOME: home, USERPROFILE: home };
      const calls: Call[] = [];
      const backend = createCliTuiBackend({
        profileConfigDir: configDir,
        ascii: true,
        kavrixArtifactDir: join(home, '.kavrix'),
        commandRunner: liveRunner(env, calls),
      });

      // ---- Create: file profile through the real TUI create flow ----
      const created = await backend.dispatch({
        type: 'create-file-profile',
        profileId: 'default',
        dataFile: join(home, '.kavrix', 'kavrix.vault'),
        keyFile: join(home, '.kavrix', 'kavrix.key'),
        passphrase: PASSPHRASE,
      });
      expect(created.snapshot.noticeTone).toBe('success');
      expect(created.snapshot.home.profileId).toBe('default');
      expect(created.snapshot.home.vaultId).not.toBeNull();
      expect(created.snapshot.home.unlocked).toBe(true);

      // ---- Create: credential ----
      const put = await backend.dispatch({
        type: 'put-credential',
        name: 'github/token',
        value: 'live-qa-canary-value',
      });
      expect(put.snapshot.noticeTone).toBe('success');
      expect(put.snapshot.home.credentialCount).toBe(1);
      expect(
        put.snapshot.credentials.some((entry) => entry.name === 'github/token'),
      ).toBe(true);

      // ---- Update: rename ----
      const renamed = await backend.dispatch({
        type: 'rename-credential',
        from: 'github/token',
        to: 'git/token',
      });
      expect(renamed.snapshot.noticeTone).toBe('success');
      expect(
        renamed.snapshot.credentials.some((entry) => entry.name === 'git/token'),
      ).toBe(true);

      // ---- Policy: create → list shows the policy row ----
      const policyCreated = await backend.dispatch({
        type: 'policy-create',
        id: 'deploy',
        secret: 'git/token',
        command: 'terraform',
      });
      expect(policyCreated.snapshot.noticeTone).toBe('success');
      expect(
        policyCreated.snapshot.policies.some(
          (row) => row.kind === 'policy' && row.id === 'deploy',
        ),
      ).toBe(true);

      // ---- Grant: create → list shows the grant row ----
      const grantCreated = await backend.dispatch({
        type: 'grant-create',
        secret: 'git/token',
        command: 'terraform',
        ttl: '15m',
      });
      expect(grantCreated.snapshot.noticeTone).toBe('success');
      const grantRow = grantCreated.snapshot.policies.find(
        (row) => row.kind === 'grant',
      );
      expect(grantRow).toBeDefined();

      // ---- Grant: revoke ----
      if (grantRow === undefined) throw new Error('grant row missing');
      const grantRevoked = await backend.dispatch({
        type: 'grant-revoke',
        grantId: grantRow.id,
      });
      expect(grantRevoked.snapshot.noticeTone).toBe('success');
      expect(
        grantRevoked.snapshot.policies.every(
          (row) => row.kind !== 'grant' || row.status === 'revoked',
        ),
      ).toBe(true);

      // ---- Policy: delete ----
      const policyRemoved = await backend.dispatch({
        type: 'policy-remove',
        id: 'deploy',
      });
      expect(policyRemoved.snapshot.noticeTone).toBe('success');
      expect(
        policyRemoved.snapshot.policies.some(
          (row) => row.kind === 'policy' && row.id === 'deploy',
        ),
      ).toBe(false);

      // ---- Run preview (dry) ----
      const preview = await backend.dispatch({
        type: 'preview-run',
        credentialNames: ['git/token'],
      });
      expect(preview.snapshot.runPreview ?? '').toContain('git/token');

      // ---- Recovery kit: create → status → verify ----
      const recoveryFile = join(home, 'kavrix.recovery');
      const recoveryCreated = await backend.dispatch({
        type: 'recovery-create',
        recoveryFile,
        recoveryPassphrase: 'RecoveryQaPassphrase22!',
      });
      expect(recoveryCreated.snapshot.noticeTone).toBe('success');
      const recoveryVerified = await backend.dispatch({
        type: 'recovery-verify',
        recoveryFile,
        recoveryPassphrase: 'RecoveryQaPassphrase22!',
      });
      expect(recoveryVerified.snapshot.noticeTone).toBe('success');

      // ---- Delete: credential ----
      const removed = await backend.dispatch({
        type: 'remove-credential',
        name: 'git/token',
      });
      expect(removed.snapshot.noticeTone).toBe('success');
      expect(removed.snapshot.home.credentialCount).toBe(0);

      // ---- Vault: create a second vault (uses stored unlock material) ----
      const previousVaultId = preview.snapshot.home.vaultId;
      const vaultCreated = await backend.dispatch({
        type: 'create-vault',
        label: 'second vault',
      });
      expect(vaultCreated.snapshot.noticeTone).toBe('success');
      expect(vaultCreated.snapshot.home.vaultId).not.toBeNull();
      expect(vaultCreated.snapshot.home.vaultId).not.toBe(previousVaultId);

      // ---- Lock ----
      const locked = await backend.dispatch({ type: 'lock' });
      expect(locked.snapshot.home.unlocked).toBe(false);

      // ---- Delete: profile (files are kept; session is reset) ----
      const profileRemoved = await backend.dispatch({
        type: 'remove-profile',
        profileId: 'default',
      });
      expect(profileRemoved.snapshot.noticeTone, profileRemoved.snapshot.notice).toBe(
        'success',
      );
      expect(profileRemoved.snapshot.home.profileId).toBeNull();

      // Secrets never reach argv across the whole journey.
      for (const call of calls) {
        expect(call.args.join(' ')).not.toContain(PASSPHRASE);
        expect(call.args.join(' ')).not.toContain('live-qa-canary-value');
      }
    },
    process.platform === 'win32' ? 900_000 : 300_000,
  );
});
