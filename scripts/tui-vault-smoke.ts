/**
 * Manual vault mutation smoke for the TUI session backend.
 * Uses a temp HOME, inits a file database vault via CLI, then exercises
 * CliTuiSession unlock/list/reveal/put/rename/remove without Ink.
 */
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

import { createCliTuiBackend } from '../apps/cli/src/tui-session.ts';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const bin = join(root, 'apps/cli/dist/bin.js');
const PASSPHRASE = 'correct horse battery staple';

function fail(message: string): void {
  console.error(`FAIL: ${message}`);
  process.exitCode = 1;
}

function pass(message: string): void {
  console.log(`PASS: ${message}`);
}

async function runCli(
  args: readonly string[],
  frames: readonly string[] = [],
  env: Record<string, string | undefined> = {},
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [bin, ...args], {
      env: { ...process.env, ...env, FORCE_COLOR: undefined },
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout?.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr?.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.stdin?.end(frames.map((frame) => `${frame}\n`).join(''), 'utf8');
    child.on('error', reject);
    child.on('close', (code) => {
      resolvePromise({
        code,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      });
    });
  });
}

async function main(): Promise<void> {
  const home = await mkdtemp(join(tmpdir(), 'kavrix-tui-vault-smoke-'));
  const cfg = join(home, 'cfg');
  const dataFile = join(home, 'db.kavrix');
  const keyFile = join(home, 'owner.key');
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  await chmod(home, 0o700);

  try {
    let result = await runCli(
      [
        'db',
        'profile',
        'add',
        'smoke',
        '--datastore',
        'file',
        '--data-file',
        dataFile,
        '--key-file',
        keyFile,
        '--config-dir',
        cfg,
      ],
      [],
      { HOME: home },
    );
    if (result.code !== 0) {
      fail(`profile add: ${result.stderr || result.stdout}`);
      return;
    }
    pass('db profile add');

    result = await runCli(
      ['db', 'profile', 'use', 'smoke', '--config-dir', cfg],
      [],
      { HOME: home },
    );
    if (result.code !== 0) {
      fail(`profile use: ${result.stderr || result.stdout}`);
      return;
    }
    pass('db profile use');

    result = await runCli(
      ['db', 'init', '--profile', 'smoke', '--config-dir', cfg, '--passphrase-stdin'],
      ['smoke-label', PASSPHRASE, PASSPHRASE],
      { HOME: home },
    );
    if (result.code !== 0) {
      fail(`db init: ${result.stderr || result.stdout}`);
      return;
    }
    pass('db init');

    result = await runCli(
      [
        'db',
        'vault',
        'create',
        '--profile',
        'smoke',
        '--profile-config-dir',
        cfg,
        '--passphrase-stdin',
        '--json',
      ],
      [PASSPHRASE, 'smoke-vault'],
      { HOME: home },
    );
    if (result.code !== 0) {
      fail(`vault create: ${result.stderr || result.stdout}`);
      return;
    }
    const created = JSON.parse(result.stdout) as { vaultId?: unknown };
    const vaultId = created.vaultId;
    if (typeof vaultId !== 'string') {
      fail('vault create missing vaultId');
      return;
    }
    pass(`db vault create (${vaultId})`);

    result = await runCli(
      [
        'db',
        'vault',
        'use',
        vaultId,
        '--profile',
        'smoke',
        '--profile-config-dir',
        cfg,
        '--passphrase-stdin',
      ],
      [PASSPHRASE],
      { HOME: home },
    );
    if (result.code !== 0) {
      fail(`vault use: ${result.stderr || result.stdout}`);
      return;
    }
    pass('db vault use');

    result = await runCli(
      [
        'put',
        'seed',
        '--profile',
        'smoke',
        '--profile-config-dir',
        cfg,
        '--passphrase-stdin',
        '--value-stdin',
      ],
      [PASSPHRASE, 'seed-value'],
      { HOME: home },
    );
    if (result.code !== 0) {
      fail(`cli put seed: ${result.stderr || result.stdout}`);
      return;
    }
    pass('cli put seed');

    const backend = createCliTuiBackend({
      profileConfigDir: cfg,
      ascii: true,
      binPath: bin,
    });

    let snap = await backend.dispatch({
      type: 'unlock',
      passphrase: PASSPHRASE,
    });
    if (!snap.snapshot.home.unlocked) {
      fail(`unlock: ${snap.snapshot.notice}`);
      return;
    }
    if (!snap.snapshot.credentials.some((c) => c.name === 'seed')) {
      fail(`unlock list missing seed: ${JSON.stringify(snap.snapshot.credentials)}`);
      return;
    }
    pass('session unlock + list');

    snap = await backend.dispatch({
      type: 'reveal-credential',
      name: 'seed',
    });
    if (snap.revealedSecret !== 'seed-value') {
      fail(`reveal expected seed-value got ${JSON.stringify(snap.revealedSecret)}`);
      return;
    }
    pass('session reveal');

    snap = await backend.dispatch({
      type: 'put-credential',
      name: 'from-tui',
      value: 'tui-secret',
    });
    if (snap.snapshot.noticeTone !== 'success') {
      fail(`put: ${snap.snapshot.notice}`);
      return;
    }
    if (!snap.snapshot.credentials.some((c) => c.name === 'from-tui')) {
      fail('put did not refresh list');
      return;
    }
    pass('session put-credential');

    snap = await backend.dispatch({
      type: 'rename-credential',
      from: 'from-tui',
      to: 'renamed-tui',
    });
    if (!snap.snapshot.credentials.some((c) => c.name === 'renamed-tui')) {
      fail(`rename: ${snap.snapshot.notice}`);
      return;
    }
    pass('session rename-credential');

    snap = await backend.dispatch({
      type: 'remove-credential',
      name: 'renamed-tui',
    });
    if (snap.snapshot.credentials.some((c) => c.name === 'renamed-tui')) {
      fail(`remove: ${snap.snapshot.notice}`);
      return;
    }
    pass('session remove-credential');

    snap = await backend.dispatch({ type: 'recovery-status' });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`recovery-status: ${snap.snapshot.notice}`);
      return;
    }
    if (snap.snapshot.recovery.length < 1) {
      fail('recovery-status empty');
      return;
    }
    pass('session recovery-status');

    const recoveryFile = join(home, 'recovery.kit');
    const recoveryPass = 'recovery-pass-phrase-ok';
    snap = await backend.dispatch({
      type: 'recovery-create',
      recoveryFile,
      recoveryPassphrase: recoveryPass,
    });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`recovery-create: ${snap.snapshot.notice}`);
      return;
    }
    const activeAfterCreate = snap.snapshot.recovery.filter(
      (slot) => slot.status === 'active' && !slot.slotId.startsWith('('),
    );
    if (activeAfterCreate.length < 1) {
      fail(
        `recovery-create missing active slot: ${JSON.stringify(snap.snapshot.recovery)}`,
      );
      return;
    }
    pass(`session recovery-create (${activeAfterCreate[0]?.slotId})`);

    snap = await backend.dispatch({ type: 'recovery-status' });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`recovery-status after create: ${snap.snapshot.notice}`);
      return;
    }
    pass('session recovery-status after create');

    snap = await backend.dispatch({
      type: 'recovery-verify',
      recoveryFile,
      recoveryPassphrase: recoveryPass,
    });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`recovery-verify: ${snap.snapshot.notice}`);
      return;
    }
    pass('session recovery-verify');

    snap = await backend.dispatch({ type: 'run-doctor' });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`run-doctor: ${snap.snapshot.notice}`);
      return;
    }
    if (snap.snapshot.doctor.length < 1) {
      fail('run-doctor produced no rows');
      return;
    }
    pass(`session run-doctor (${String(snap.snapshot.doctor.length)} rows)`);

    snap = await backend.dispatch({
      type: 'policy-create',
      id: 'tui-smoke-policy',
      secret: 'seed',
      command: 'true',
    });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`policy-create: ${snap.snapshot.notice}`);
      return;
    }
    if (
      !snap.snapshot.policies.some(
        (row) => row.kind === 'policy' && row.id === 'tui-smoke-policy',
      )
    ) {
      fail(`policy-create missing row: ${JSON.stringify(snap.snapshot.policies)}`);
      return;
    }
    pass('session policy-create');

    snap = await backend.dispatch({ type: 'refresh-policy' });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`refresh-policy: ${snap.snapshot.notice}`);
      return;
    }
    if (
      !snap.snapshot.policies.some(
        (row) => row.kind === 'policy' && row.id === 'tui-smoke-policy',
      )
    ) {
      fail('refresh-policy lost created policy');
      return;
    }
    pass('session refresh-policy (list)');

    snap = await backend.dispatch({
      type: 'grant-create',
      secret: 'seed',
      command: 'true',
      ttl: '15m',
    });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`grant-create: ${snap.snapshot.notice}`);
      return;
    }
    const grantRow = snap.snapshot.policies.find((row) => row.kind === 'grant');
    if (grantRow === undefined) {
      fail(`grant-create missing grant row: ${JSON.stringify(snap.snapshot.policies)}`);
      return;
    }
    pass(`session grant-create (${grantRow.id})`);

    snap = await backend.dispatch({
      type: 'grant-revoke',
      grantId: grantRow.id,
    });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`grant-revoke: ${snap.snapshot.notice}`);
      return;
    }
    const afterRevoke = snap.snapshot.policies.find((row) => row.id === grantRow.id);
    if (
      afterRevoke !== undefined &&
      !afterRevoke.summary.toLowerCase().includes('revoked')
    ) {
      fail(
        `grant-revoke did not clear/revoke grant: ${JSON.stringify(afterRevoke)}`,
      );
      return;
    }
    pass('session grant-revoke');

    snap = await backend.dispatch({
      type: 'policy-remove',
      id: 'tui-smoke-policy',
    });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`policy-remove: ${snap.snapshot.notice}`);
      return;
    }
    if (
      snap.snapshot.policies.some(
        (row) => row.kind === 'policy' && row.id === 'tui-smoke-policy',
      )
    ) {
      fail('policy-remove left policy row present');
      return;
    }
    pass('session policy-remove');

    snap = await backend.dispatch({
      type: 'preview-run',
      credentialNames: ['seed'],
    });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`preview-run: ${snap.snapshot.notice}`);
      return;
    }
    if (!snap.snapshot.runPreview.toLowerCase().includes('validated')) {
      fail(`preview-run unexpected preview: ${snap.snapshot.runPreview}`);
      return;
    }
    pass('session preview-run');

    const agentConfig = join(home, 'agent.kavrix.json');
    await writeFile(
      agentConfig,
      `${JSON.stringify(
        {
          version: 1,
          agents: {
            noop: {
              permissions: {
                ping: {
                  secret: 'seed',
                  commands: ['true'],
                  env: 'SEED',
                },
              },
            },
          },
        },
        null,
        2,
      )}\n`,
      'utf8',
    );
    snap = await backend.dispatch({
      type: 'agent-dry-run',
      configPath: agentConfig,
      agentName: 'noop',
    });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`agent-dry-run: ${snap.snapshot.notice}`);
      return;
    }
    pass('session agent-dry-run');

    await writeFile(join(home, 'tui-vault-smoke.ok'), 'ok\n', 'utf8');
    console.log('tui-vault-smoke: ALL PASS');
  } finally {
    await rm(home, { recursive: true, force: true });
  }
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
