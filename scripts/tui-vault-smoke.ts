/**
 * Manual vault mutation smoke for the TUI session backend.
 * Uses a temp HOME, inits a file database vault via CLI, then exercises
 * CliTuiSession unlock/list/reveal/put/rename/remove without Ink.
 */
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
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
  const shimDir = join(home, 'bin');
  await mkdir(shimDir, { recursive: true });
  // Consume stdin and exit 0 — lets headless copy exercise real secret fetch.
  const shim = `#!/usr/bin/env node\nlet d='';process.stdin.on('data',c=>d+=c);process.stdin.on('end',()=>process.exit(0));\n`;
  for (const name of ['xsel', 'xclip', 'wl-copy'] as const) {
    const target = join(shimDir, name);
    await writeFile(target, shim, 'utf8');
    await chmod(target, 0o755);
  }
  process.env.PATH = `${shimDir}${process.platform === 'win32' ? ';' : ':'}${process.env.PATH ?? ''}`;

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

    result = await runCli(['db', 'profile', 'use', 'smoke', '--config-dir', cfg], [], {
      HOME: home,
    });
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

    if (snap.snapshot.profiles.length < 1) {
      fail('profiles list empty after unlock');
      return;
    }
    pass(`session profiles list (${String(snap.snapshot.profiles.length)})`);

    if (snap.snapshot.vaults.length < 1) {
      fail('vaults list empty after unlock');
      return;
    }
    pass(`session vaults list (${String(snap.snapshot.vaults.length)})`);

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

    snap = await backend.dispatch({
      type: 'copy-credential',
      name: 'seed',
    });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`copy-credential: ${snap.snapshot.notice}`);
      return;
    }
    const copyNotice = (snap.snapshot.notice ?? '').toLowerCase();
    if (
      !copyNotice.includes('copy') &&
      !copyNotice.includes('clipboard') &&
      !copyNotice.includes('osc')
    ) {
      // Still accept success tone; clipboard backends vary in headless CI.
      console.log(`NOTE: copy notice=${JSON.stringify(snap.snapshot.notice)}`);
    }
    pass('session copy-credential');

    snap = await backend.dispatch({ type: 'lock' });
    if (snap.snapshot.home.unlocked) {
      fail(`lock left vault unlocked: ${snap.snapshot.notice}`);
      return;
    }
    pass('session lock');

    snap = await backend.dispatch({
      type: 'unlock',
      passphrase: PASSPHRASE,
    });
    if (!snap.snapshot.home.unlocked) {
      fail(`re-unlock after lock: ${snap.snapshot.notice}`);
      return;
    }
    pass('session unlock after lock');

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

    const recoveryPass = 'recovery-pass-phrase-ok';
    const recoveryFileA = join(home, 'recovery-a.kit');
    const recoveryFileB = join(home, 'recovery-b.kit');
    for (const [label, recoveryFile] of [
      ['A', recoveryFileA],
      ['B', recoveryFileB],
    ] as const) {
      snap = await backend.dispatch({
        type: 'recovery-create',
        recoveryFile,
        recoveryPassphrase: recoveryPass,
      });
      if (snap.snapshot.noticeTone === 'error') {
        fail(`recovery-create ${label}: ${snap.snapshot.notice}`);
        return;
      }
      pass(`session recovery-create ${label}`);
    }

    snap = await backend.dispatch({ type: 'recovery-status' });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`recovery-status after create: ${snap.snapshot.notice}`);
      return;
    }
    const activeAfterCreate = snap.snapshot.recovery.filter(
      (slot) => slot.status === 'active' && !slot.slotId.startsWith('('),
    );
    if (activeAfterCreate.length < 2) {
      fail(
        `expected >=2 active recovery slots, got ${JSON.stringify(snap.snapshot.recovery)}`,
      );
      return;
    }
    pass(
      `session recovery-status after create (${String(activeAfterCreate.length)} active)`,
    );

    snap = await backend.dispatch({
      type: 'recovery-verify',
      recoveryFile: recoveryFileA,
      recoveryPassphrase: recoveryPass,
    });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`recovery-verify: ${snap.snapshot.notice}`);
      return;
    }
    pass('session recovery-verify');

    const revokeTarget = activeAfterCreate[activeAfterCreate.length - 1]!;
    snap = await backend.dispatch({
      type: 'recovery-revoke',
      slotId: revokeTarget.slotId,
    });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`recovery-revoke: ${snap.snapshot.notice}`);
      return;
    }
    const stillActive = snap.snapshot.recovery.some(
      (slot) => slot.slotId === revokeTarget.slotId && slot.status === 'active',
    );
    if (stillActive) {
      fail(`recovery-revoke left slot active: ${revokeTarget.slotId}`);
      return;
    }
    const remainingActive = snap.snapshot.recovery.filter(
      (slot) => slot.status === 'active' && !slot.slotId.startsWith('('),
    );
    if (remainingActive.length < 1) {
      fail('recovery-revoke accidentally cleared all active slots');
      return;
    }
    pass(
      `session recovery-revoke (${revokeTarget.slotId}; ${String(remainingActive.length)} remain)`,
    );

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
      fail(`grant-revoke did not clear/revoke grant: ${JSON.stringify(afterRevoke)}`);
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

    snap = await backend.dispatch({ type: 'refresh-browse' });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`refresh-browse (pre-profile-switch): ${snap.snapshot.notice}`);
      return;
    }
    pass(`session refresh-browse early (${String(snap.snapshot.browse.length)} nodes)`);

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

    snap = await backend.dispatch({ type: 'agent-dry-run' });
    if (snap.snapshot.noticeTone !== 'error') {
      fail('agent-dry-run without name should error (no noop invent)');
      return;
    }
    if (!snap.snapshot.agentStatus.toLowerCase().includes('agent name')) {
      fail(
        `agent-dry-run missing-name message unexpected: ${snap.snapshot.agentStatus}`,
      );
      return;
    }
    pass('session agent-dry-run rejects missing name (no noop)');

    const extraData = join(home, 'extra.kavrix');
    const extraKey = join(home, 'extra.key');
    snap = await backend.dispatch({
      type: 'create-file-profile',
      profileId: 'smoke-file-2',
      dataFile: extraData,
      keyFile: extraKey,
      passphrase: PASSPHRASE,
      databaseLabel: 'extra-db',
      vaultLabel: 'extra-vault',
    });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`create-file-profile: ${snap.snapshot.notice}`);
      return;
    }
    if (!snap.snapshot.profiles.some((p) => p.id === 'smoke-file-2')) {
      fail(
        `create-file-profile missing profile: ${JSON.stringify(snap.snapshot.profiles)}`,
      );
      return;
    }
    pass('session create-file-profile');

    snap = await backend.dispatch({ type: 'lock' });
    if (snap.snapshot.noticeTone === 'error' && snap.snapshot.home.unlocked) {
      fail(`lock before use-profile: ${snap.snapshot.notice}`);
      return;
    }

    snap = await backend.dispatch({ type: 'use-profile', profileId: 'smoke' });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`use-profile smoke: ${snap.snapshot.notice}`);
      return;
    }
    pass('session use-profile');

    snap = await backend.dispatch({
      type: 'unlock',
      passphrase: PASSPHRASE,
    });
    if (!snap.snapshot.home.unlocked) {
      fail(`unlock after use-profile: ${snap.snapshot.notice}`);
      return;
    }
    const smokeVault =
      snap.snapshot.vaults.find((v) => v.selected)?.id ?? snap.snapshot.home.vaultId;
    if (smokeVault === null || smokeVault === undefined) {
      fail(`no smoke vault after unlock: ${JSON.stringify(snap.snapshot.vaults)}`);
      return;
    }
    snap = await backend.dispatch({ type: 'use-vault', vaultId: smokeVault });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`use-vault: ${snap.snapshot.notice}`);
      return;
    }
    pass(`session use-vault (${smokeVault})`);

    snap = await backend.dispatch({ type: 'refresh-browse' });
    if (snap.snapshot.noticeTone === 'error') {
      fail(`refresh-browse: ${snap.snapshot.notice}`);
      return;
    }
    pass(`session refresh-browse (${String(snap.snapshot.browse.length)} nodes)`);

    const mongoUrl =
      process.env.MONGO_URL?.trim() || process.env.KAVRIX_MONGODB_URI?.trim();
    if (!mongoUrl) {
      console.log('SKIP: create-mongodb-profile (set MONGO_URL for live mongo smoke)');
    } else {
      const mongoKey = join(home, 'mongo-owner.key');
      snap = await backend.dispatch({
        type: 'create-mongodb-profile',
        profileId: 'smoke-mongo',
        database: 'kavrix_smoke',
        keyFile: mongoKey,
        databaseUrl: mongoUrl,
        passphrase: PASSPHRASE,
        databaseLabel: 'smoke-mongo-db',
        vaultLabel: 'smoke-mongo-vault',
      });
      if (snap.snapshot.noticeTone === 'error') {
        fail(`create-mongodb-profile: ${snap.snapshot.notice}`);
        return;
      }
      if (snap.snapshot.home.datastore !== 'mongodb') {
        fail(`create-mongodb-profile datastore: ${snap.snapshot.home.datastore}`);
        return;
      }
      pass('session create-mongodb-profile');
    }

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
