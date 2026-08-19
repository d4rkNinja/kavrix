/* global Buffer, process, setTimeout, clearTimeout */

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const cliRoot = join(workspaceRoot, 'apps', 'cli');
const npmCommand = process.platform === 'win32' ? process.execPath : 'npm';
const npmArgsPrefix =
  process.platform === 'win32'
    ? [join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')]
    : [];
const commandTimeoutMs = 180_000;
const maxOutputBytes = 4 * 1024 * 1024;
const activeChildren = new Set();

const expectedHelpPaths = [
  [],
  ['init'],
  ['db'],
  ['db', 'ping'],
  ['put'],
  ['get'],
  ['list'],
  ['view'],
  ['search'],
  ['stats'],
  ['remove'],
  ['has'],
  ['rename'],
  ['doctor'],
  ['doctor', 'health'],
  ['recovery'],
  ['recovery', 'create'],
  ['recovery', 'verify'],
  ['recovery', 'revoke'],
  ['recovery', 'status'],
  ['recovery', 'use'],
  ['vault'],
  ['vault', 'list'],
  ['vault', 'status'],
  ['key'],
  ['key', 'status'],
  ['key', 'verify'],
  ['key', 'copy'],
  ['key', 'replicate'],
  ['key', 'assign'],
  ['key', 'rewrap'],
];

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function secretFrames(values) {
  return values.join('\n') + '\n';
}

function ephemeralSecret() {
  return randomBytes(24).toString('base64url');
}

async function runProcess(command, args, options = {}) {
  return await new Promise((resolveResult, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd ?? workspaceRoot,
      env: options.environment ?? process.env,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    activeChildren.add(child);
    const stdout = [];
    const stderr = [];
    let bytes = 0;
    let settled = false;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (error !== undefined) reject(error);
      else resolveResult(result);
    };
    const capture = (chunk, target) => {
      bytes += chunk.byteLength;
      if (bytes > maxOutputBytes) {
        child.kill();
        finish(new Error(`${options.label ?? command} exceeded its output limit`));
        return;
      }
      target.push(Buffer.from(chunk));
    };
    child.stdout.on('data', (chunk) => capture(chunk, stdout));
    child.stderr.on('data', (chunk) => capture(chunk, stderr));
    child.once('error', () => {
      finish(new Error(`${options.label ?? command} could not start`));
    });
    child.once('close', (code, signal) => {
      activeChildren.delete(child);
      const result = {
        code,
        signal,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      };
      if (code !== (options.expectedCode ?? 0) || signal !== null) {
        finish(new Error(`${options.label ?? command} failed`));
      } else {
        finish(undefined, result);
      }
    });
    child.stdin.on('error', () => undefined);
    child.stdin.end(options.input ?? '');
    const timeout = setTimeout(() => {
      child.kill();
      finish(new Error(`${options.label ?? command} timed out`));
    }, options.timeoutMs ?? commandTimeoutMs);
  });
}

function parseJson(result, label) {
  try {
    return JSON.parse(result.stdout);
  } catch {
    fail(`${label} did not emit JSON`);
  }
}

function assertNoSecret(result, secret, label) {
  assert(!result.stdout.includes(secret), `${label} exposed the credential value`);
  assert(!result.stderr.includes(secret), `${label} exposed the credential value`);
}

async function assertEncryptedArtifacts(root, secret) {
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const content = await readFile(join(root, entry.name));
    assert(
      !content.includes(Buffer.from(secret, 'utf8')),
      `${entry.name} contains the plaintext credential value`,
    );
  }
}

function cliRunner(bin, cwd, secret) {
  return async (args, frames = [], options = {}) => {
    const result = await runProcess(process.execPath, [bin, ...args], {
      cwd,
      input: secretFrames(frames),
      label: `kavrix ${args.join(' ')}`,
      expectedCode: options.expectedCode,
    });
    if (options.allowSecretOutput !== true)
      assertNoSecret(result, secret, args.join(' '));
    return result;
  };
}

function fileArgs(paths) {
  return [
    '--datastore',
    'file',
    '--data-file',
    paths.dataFile,
    '--vault',
    paths.vaultId,
  ];
}

function keyArgs(paths) {
  return ['--key-file', paths.keyFile];
}

function stdinFlags(...flags) {
  return flags.flatMap((flag) => [`--${flag}-stdin`]);
}

function destroyConfirmationFrames(output, vaultId, revision) {
  const match = /Destruction challenge:\s*([A-Z0-9]{12})/u.exec(output);
  const challenge = match?.[1];
  if (challenge === undefined) {
    fail('Destroy confirmation format mismatch: the bounded challenge is missing.');
  }
  return [`DESTROY ${vaultId}`, `DELETE REVISION ${String(revision)} ${challenge}`];
}

async function runDestroy(bin, cwd, paths, passphrase, secret, revision) {
  const artifacts = [
    paths.primaryKeyFile,
    paths.copyKeyFile,
    paths.replicaKeyFile,
    paths.assignedKeyFile,
    paths.recoveryFile,
    paths.secondRecoveryFile,
    paths.replacementRecoveryFile,
  ];
  await new Promise((resolveResult, reject) => {
    const args = [
      bin,
      'destroy',
      ...fileArgs(paths),
      ...keyArgs(paths),
      '--passphrase-stdin',
      '--confirmation-stdin',
      ...artifacts.flatMap((path) => ['--artifact', path]),
    ];
    const child = spawn(process.execPath, args, {
      cwd,
      env: process.env,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    activeChildren.add(child);
    const stdout = [];
    const stderr = [];
    let bytes = 0;
    let confirmationsSent = false;
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (error !== undefined) reject(error);
      else resolveResult();
    };
    const inspect = () => {
      const output = Buffer.concat([...stdout, ...stderr]).toString('utf8');
      if (!confirmationsSent && output.includes('Destruction challenge:')) {
        try {
          const confirmations = destroyConfirmationFrames(
            output,
            paths.vaultId,
            revision,
          );
          child.stdin.end(secretFrames([passphrase, ...confirmations]));
          confirmationsSent = true;
        } catch (error) {
          child.kill();
          finish(
            error instanceof Error ? error : new Error('Destroy confirmation failed'),
          );
        }
      }
    };
    const capture = (chunk, target) => {
      bytes += chunk.byteLength;
      if (bytes > maxOutputBytes) {
        child.kill();
        finish(new Error('kavrix destroy exceeded its output limit'));
        return;
      }
      target.push(Buffer.from(chunk));
      inspect();
    };
    child.stdout.on('data', (chunk) => capture(chunk, stdout));
    child.stderr.on('data', (chunk) => capture(chunk, stderr));
    child.stdin.on('error', () => undefined);
    child.once('error', () => finish(new Error('kavrix destroy could not start')));
    child.once('close', (code, signal) => {
      activeChildren.delete(child);
      const output = Buffer.concat([...stdout, ...stderr]).toString('utf8');
      if (output.includes(secret)) {
        finish(new Error('kavrix destroy exposed the credential value'));
      } else if (code !== 0 || signal !== null || !confirmationsSent) {
        finish(new Error(`kavrix destroy failed: ${output}`));
      } else {
        finish(undefined);
      }
    });
    const timeout = setTimeout(() => {
      child.kill();
      finish(new Error('kavrix destroy timed out'));
    }, commandTimeoutMs);
  });
}

async function stopActiveChildren() {
  await Promise.all(
    [...activeChildren].map(
      (child) =>
        new Promise((resolveStopped) => {
          if (child.exitCode !== null || child.signalCode !== null) {
            activeChildren.delete(child);
            resolveStopped();
            return;
          }
          let settled = false;
          let forceKill;
          const finish = () => {
            if (settled) return;
            settled = true;
            if (forceKill !== undefined) clearTimeout(forceKill);
            activeChildren.delete(child);
            resolveStopped();
          };
          child.once('close', finish);
          child.kill();
          forceKill = setTimeout(() => {
            child.kill('SIGKILL');
            finish();
          }, 1_000);
        }),
    ),
  );
}

async function exerciseHelp(run) {
  const rootHelp = await run(['--help']);
  assert(
    !/^\s*destroy(?:\s|$)/mu.test(rootHelp.stdout),
    'destroy leaked into root help',
  );
  for (const path of expectedHelpPaths.slice(1)) {
    const result = await run([...path, '--help']);
    assert(result.stdout.includes('Usage:'), `${path.join(' ')} help is missing Usage`);
  }
}

async function exerciseLifecycle(run, bin, installRoot, paths) {
  const passphrase = ephemeralSecret();
  const rewrappedPassphrase = ephemeralSecret();
  const replacementPassphrase = ephemeralSecret();
  const recoveryPassphrase = ephemeralSecret();
  const file = fileArgs(paths);
  const key = keyArgs(paths);
  const passStdin = stdinFlags('passphrase');

  await run(['init', ...file, ...key, ...passStdin], [passphrase, passphrase]);
  await run(['vault', 'list', '--datastore', 'file', '--data-file', paths.dataFile]);
  await run(['vault', 'status', ...file]);
  await run(['key', 'status', ...key, ...passStdin], [passphrase]);
  await run(['key', 'verify', ...key, ...passStdin], [passphrase]);

  for (const [command, destination, destinationPassphrase] of [
    ['copy', paths.copyKeyFile, ephemeralSecret()],
    ['replicate', paths.replicaKeyFile, ephemeralSecret()],
    ['assign', paths.assignedKeyFile, ephemeralSecret()],
  ]) {
    await run(
      [
        'key',
        command,
        ...key,
        '--destination',
        destination,
        ...stdinFlags('passphrase', 'new-passphrase'),
      ],
      [passphrase, destinationPassphrase, destinationPassphrase],
    );
  }
  await run(
    ['key', 'rewrap', ...key, ...stdinFlags('passphrase', 'new-passphrase')],
    [passphrase, rewrappedPassphrase, rewrappedPassphrase],
  );

  const currentPass = [rewrappedPassphrase];
  await run(
    [
      'put',
      paths.credentialName,
      ...file,
      ...key,
      ...stdinFlags('passphrase', 'value'),
    ],
    [rewrappedPassphrase, paths.secret],
  );
  await run(['has', paths.credentialName, ...file, ...key, ...passStdin], currentPass);
  await run(['get', paths.credentialName, ...file, ...key, ...passStdin], currentPass);
  const revealed = await run(
    ['get', paths.credentialName, ...file, ...key, ...passStdin, '--reveal'],
    currentPass,
    { allowSecretOutput: true },
  );
  assert(
    revealed.stdout.trim() === paths.secret,
    'get --reveal returned the wrong value',
  );
  await run(['list', ...file, ...key, ...passStdin], currentPass);
  await run(['view', ...file, ...key, ...passStdin, '--json'], currentPass);
  await run(
    ['view', paths.credentialName, ...file, ...key, ...passStdin, '--json'],
    currentPass,
  );
  await run(
    ['search', 'acceptance', ...file, ...key, ...passStdin, '--json', '--limit', '5'],
    currentPass,
  );
  await run(['stats', ...file, ...key, ...passStdin, '--json'], currentPass);
  await run(
    [
      'rename',
      paths.credentialName,
      paths.renamedCredential,
      ...file,
      ...key,
      ...passStdin,
    ],
    currentPass,
  );
  await run(
    [
      'put',
      paths.temporaryCredential,
      ...file,
      ...key,
      ...stdinFlags('passphrase', 'value'),
    ],
    [rewrappedPassphrase, ephemeralSecret()],
  );
  await run(
    ['remove', paths.temporaryCredential, ...file, ...key, ...passStdin],
    currentPass,
  );
  await run(['doctor', ...file, ...key, ...passStdin], currentPass);
  await run(['doctor', 'health', ...file, ...key, ...passStdin], currentPass);

  const recoverySlots = [];
  for (const recoveryFile of [paths.recoveryFile, paths.secondRecoveryFile]) {
    const created = await run(
      [
        'recovery',
        'create',
        ...file,
        ...key,
        '--recovery-file',
        recoveryFile,
        ...stdinFlags('passphrase', 'recovery-passphrase'),
      ],
      [rewrappedPassphrase, recoveryPassphrase],
    );
    recoverySlots.push(parseJson(created, 'recovery create').recoverySlotId);
    await run(
      [
        'recovery',
        'verify',
        ...file,
        ...key,
        '--recovery-file',
        recoveryFile,
        ...stdinFlags('recovery-passphrase'),
        '--json',
      ],
      [recoveryPassphrase],
    );
  }
  await run(['recovery', 'status', ...file, '--json']);
  await run(
    ['recovery', 'revoke', recoverySlots[0], ...file, ...key, ...passStdin],
    currentPass,
  );
  await run(
    [
      'recovery',
      'use',
      ...file,
      ...key,
      '--recovery-file',
      paths.secondRecoveryFile,
      '--output-recovery-file',
      paths.replacementRecoveryFile,
      '--destination',
      paths.replacementKeyFile,
      ...stdinFlags('recovery-passphrase', 'new-passphrase'),
    ],
    [recoveryPassphrase, replacementPassphrase, replacementPassphrase],
  );

  paths.keyFile = paths.replacementKeyFile;
  await run(
    ['key', 'verify', ...keyArgs(paths), ...passStdin],
    [replacementPassphrase],
  );
  await run(
    ['doctor', ...file, ...keyArgs(paths), ...passStdin],
    [replacementPassphrase],
  );
  await assertEncryptedArtifacts(installRoot, paths.secret);
  const finalStatus = parseJson(
    await run(['vault', 'status', ...file]),
    'vault status before destroy',
  );
  assert(
    Number.isInteger(finalStatus.revision),
    'vault status did not expose the revision required for destroy',
  );
  await runDestroy(
    bin,
    installRoot,
    paths,
    replacementPassphrase,
    paths.secret,
    finalStatus.revision,
  );
  assert(!existsSync(paths.dataFile), 'destroy left the local datastore behind');
  assert(!existsSync(paths.keyFile), 'destroy left the active key file behind');
  assert(
    !existsSync(paths.keyFile + '.anchor'),
    'destroy left the active anchor behind',
  );
  for (const path of [
    paths.primaryKeyFile,
    paths.copyKeyFile,
    paths.replicaKeyFile,
    paths.assignedKeyFile,
    paths.recoveryFile,
    paths.secondRecoveryFile,
    paths.replacementRecoveryFile,
  ]) {
    assert(!existsSync(path), `destroy left an additional artifact behind: ${path}`);
    assert(
      !existsSync(path + '.anchor'),
      `destroy left an additional artifact anchor behind: ${path}.anchor`,
    );
  }
}

async function main() {
  let temporaryRoot;
  let previousNpmCache;
  let signal;
  let operationError;
  const onSignal = (value) => {
    signal = value;
    for (const child of activeChildren) child.kill();
  };
  const onSigint = () => onSignal('SIGINT');
  const onSigterm = () => onSignal('SIGTERM');
  process.once('SIGINT', onSigint);
  process.once('SIGTERM', onSigterm);
  try {
    temporaryRoot = await mkdtemp(join(tmpdir(), 'kavrix-pre-ci-'));
    const packRoot = join(temporaryRoot, 'pack');
    const installRoot = join(temporaryRoot, 'install');
    const npmCache = join(temporaryRoot, 'npm-cache');
    await Promise.all([
      mkdir(packRoot, { recursive: true }),
      mkdir(installRoot, { recursive: true }),
      mkdir(npmCache, { recursive: true }),
    ]);
    previousNpmCache = process.env['npm_config_cache'];
    process.env['npm_config_cache'] = npmCache;
    await runProcess(
      npmCommand,
      [...npmArgsPrefix, 'pack', '--pack-destination', packRoot, '--ignore-scripts'],
      { cwd: cliRoot, label: 'npm pack' },
    );
    const archives = (await readdir(packRoot)).filter((file) => file.endsWith('.tgz'));
    assert(archives.length === 1, 'npm pack did not create exactly one archive');
    await runProcess(
      npmCommand,
      [
        ...npmArgsPrefix,
        'install',
        '--ignore-scripts',
        '--no-audit',
        '--no-fund',
        '--omit=dev',
        '--prefix',
        installRoot,
        join(packRoot, archives[0]),
      ],
      { cwd: installRoot, label: 'npm install packed kavrix' },
    );
    const bin = join(installRoot, 'node_modules', 'kavrix', 'dist', 'bin.js');
    assert(existsSync(bin), 'The packed CLI executable is missing');
    const paths = {
      assignedKeyFile: join(installRoot, 'assigned.key'),
      copyKeyFile: join(installRoot, 'copy.key'),
      credentialName: 'acceptance/item',
      dataFile: join(installRoot, 'vault.kavrix'),
      keyFile: join(installRoot, 'primary.key'),
      primaryKeyFile: join(installRoot, 'primary.key'),
      recoveryFile: join(installRoot, 'first.recovery'),
      renamedCredential: 'acceptance/renamed-item',
      replacementKeyFile: join(installRoot, 'replacement.key'),
      replacementRecoveryFile: join(installRoot, 'replacement.recovery'),
      replicaKeyFile: join(installRoot, 'replica.key'),
      secondRecoveryFile: join(installRoot, 'second.recovery'),
      secret: 'runtime-vault-secret-canary-pre-ci',
      temporaryCredential: 'acceptance/temporary',
      vaultId: 'acceptance-vault',
    };
    const run = cliRunner(bin, installRoot, paths.secret);
    await run(['--version']);
    await exerciseHelp(run);
    await exerciseLifecycle(run, bin, installRoot, paths);
    if (signal !== undefined) fail(`Acceptance interrupted by ${signal}`);
  } catch (error) {
    operationError = error;
  }
  process.removeListener('SIGINT', onSigint);
  process.removeListener('SIGTERM', onSigterm);
  const cleanupErrors = [];
  try {
    await stopActiveChildren();
  } catch (error) {
    cleanupErrors.push(error);
  }
  try {
    if (temporaryRoot !== undefined) {
      await rm(temporaryRoot, { recursive: true, force: true });
      assert(!existsSync(temporaryRoot), 'Acceptance temporary root cleanup failed');
    }
  } catch (error) {
    cleanupErrors.push(error);
  }
  if (previousNpmCache === undefined) delete process.env['npm_config_cache'];
  else process.env['npm_config_cache'] = previousNpmCache;
  if (operationError !== undefined && cleanupErrors.length > 0) {
    throw new AggregateError(
      [operationError, ...cleanupErrors],
      'Acceptance and cleanup failed.',
    );
  }
  if (operationError !== undefined) throw operationError;
  if (cleanupErrors.length > 0) {
    throw new AggregateError(cleanupErrors, 'Acceptance cleanup failed.');
  }
  process.stdout.write('Packed all-command local-file acceptance passed.\n');
}

main().catch((error) => {
  process.stderr.write(
    `${error instanceof Error ? error.message : 'Packed acceptance failed.'}\n`,
  );
  process.exitCode = 1;
});
