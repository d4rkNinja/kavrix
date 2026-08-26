/* global Buffer, process, setTimeout, clearTimeout */

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { setWindowsUserOnlyAcl } from '../../../packages/key-files/dist/windows-acl.js';

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const cliRoot = join(workspaceRoot, 'apps', 'cli');
const npmCommand = process.platform === 'win32' ? process.execPath : 'npm';
const npmArgsPrefix =
  process.platform === 'win32'
    ? [join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')]
    : [];
const commandTimeoutMs = 240_000;
const maxOutputBytes = 4 * 1024 * 1024;
const activeChildren = new Set();
const capturedInvocations = [];
const capturedOutputs = [];
const sensitiveValues = new Set();
const expectedPackageFiles = Object.freeze([
  'LICENSE',
  'README.md',
  'dist/bin.js',
  'dist/index.d.ts',
  'dist/index.js',
  'dist/kavrix.cdx.json',
  'package.json',
]);
function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function ephemeralSecret(label) {
  const value = `${label}-${randomBytes(24).toString('base64url')}`;
  sensitiveValues.add(value);
  return value;
}

function stdinFrames(values) {
  return `${values.join('\n')}\n`;
}

function assertNoSensitiveText(text, label) {
  for (const secret of sensitiveValues) {
    assert(!text.includes(secret), `${label} exposed protected runtime input`);
  }
}

function assertSafeInvocation(command, args, environment, label) {
  assertNoSensitiveText(command, `${label} executable`);
  assertNoSensitiveText(JSON.stringify(args), `${label} argv`);
  for (const [name, value] of Object.entries(environment)) {
    if (typeof value !== 'string') continue;
    for (const secret of sensitiveValues) {
      assert(
        value !== secret && !value.includes(secret),
        `${label} environment ${name}`,
      );
    }
  }
}

async function runProcess(command, args, options = {}) {
  const environment = options.environment ?? process.env;
  const label = options.label ?? command;
  assertSafeInvocation(command, args, environment, label);
  capturedInvocations.push({ command, args: [...args] });
  return await new Promise((resolveResult, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd ?? workspaceRoot,
      env: environment,
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    activeChildren.add(child);
    const stdout = [];
    const stderr = [];
    let bytes = 0;
    let settled = false;
    let timeout;
    const finish = (error, result) => {
      if (settled) return;
      settled = true;
      if (timeout !== undefined) clearTimeout(timeout);
      if (error !== undefined) reject(error);
      else resolveResult(result);
    };
    const capture = (chunk, target) => {
      bytes += chunk.byteLength;
      if (bytes > maxOutputBytes) {
        child.kill();
        finish(new Error(`${label} exceeded its output limit`));
        return;
      }
      target.push(Buffer.from(chunk));
    };
    child.stdout.on('data', (chunk) => capture(chunk, stdout));
    child.stderr.on('data', (chunk) => capture(chunk, stderr));
    child.stdin.on('error', () => undefined);
    child.once('error', () => finish(new Error(`${label} could not start`)));
    child.once('close', (code, signal) => {
      activeChildren.delete(child);
      const result = {
        code,
        signal,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      };
      const expectedSensitiveStdout = options.expectedSensitiveStdout;
      const sensitiveOutputMatches =
        expectedSensitiveStdout === undefined ||
        (result.stdout === expectedSensitiveStdout && result.stderr === '');
      capturedOutputs.push({
        label,
        stdout: expectedSensitiveStdout === undefined ? result.stdout : '[VERIFIED]\n',
        stderr: result.stderr,
      });
      if (!sensitiveOutputMatches) {
        finish(new Error(`${label} returned unexpected guarded output`));
        return;
      }
      if (options.allowFailure === true) {
        finish(undefined, result);
      } else if (code !== 0 || signal !== null) {
        finish(new Error(`${label} failed: ${redactedDiagnostic(result)}`));
      } else {
        finish(undefined, result);
      }
    });
    child.stdin.end(options.input ?? '');
    timeout = setTimeout(() => {
      child.kill();
      finish(new Error(`${label} timed out`));
    }, options.timeoutMs ?? commandTimeoutMs);
  });
}

function redactedDiagnostic(result) {
  let diagnostic = `${result.stderr}\n${result.stdout}`.trim();
  for (const secret of sensitiveValues) {
    diagnostic = diagnostic.replaceAll(secret, '[REDACTED]');
  }
  for (const marker of privatePathMarkers()) {
    diagnostic = diagnostic.replaceAll(marker, '[PATH]');
  }
  diagnostic = Array.from(diagnostic)
    .filter((character) => {
      const point = character.codePointAt(0) ?? 0;
      return !(
        point < 9 ||
        point === 11 ||
        point === 12 ||
        (point >= 14 && point <= 31) ||
        (point >= 127 && point <= 159)
      );
    })
    .join('');
  return diagnostic.slice(0, 1_024) || 'no diagnostic output';
}

function parseJson(result, label) {
  try {
    return JSON.parse(result.stdout);
  } catch {
    fail(`${label} did not emit JSON`);
  }
}

function cliRunner(bin, installRoot) {
  return async (args, frames = [], options = {}) => {
    const result = await runProcess(process.execPath, [bin, ...args], {
      cwd: installRoot,
      input: stdinFrames(frames),
      label: `packed kavrix ${args.slice(0, 3).join(' ')}`,
      allowFailure: options.allowFailure,
      expectedSensitiveStdout: options.expectedSensitiveStdout,
    });
    if (options.expectedSensitiveStdout === undefined)
      assertNoSensitiveText(result.stdout, `kavrix ${args.join(' ')} stdout`);
    assertNoSensitiveText(result.stderr, `kavrix ${args.join(' ')} stderr`);
    if (options.expectFailure === true) {
      assert(
        result.code !== 0 || result.signal !== null,
        `kavrix ${args.join(' ')} unexpectedly succeeded`,
      );
    }
    return result;
  };
}

function profileConfigArgs(paths) {
  return ['--config-dir', paths.configDirectory];
}

function profileRoute(paths, profile) {
  return ['--profile', profile, '--profile-config-dir', paths.configDirectory];
}

function legacyFileArgs(dataFile, keyFile, vaultId) {
  return [
    '--datastore',
    'file',
    '--data-file',
    dataFile,
    '--key-file',
    keyFile,
    '--vault',
    vaultId,
  ];
}

async function addFileProfile(run, paths, id, dataFile, keyFile) {
  const result = await run([
    'db',
    'profile',
    'add',
    id,
    ...profileConfigArgs(paths),
    '--datastore',
    'file',
    '--data-file',
    dataFile,
    '--key-file',
    keyFile,
  ]);
  const profile = parseJson(result, `profile add ${id}`).profile;
  assert(profile?.id === id, `profile ${id} was not registered`);
  assert(profile?.databaseId === undefined, `profile ${id} bound before init`);
}

async function selectProfile(run, paths, id) {
  await run(['db', 'profile', 'use', id, ...profileConfigArgs(paths)]);
  const status = parseJson(
    await run(['db', 'profile', 'status', ...profileConfigArgs(paths)]),
    `profile status ${id}`,
  );
  assert(status.current?.id === id, `profile ${id} was not selected`);
}

async function initializeDatabase(run, paths, id, passphrase, label) {
  const result = parseJson(
    await run(
      ['db', 'init', ...profileRoute(paths, id), '--secrets-stdin'],
      [label, passphrase, passphrase],
    ),
    `database init ${id}`,
  );
  assert(result.initialized === true, `database ${id} was not initialized`);
  assert(typeof result.databaseId === 'string', `database ${id} has no identifier`);
  return result.databaseId;
}

async function createVault(run, paths, profile, passphrase, label, options = {}) {
  const result = await run(
    ['db', 'vault', 'create', ...profileRoute(paths, profile), '--secrets-stdin'],
    [passphrase, label],
    options,
  );
  if (options.expectFailure === true) return result;
  const created = parseJson(result, `vault create ${profile}`).created;
  assert(typeof created?.id === 'string', 'vault creation did not return an ID');
  return created.id;
}

async function putCredential(run, paths, profile, vaultId, passphrase, name, value) {
  const result = parseJson(
    await run(
      [
        'put',
        name,
        ...profileRoute(paths, profile),
        '--vault',
        vaultId,
        '--passphrase-stdin',
        '--value-stdin',
      ],
      [passphrase, value],
    ),
    `put ${name}`,
  );
  assert(result.saved === true, `credential ${name} was not saved`);
}

async function assertCredential(run, paths, profile, vaultId, passphrase, name) {
  const route = [
    ...profileRoute(paths, profile),
    '--vault',
    vaultId,
    '--passphrase-stdin',
  ];
  const exists = parseJson(
    await run(['has', name, ...route], [passphrase]),
    `has ${name}`,
  );
  assert(exists.exists === true, `credential ${name} was not found`);
  const read = parseJson(
    await run(['get', name, ...route], [passphrase]),
    `get ${name}`,
  );
  assert(read.value === '[REDACTED]', `credential ${name} was revealed by default`);
}

async function assertCredentialExact(
  run,
  paths,
  profile,
  vaultId,
  passphrase,
  name,
  expected,
) {
  const result = await run(
    [
      'get',
      name,
      ...profileRoute(paths, profile),
      '--vault',
      vaultId,
      '--passphrase-stdin',
      '--reveal',
    ],
    [passphrase],
    { expectedSensitiveStdout: `${expected}\n` },
  );
  assert(result.code === 0 && result.signal === null, `get ${name} did not succeed`);
}

async function exerciseConcurrentConflict(run, paths, profile, passphrase, label) {
  const args = [
    'db',
    'vault',
    'create',
    ...profileRoute(paths, profile),
    '--secrets-stdin',
  ];
  const attempts = await Promise.all([
    run(args, [passphrase, label], { allowFailure: true }),
    run(args, [passphrase, label], { allowFailure: true }),
  ]);
  const successes = attempts.filter(
    (result) => result.code === 0 && result.signal === null,
  );
  const failures = attempts.filter(
    (result) => result.code !== 0 || result.signal !== null,
  );
  assert(successes.length === 1, 'concurrent vault creation had no single winner');
  assert(failures.length === 1, 'concurrent vault creation did not fail closed');
}

async function exerciseDatabaseContainer(run, paths) {
  const primaryPassphrase = ephemeralSecret('primary-passphrase');
  const secondPassphrase = ephemeralSecret('second-passphrase');
  const legacyPassphrase = ephemeralSecret('legacy-passphrase');
  const migrationPassphrase = ephemeralSecret('migration-passphrase');
  const recoveryPassphrase = ephemeralSecret('recovery-passphrase');
  const canaryA = ephemeralSecret('plaintext-canary-a');
  const canaryB = ephemeralSecret('plaintext-canary-b');
  const legacyCanary = ephemeralSecret('plaintext-canary-legacy');
  const databaseLabel = ephemeralSecret('private-database-label');
  const firstVaultLabel = ephemeralSecret('private-vault-label-a');
  const secondVaultLabel = ephemeralSecret('private-vault-label-b');
  const conflictLabel = ephemeralSecret('private-vault-label-conflict');
  const secondDatabaseLabel = ephemeralSecret('private-database-label-two');
  const secondDatabaseVaultLabel = ephemeralSecret('private-vault-label-two');
  const migratedDatabaseLabel = ephemeralSecret('private-database-label-migrated');
  const migratedVaultLabel = ephemeralSecret('private-vault-label-migrated');

  await addFileProfile(
    run,
    paths,
    'primary',
    paths.primaryDataFile,
    paths.primaryKeyFile,
  );
  await selectProfile(run, paths, 'primary');
  const primaryDatabaseId = await initializeDatabase(
    run,
    paths,
    'primary',
    primaryPassphrase,
    databaseLabel,
  );

  const firstVaultId = await createVault(
    run,
    paths,
    'primary',
    primaryPassphrase,
    firstVaultLabel,
  );
  const secondVaultId = await createVault(
    run,
    paths,
    'primary',
    primaryPassphrase,
    secondVaultLabel,
  );
  assert(firstVaultId !== secondVaultId, 'database vault IDs are not independent');

  const listed = parseJson(
    await run(
      [
        'db',
        'vault',
        'list',
        ...profileRoute(paths, 'primary'),
        '--secrets-stdin',
        '--json',
      ],
      [primaryPassphrase],
    ),
    'primary vault list',
  );
  assert(listed.vaults?.length === 2, 'primary database did not list two vaults');
  assert(
    listed.vaults.every((entry) => entry.label === '[REDACTED]'),
    'vault labels were visible without an explicit reveal flow',
  );

  await putCredential(
    run,
    paths,
    'primary',
    firstVaultId,
    primaryPassphrase,
    'service/first',
    canaryA,
  );
  await putCredential(
    run,
    paths,
    'primary',
    secondVaultId,
    primaryPassphrase,
    'service/second',
    canaryB,
  );
  await assertCredential(
    run,
    paths,
    'primary',
    firstVaultId,
    primaryPassphrase,
    'service/first',
  );
  await assertCredential(
    run,
    paths,
    'primary',
    secondVaultId,
    primaryPassphrase,
    'service/second',
  );
  await assertCredentialExact(
    run,
    paths,
    'primary',
    firstVaultId,
    primaryPassphrase,
    'service/first',
    canaryA,
  );
  await assertCredentialExact(
    run,
    paths,
    'primary',
    secondVaultId,
    primaryPassphrase,
    'service/second',
    canaryB,
  );

  await run(
    [
      'db',
      'recovery',
      'create',
      ...profileRoute(paths, 'primary'),
      '--recovery-file',
      paths.databaseRecoveryFile,
      '--secrets-stdin',
    ],
    [primaryPassphrase, recoveryPassphrase, recoveryPassphrase],
  );

  await exerciseConcurrentConflict(
    run,
    paths,
    'primary',
    primaryPassphrase,
    conflictLabel,
  );

  await addFileProfile(
    run,
    paths,
    'secondary',
    paths.secondDataFile,
    paths.secondKeyFile,
  );
  await selectProfile(run, paths, 'secondary');
  const secondDatabaseId = await initializeDatabase(
    run,
    paths,
    'secondary',
    secondPassphrase,
    secondDatabaseLabel,
  );
  assert(secondDatabaseId !== primaryDatabaseId, 'two databases shared an ID');
  await createVault(
    run,
    paths,
    'secondary',
    secondPassphrase,
    secondDatabaseVaultLabel,
  );

  const wrongDatabaseBinding = await run(
    [
      'db',
      'status',
      ...profileRoute(paths, 'secondary'),
      '--key-file',
      paths.primaryKeyFile,
      '--secrets-stdin',
    ],
    [primaryPassphrase],
    { allowFailure: true, expectFailure: true },
  );
  assert(
    wrongDatabaseBinding.stdout === '' &&
      wrongDatabaseBinding.stderr === 'Database binding validation failed.\n',
    'wrong database/key pairing did not fail with the exact redacted binding error',
  );

  await selectProfile(run, paths, 'primary');
  await assertCredential(
    run,
    paths,
    'primary',
    firstVaultId,
    primaryPassphrase,
    'service/first',
  );
  await assertCredential(
    run,
    paths,
    'primary',
    secondVaultId,
    primaryPassphrase,
    'service/second',
  );

  const anchorPath = `${paths.primaryKeyFile}.database-anchor`;
  const staleAnchor = await readFile(anchorPath);
  const staleDatabase = await readFile(paths.primaryDataFile);
  await createVault(
    run,
    paths,
    'primary',
    primaryPassphrase,
    ephemeralSecret('private-vault-label-anchor-advance'),
  );
  const currentAnchor = await readFile(anchorPath);
  assert(!staleAnchor.equals(currentAnchor), 'database anchor did not advance');
  const currentDatabase = await readFile(paths.primaryDataFile);
  try {
    await writeFile(anchorPath, staleAnchor);
    if (process.platform !== 'win32') await chmod(anchorPath, 0o600);
    const staleAnchorFailure = await run(
      ['db', 'status', ...profileRoute(paths, 'primary'), '--secrets-stdin'],
      [primaryPassphrase],
      { allowFailure: true, expectFailure: true },
    );
    assert(
      staleAnchorFailure.stdout === '' &&
        staleAnchorFailure.stderr ===
          'The database snapshot was rejected as stale or forked.\n',
      'an authentic stale database anchor did not fail with the rollback error',
    );
  } finally {
    await writeFile(anchorPath, currentAnchor);
    if (process.platform !== 'win32') await chmod(anchorPath, 0o600);
  }

  try {
    await writeFile(paths.primaryDataFile, staleDatabase);
    if (process.platform !== 'win32') await chmod(paths.primaryDataFile, 0o600);
    const rollbackFailure = await run(
      ['db', 'status', ...profileRoute(paths, 'primary'), '--secrets-stdin'],
      [primaryPassphrase],
      { allowFailure: true, expectFailure: true },
    );
    assert(
      rollbackFailure.stdout === '' &&
        rollbackFailure.stderr ===
          'The database snapshot was rejected as stale or forked.\n',
      'a stale database snapshot did not fail with the pinned rollback error',
    );
  } finally {
    await writeFile(paths.primaryDataFile, currentDatabase);
    if (process.platform !== 'win32') await chmod(paths.primaryDataFile, 0o600);
  }

  try {
    const tamperedAnchor = Buffer.from(currentAnchor);
    assert(tamperedAnchor.byteLength > 0, 'database anchor was empty');
    tamperedAnchor[tamperedAnchor.byteLength - 1] ^= 1;
    await writeFile(anchorPath, tamperedAnchor);
    if (process.platform !== 'win32') await chmod(anchorPath, 0o600);
    const tamperedAnchorFailure = await run(
      ['db', 'status', ...profileRoute(paths, 'primary'), '--secrets-stdin'],
      [primaryPassphrase],
      { allowFailure: true, expectFailure: true },
    );
    assert(
      tamperedAnchorFailure.stdout === '' &&
        tamperedAnchorFailure.stderr ===
          'The database snapshot was rejected as stale or forked.\n',
      'a tampered database anchor did not fail with the pinned rollback error',
    );
  } finally {
    await writeFile(anchorPath, currentAnchor);
    if (process.platform !== 'win32') await chmod(anchorPath, 0o600);
  }

  const authenticDatabase = await readFile(paths.primaryDataFile);
  try {
    const tampered = JSON.parse(authenticDatabase.toString('utf8'));
    const ciphertext = tampered.database.encryptedCatalog.ciphertext;
    assert(typeof ciphertext === 'string' && ciphertext.length > 0, 'catalog missing');
    tampered.database.encryptedCatalog.ciphertext = `${
      ciphertext[0] === 'A' ? 'B' : 'A'
    }${ciphertext.slice(1)}`;
    await writeFile(paths.primaryDataFile, JSON.stringify(tampered));
    if (process.platform !== 'win32') await chmod(paths.primaryDataFile, 0o600);
    await run(
      ['db', 'status', ...profileRoute(paths, 'primary'), '--secrets-stdin'],
      [primaryPassphrase],
      { allowFailure: true, expectFailure: true },
    );
  } finally {
    await writeFile(paths.primaryDataFile, authenticDatabase);
    if (process.platform !== 'win32') await chmod(paths.primaryDataFile, 0o600);
  }

  await addFileProfile(run, paths, 'legacy', paths.legacyDataFile, paths.legacyKeyFile);
  await run(
    [
      'init',
      ...legacyFileArgs(paths.legacyDataFile, paths.legacyKeyFile, 'legacy-v2'),
      '--passphrase-stdin',
    ],
    [legacyPassphrase, legacyPassphrase],
  );
  await run(
    [
      'put',
      'legacy/item',
      ...legacyFileArgs(paths.legacyDataFile, paths.legacyKeyFile, 'legacy-v2'),
      '--passphrase-stdin',
      '--value-stdin',
    ],
    [legacyPassphrase, legacyCanary],
  );

  await addFileProfile(
    run,
    paths,
    'migrated',
    paths.migratedDataFile,
    paths.migratedKeyFile,
  );
  const migrated = parseJson(
    await run(
      [
        'migrate',
        'database',
        '--source-profile',
        'legacy',
        '--destination-profile',
        'migrated',
        '--source-vault',
        'legacy-v2',
        '--profile-config-dir',
        paths.configDirectory,
        '--initialize',
        '--secrets-stdin',
      ],
      [
        legacyPassphrase,
        'legacy-v2',
        migrationPassphrase,
        migrationPassphrase,
        migratedDatabaseLabel,
        migratedVaultLabel,
      ],
    ),
    'legacy database migration',
  );
  assert(migrated.migrated === true, 'legacy migration did not report success');
  assert(migrated.recordCount === 1, 'legacy migration record count was incorrect');
  await selectProfile(run, paths, 'migrated');
  await assertCredential(
    run,
    paths,
    'migrated',
    migrated.vaultId,
    migrationPassphrase,
    'legacy/item',
  );
  await assertCredentialExact(
    run,
    paths,
    'migrated',
    migrated.vaultId,
    migrationPassphrase,
    'legacy/item',
    legacyCanary,
  );

  await selectProfile(run, paths, 'primary');
  await assertCredential(
    run,
    paths,
    'primary',
    firstVaultId,
    primaryPassphrase,
    'service/first',
  );
  await assertCredential(
    run,
    paths,
    'primary',
    secondVaultId,
    primaryPassphrase,
    'service/second',
  );
}

async function walkFiles(root, current = root) {
  const entries = await readdir(current, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(current, entry.name);
    if (entry.isDirectory()) files.push(...(await walkFiles(root, path)));
    else if (entry.isFile()) files.push(relative(root, path).replaceAll('\\', '/'));
  }
  return files;
}

function privatePathMarkers() {
  const candidates = [workspaceRoot, dirname(workspaceRoot), homedir()];
  return [...new Set(candidates.map((value) => value.replaceAll('\\', '/')))];
}

function assertNoPrivatePath(text, label) {
  const normalized = text.replaceAll('\\', '/');
  for (const marker of privatePathMarkers()) {
    assert(!normalized.includes(marker), `${label} contains a private build path`);
  }
}

async function scanPackage(packageRoot) {
  const files = (await walkFiles(packageRoot)).sort();
  assertExactPackageFiles(files);
  for (const file of files) {
    const content = await readFile(join(packageRoot, file));
    const text = content.toString('utf8');
    assertNoSensitiveText(text, `package ${file}`);
    assertNoPrivatePath(text, `package ${file}`);
  }
}

function assertExactPackageFiles(files) {
  const normalized = [
    ...new Set(files.map((file) => file.replaceAll('\\', '/'))),
  ].sort();
  assert(
    JSON.stringify(normalized) === JSON.stringify(expectedPackageFiles),
    'packed package does not match the exact public file allowlist',
  );
}

function provePackageAllowlistRejectsExtras() {
  let rejected = false;
  try {
    assertExactPackageFiles([...expectedPackageFiles, 'dist/private/debug.js']);
  } catch {
    rejected = true;
  }
  assert(rejected, 'package allowlist accepted a private debug artifact');
}

async function scanArtifacts(paths) {
  for (const path of [
    join(paths.configDirectory, 'datastore-profiles.json'),
    paths.primaryDataFile,
    paths.primaryKeyFile,
    `${paths.primaryKeyFile}.database-anchor`,
    paths.databaseRecoveryFile,
    `${paths.databaseRecoveryFile}.database-anchor`,
    paths.secondDataFile,
    paths.secondKeyFile,
    `${paths.secondKeyFile}.database-anchor`,
    paths.legacyDataFile,
    paths.legacyKeyFile,
    `${paths.legacyKeyFile}.anchor`,
    paths.migratedDataFile,
    paths.migratedKeyFile,
    `${paths.migratedKeyFile}.database-anchor`,
  ]) {
    assert(existsSync(path), `expected acceptance artifact is missing: ${path}`);
    const content = await readFile(path);
    const text = content.toString('utf8');
    assertNoSensitiveText(text, `artifact ${path}`);
    assertNoPrivatePath(text, `artifact ${path}`);
  }
  for (const output of capturedOutputs) {
    assertNoSensitiveText(output.stdout, `${output.label} stdout`);
    assertNoSensitiveText(output.stderr, `${output.label} stderr`);
    assertNoPrivatePath(output.stdout, `${output.label} stdout`);
    assertNoPrivatePath(output.stderr, `${output.label} stderr`);
  }
  for (const invocation of capturedInvocations) {
    assertNoSensitiveText(JSON.stringify(invocation), 'captured argv');
    assertNoPrivatePath(JSON.stringify(invocation.args), 'captured argv');
  }
}

async function stopActiveChildren() {
  const failures = [];
  for (const child of [...activeChildren]) {
    try {
      if (child.exitCode !== null || child.signalCode !== null) {
        activeChildren.delete(child);
        continue;
      }
      await new Promise((resolveStopped) => {
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
        child.kill('SIGTERM');
        forceKill = setTimeout(() => {
          child.kill('SIGKILL');
          finish();
        }, 1_000);
      });
    } catch {
      failures.push(new Error('A child process could not be stopped.'));
    }
  }
  if (failures.length > 0) throw new AggregateError(failures, 'Child cleanup failed.');
}

function redactedError(error, fallback) {
  const source = error instanceof Error ? error.message : fallback;
  let message = source;
  for (const secret of sensitiveValues)
    message = message.replaceAll(secret, '[REDACTED]');
  for (const marker of privatePathMarkers())
    message = message.replaceAll(marker, '[PATH]');
  return new Error(message.length === 0 ? fallback : message);
}

async function runSignalProbeChild(signal, stage) {
  if (
    (signal !== 'SIGINT' && signal !== 'SIGTERM') ||
    (stage !== 'startup' && stage !== 'cleanup')
  )
    process.exit(2);
  const previousNpmCache = process.env['npm_config_cache'];
  let roots = [];
  let releaseBarrier;
  const barrier = new Promise((resolveBarrier) => {
    releaseBarrier = resolveBarrier;
  });
  let cleanupPromise;
  let cleanupStarts = 0;
  let finalizing = false;
  const cleanup = () => {
    if (cleanupPromise !== undefined) return cleanupPromise;
    cleanupStarts += 1;
    cleanupPromise = (async () => {
      const errors = [];
      for (let index = 0; index < roots.length; index += 1) {
        try {
          await rm(roots[index], { recursive: true, force: true });
        } catch {
          errors.push(new Error('target cleanup failed'));
        }
        if (stage === 'cleanup' && index === 0) {
          process.send?.({ type: 'cleanup-paused' });
          await barrier;
        }
      }
      try {
        if (previousNpmCache === undefined) delete process.env['npm_config_cache'];
        else process.env['npm_config_cache'] = previousNpmCache;
      } catch {
        errors.push(new Error('cache restoration failed'));
      }
      if (errors.length > 0) throw new AggregateError(errors, 'cleanup failed');
    })();
    return cleanupPromise;
  };
  const finish = async () => {
    if (finalizing) return;
    finalizing = true;
    let passed;
    try {
      await cleanup();
      passed =
        cleanupStarts === 1 &&
        roots.every((root) => !existsSync(root)) &&
        process.env['npm_config_cache'] === previousNpmCache;
    } catch {
      passed = false;
    }
    process.removeListener('SIGINT', onSigint);
    process.removeListener('SIGTERM', onSigterm);
    process.send?.({ type: passed ? 'cleanup-complete' : 'cleanup-failed' });
    process.disconnect?.();
    if (!passed) process.exitCode = 1;
  };
  const onNamedSignal = () => {
    releaseBarrier?.();
    void finish();
  };
  const onSigint = () => onNamedSignal();
  const onSigterm = () => onNamedSignal();
  process.on('SIGINT', onSigint);
  process.on('SIGTERM', onSigterm);
  process.on('message', (message) => {
    if (message?.type === 'configure') {
      if (
        roots.length !== 0 ||
        !Array.isArray(message.roots) ||
        message.roots.length !== 3 ||
        message.roots.some(
          (root) =>
            typeof root !== 'string' ||
            !resolve(root).startsWith(
              `${resolve(tmpdir())}${process.platform === 'win32' ? '\\' : '/'}`,
            ),
        )
      ) {
        process.send?.({ type: 'cleanup-failed' });
        return;
      }
      roots = [...message.roots];
      if (stage === 'startup') {
        process.send?.({ type: 'startup-paused' });
        return;
      }
      void (async () => {
        try {
          for (const root of roots) await mkdir(root, { mode: 0o700 });
          process.env['npm_config_cache'] = roots[2];
          process.send?.({ type: 'ready' });
        } catch {
          await finish();
        }
      })();
    }
    if (message?.type === 'begin-cleanup') void cleanup();
    if (message?.type === 'deliver-signal') process.emit(signal);
  });
  process.send?.({ type: 'handlers-ready' });
}

async function exerciseSignalCleanupProbe(signal, stage) {
  const nonce = randomBytes(16).toString('hex');
  const roots = ['install', 'pack', 'cache'].map((kind) =>
    join(tmpdir(), `kavrix-signal-${kind}-${nonce}`),
  );
  const child = spawn(
    process.execPath,
    [fileURLToPath(import.meta.url), '--signal-probe-child', signal, stage],
    {
      env: process.env,
      shell: false,
      stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      windowsHide: true,
    },
  );
  activeChildren.add(child);
  let completed = false;
  try {
    await new Promise((resolveProbe, rejectProbe) => {
      let timeout;
      const finish = (error) => {
        if (timeout !== undefined) clearTimeout(timeout);
        if (error === undefined) resolveProbe();
        else rejectProbe(error);
      };
      child.on('message', (message) => {
        if (message?.type === 'handlers-ready') {
          child.send({ type: 'configure', roots });
        } else if (message?.type === 'startup-paused') {
          if (process.platform === 'win32') child.send({ type: 'deliver-signal' });
          else child.kill(signal);
        } else if (message?.type === 'ready') {
          child.send({ type: 'begin-cleanup' });
        } else if (message?.type === 'cleanup-paused') {
          if (process.platform === 'win32') child.send({ type: 'deliver-signal' });
          else child.kill(signal);
        } else if (message?.type === 'cleanup-complete') {
          completed = true;
        } else if (message?.type === 'cleanup-failed') {
          finish(new Error(`${signal} ${stage} probe reported failure`));
        }
      });
      child.once('error', () => finish(new Error(`${signal} ${stage} probe failed`)));
      child.once('close', (code, childSignal) => {
        activeChildren.delete(child);
        if (!completed || code !== 0 || childSignal !== null) {
          finish(new Error(`${signal} ${stage} probe exited before verification`));
          return;
        }
        finish();
      });
      timeout = setTimeout(() => {
        child.kill('SIGKILL');
        finish(new Error(`${signal} ${stage} probe timed out`));
      }, 20_000);
    });
    assert(
      roots.every((root) => !existsSync(root)),
      `${signal} ${stage} probe left a potential root behind`,
    );
  } finally {
    activeChildren.delete(child);
    for (const root of roots) await rm(root, { recursive: true, force: true });
  }
}

async function main() {
  let packRoot;
  let installRoot;
  let npmCache;
  const previousNpmCache = process.env['npm_config_cache'];
  let interruptedSignal;
  let operationError;
  let verifiedVersion;
  let cleanupPromise;
  const onSignal = (signal) => {
    interruptedSignal ??= signal;
    for (const child of activeChildren) child.kill('SIGTERM');
    void cleanup();
  };
  const onSigint = () => onSignal('SIGINT');
  const onSigterm = () => onSignal('SIGTERM');
  const cleanup = () => {
    if (cleanupPromise !== undefined) return cleanupPromise;
    cleanupPromise = (async () => {
      const cleanupErrors = [];
      for (const [label, cleanupTarget] of [
        ['child processes', () => stopActiveChildren()],
        [
          'npm cache environment',
          async () => {
            if (previousNpmCache === undefined) delete process.env['npm_config_cache'];
            else process.env['npm_config_cache'] = previousNpmCache;
          },
        ],
        [
          'installed package',
          async () => {
            if (installRoot !== undefined)
              await rm(installRoot, { recursive: true, force: true });
          },
        ],
        [
          'packed archive',
          async () => {
            if (packRoot !== undefined)
              await rm(packRoot, { recursive: true, force: true });
          },
        ],
        [
          'dedicated npm cache',
          async () => {
            if (npmCache !== undefined)
              await rm(npmCache, { recursive: true, force: true });
          },
        ],
      ]) {
        try {
          await cleanupTarget();
        } catch (error) {
          cleanupErrors.push(redactedError(error, `${label} cleanup failed.`));
        }
      }
      for (const [label, path] of [
        ['installed package', installRoot],
        ['packed archive', packRoot],
        ['dedicated npm cache', npmCache],
      ]) {
        if (path !== undefined && existsSync(path)) {
          cleanupErrors.push(new Error(`${label} cleanup did not remove its target.`));
        }
      }
      if (process.env['npm_config_cache'] !== previousNpmCache) {
        cleanupErrors.push(new Error('npm cache environment was not restored.'));
      }
      return cleanupErrors;
    })();
    return cleanupPromise;
  };
  const registerRoot = async (root) => {
    if (interruptedSignal === undefined) return root;
    await rm(root, { recursive: true, force: true });
    throw new Error(`Acceptance interrupted by ${interruptedSignal}`);
  };
  process.on('SIGINT', onSigint);
  process.on('SIGTERM', onSigterm);
  try {
    provePackageAllowlistRejectsExtras();
    await exerciseSignalCleanupProbe('SIGINT', 'startup');
    await exerciseSignalCleanupProbe('SIGTERM', 'startup');
    await exerciseSignalCleanupProbe('SIGINT', 'cleanup');
    await exerciseSignalCleanupProbe('SIGTERM', 'cleanup');
    packRoot = await registerRoot(
      await mkdtemp(join(tmpdir(), 'kavrix-database-pack-')),
    );
    installRoot = await registerRoot(
      await mkdtemp(join(tmpdir(), 'kavrix-database-install-')),
    );
    npmCache = await registerRoot(
      await mkdtemp(join(tmpdir(), 'kavrix-database-npm-cache-')),
    );
    if (process.platform === 'win32') {
      await Promise.all(
        [packRoot, installRoot, npmCache].map((root) => setWindowsUserOnlyAcl(root)),
      );
    }
    process.env['npm_config_cache'] = npmCache;
    const npmEnvironment = { ...process.env, npm_config_cache: npmCache };
    await runProcess(
      npmCommand,
      [...npmArgsPrefix, 'pack', '--pack-destination', packRoot, '--ignore-scripts'],
      { cwd: cliRoot, environment: npmEnvironment, label: 'npm pack kavrix' },
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
      {
        cwd: installRoot,
        environment: npmEnvironment,
        label: 'npm install packed kavrix',
      },
    );

    const packageRoot = join(installRoot, 'node_modules', 'kavrix');
    const bin = join(packageRoot, 'dist', 'bin.js');
    assert(existsSync(bin), 'packed kavrix executable is missing');
    const manifest = JSON.parse(
      await readFile(join(packageRoot, 'package.json'), 'utf8'),
    );
    verifiedVersion = manifest.version;
    await scanPackage(packageRoot);

    const paths = {
      configDirectory: join(installRoot, 'profiles'),
      primaryDataFile: join(installRoot, 'primary.database'),
      primaryKeyFile: join(installRoot, 'primary.database.key'),
      databaseRecoveryFile: join(installRoot, 'primary.database.recovery'),
      secondDataFile: join(installRoot, 'secondary.database'),
      secondKeyFile: join(installRoot, 'secondary.database.key'),
      legacyDataFile: join(installRoot, 'legacy.vault'),
      legacyKeyFile: join(installRoot, 'legacy.key'),
      migratedDataFile: join(installRoot, 'migrated.database'),
      migratedKeyFile: join(installRoot, 'migrated.database.key'),
    };
    await mkdir(paths.configDirectory, { recursive: true });
    if (process.platform === 'win32') {
      await setWindowsUserOnlyAcl(paths.configDirectory);
    } else {
      await chmod(paths.configDirectory, 0o700);
    }
    const run = cliRunner(bin, installRoot);
    const rootHelp = await run(['--help']);
    assert(!/^\s*destroy(?:\s|$)/mu.test(rootHelp.stdout), 'destroy leaked into help');
    await exerciseDatabaseContainer(run, paths);
    await scanPackage(packageRoot);
    await scanArtifacts(paths);
    if (interruptedSignal !== undefined) {
      fail(`Acceptance interrupted by ${interruptedSignal}`);
    }
  } catch (error) {
    operationError = redactedError(error, 'Packed database acceptance failed.');
  }
  const cleanupErrors = await cleanup();
  if (interruptedSignal !== undefined && operationError === undefined) {
    operationError = new Error(`Acceptance interrupted by ${interruptedSignal}`);
  }
  process.removeListener('SIGINT', onSigint);
  process.removeListener('SIGTERM', onSigterm);
  if (operationError !== undefined && cleanupErrors.length > 0) {
    throw new AggregateError(
      [operationError, ...cleanupErrors],
      'Packed database acceptance and cleanup failed.',
    );
  }
  if (operationError !== undefined) throw operationError;
  if (cleanupErrors.length > 0) {
    throw new AggregateError(
      cleanupErrors,
      'Packed database acceptance cleanup failed.',
    );
  }
  process.stdout.write(
    `Packed kavrix ${verifiedVersion} database-container acceptance passed.\n`,
  );
}

const entryMode = process.argv[2];
const entryPromise =
  entryMode === '--signal-probe-child'
    ? runSignalProbeChild(process.argv[3], process.argv[4])
    : main();

entryPromise.catch((error) => {
  const message =
    error instanceof AggregateError
      ? error.message
      : error instanceof Error
        ? error.message
        : 'Packed database acceptance failed.';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
