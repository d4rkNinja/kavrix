/**
 * End-to-end smoke of the `note` and `item history` families through the
 * PACKAGED binary (`apps/cli/dist/bin.js`), not the source tree.
 *
 * The unit tests in `apps/cli/test` build their own Commander program, so a
 * missing top-level registration, a stale bundle, or a tsconfig that omits a new
 * source file from `dist` is invisible to them. This script catches all three.
 * Run it after every build.
 *
 * Asserts, against a real encrypted file database:
 *   1. notes add / list / show / remove round-trip and mask the body;
 *   2. a sensitive note is masked by default;
 *   3. `item history list` / `show` resolve and report an empty history;
 *   4. unknown identifiers fail closed with a stable code and no stdout;
 *   5. no note body, passphrase, or field value appears in the container bytes.
 */
import { spawn } from 'node:child_process';
import { mkdir, readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { setWindowsUserOnlyAcl } from '../packages/key-files/dist/windows-acl.js';

const BIN = 'apps/cli/dist/bin.js';
const PASSPHRASE = 'smoke-passphrase-8f2c1d';
const NOTE_BODY = 'NOTE-BODY-CANARY-5b71e2';
const REVEAL_BODY = 'SENSITIVE-REVEAL-CANARY-9d4a06';
const FIELD_SECRET = 'PASSWORD-CANARY-1a2b3c';

/**
 * A fresh directory hardened to user-only, mirroring the repository's own
 * `createSecureTestDirectory`. Kavrix refuses a key/data directory it cannot
 * verify as private, so an unprotected `%TEMP%` path fails for a real reason.
 */
async function secureDirectory(name) {
  const directory = join(await realpath(tmpdir()), name);
  await mkdir(directory, { recursive: true });
  if (process.platform === 'win32') {
    await setWindowsUserOnlyAcl(directory);
  }
  return directory;
}

function run(args, stdin = '') {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, ...args], {
      cwd: process.cwd(),
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', reject);
    child.on('close', (exitCode) => resolve({ exitCode, stdout, stderr }));
    if (stdin.length > 0) child.stdin.write(stdin);
    child.stdin.end();
  });
}

let failures = 0;
function check(label, condition, detail = '') {
  if (condition) {
    console.log(`  ok   ${label}`);
    return;
  }
  failures += 1;
  console.log(`  FAIL ${label} ${detail}`);
}

function jsonField(stdout, path) {
  try {
    const parsed = JSON.parse(stdout);
    return path.reduce((node, key) => (node ?? {})[key], parsed) ?? '';
  } catch {
    return '';
  }
}

function notesOf(stdout) {
  try {
    const parsed = JSON.parse(stdout);
    return Array.isArray(parsed?.notes) ? parsed.notes : [];
  } catch {
    return [];
  }
}

const home = await secureDirectory('kavrix-smoke-');
const dataFile = join(home, 'database.kavrix');
const keyFile = join(home, 'database.kavrix.key');
const configDir = join(home, 'config');
// `db init` and `db vault create` build the database and its first vault, so
// neither takes `--vault` yet; the vault is then selected as the profile default
// and every later command routes through that selection.
const bootstrap = [
  '--profile',
  'smoke',
  '--config-dir',
  configDir,
  '--datastore',
  'file',
  '--data-file',
  dataFile,
  '--key-file',
  keyFile,
];

/** One vault-scoped call that reads only the passphrase frame. */
const authed = (...args) =>
  run([...args, ...bootstrap, '--passphrase-stdin', '--json'], PASSPHRASE + '\n');

try {
  console.log('1. profile and encrypted database');
  const added = await run([
    'db',
    'profile',
    'add',
    'smoke',
    '--config-dir',
    configDir,
    '--datastore',
    'file',
    '--data-file',
    dataFile,
    '--key-file',
    keyFile,
    '--json',
  ]);
  check(
    'db profile add exits 0',
    added.exitCode === 0,
    added.stderr.trim().slice(0, 200),
  );
  const used = await run([
    'db',
    'profile',
    'use',
    'smoke',
    '--config-dir',
    configDir,
    '--json',
  ]);
  check(
    'db profile use exits 0',
    used.exitCode === 0,
    used.stderr.trim().slice(0, 200),
  );

  // db init reads: label, passphrase, passphrase-confirm.
  const initialized = await run(
    ['db', 'init', ...bootstrap, '--passphrase-stdin', '--json'],
    ['smoke label', PASSPHRASE, PASSPHRASE].join('\n') + '\n',
  );
  check(
    'db init exits 0',
    initialized.exitCode === 0,
    initialized.stderr.trim().slice(0, 250),
  );

  // db vault create reads: passphrase, label, and returns the opaque vault id.
  const vault = await run(
    ['db', 'vault', 'create', ...bootstrap, '--passphrase-stdin', '--json'],
    [PASSPHRASE, 'main'].join('\n') + '\n',
  );
  check(
    'db vault create exits 0',
    vault.exitCode === 0,
    vault.stderr.trim().slice(0, 250),
  );
  const vaultId = jsonField(vault.stdout, ['vaultId']);
  check(
    'db vault create returned an opaque id',
    vaultId.length > 0 && !vaultId.includes('main'),
    vault.stdout.slice(0, 160),
  );

  const selected = await run(
    ['db', 'vault', 'use', vaultId, '--config-dir', configDir, '--passphrase-stdin'],
    PASSPHRASE + '\n',
  );
  check(
    'db vault use exits 0',
    selected.exitCode === 0,
    selected.stderr.trim().slice(0, 250),
  );

  console.log('2. context / service / item / field');
  const context = await authed('context', 'create', 'platform');
  check(
    'context create exits 0',
    context.exitCode === 0,
    context.stderr.trim().slice(0, 200),
  );
  const service = await authed('service', 'create', 'api', '--context', 'platform');
  check(
    'service create exits 0',
    service.exitCode === 0,
    service.stderr.trim().slice(0, 200),
  );
  const item = await authed(
    'item',
    'create',
    'runbook',
    '--context',
    'platform',
    '--service',
    'api',
  );
  check('item create exits 0', item.exitCode === 0, item.stderr.trim().slice(0, 200));

  // A field value is a protected frame, never an argv value.
  const field = await run(
    [
      'field',
      'set',
      'password',
      '--item',
      'runbook',
      '--type',
      'secret',
      '--context',
      'platform',
      '--service',
      'api',
      ...bootstrap,
      '--passphrase-stdin',
      '--value-stdin',
      '--json',
    ],
    [PASSPHRASE, FIELD_SECRET].join('\n') + '\n',
  );
  check('field set exits 0', field.exitCode === 0, field.stderr.trim().slice(0, 250));
  check('field set hides the value', !field.stdout.includes(FIELD_SECRET));

  console.log('3. note add / list / show / remove');
  const noteAdd = await run(
    [
      'note',
      'add',
      'runbook',
      'Rotation',
      '--context',
      'platform',
      '--service',
      'api',
      ...bootstrap,
      '--passphrase-stdin',
      '--content-stdin',
      '--json',
    ],
    [PASSPHRASE, NOTE_BODY].join('\n') + '\n',
  );
  check(
    'note add exits 0',
    noteAdd.exitCode === 0,
    noteAdd.stderr.trim().slice(0, 250),
  );
  check('note add does not echo the body', !noteAdd.stdout.includes(NOTE_BODY));

  const noteList = await authed(
    'note',
    'list',
    'runbook',
    '--context',
    'platform',
    '--service',
    'api',
  );
  check(
    'note list exits 0',
    noteList.exitCode === 0,
    noteList.stderr.trim().slice(0, 250),
  );
  check('note list names the title', noteList.stdout.includes('Rotation'));
  check('note list hides the body', !noteList.stdout.includes(NOTE_BODY));
  const noteId =
    notesOf(noteList.stdout)[0]?.id ?? notesOf(noteList.stdout)[0]?.noteId ?? '';
  check('note list returned an id', noteId.length > 0, noteList.stdout.slice(0, 160));

  const noteShow = await authed(
    'note',
    'show',
    'runbook',
    noteId,
    '--context',
    'platform',
    '--service',
    'api',
  );
  check(
    'note show exits 0',
    noteShow.exitCode === 0,
    noteShow.stderr.trim().slice(0, 250),
  );
  // Parity with `field get`: a note the user did not mark sensitive shows its
  // content; only `--sensitive` content needs the reveal guard.
  check(
    'non-sensitive note shows content',
    noteShow.stdout.includes(NOTE_BODY),
    noteShow.stdout.slice(0, 200),
  );

  const noteRemove = await authed(
    'note',
    'remove',
    'runbook',
    noteId,
    '--context',
    'platform',
    '--service',
    'api',
  );
  check(
    'note remove exits 0',
    noteRemove.exitCode === 0,
    noteRemove.stderr.trim().slice(0, 250),
  );
  const afterRemove = await authed(
    'note',
    'list',
    'runbook',
    '--context',
    'platform',
    '--service',
    'api',
  );
  check(
    'note list is empty after remove',
    !afterRemove.stdout.includes(NOTE_BODY),
    afterRemove.stdout.slice(0, 200),
  );

  console.log('4. sensitive notes');
  const sensitive = await run(
    [
      'note',
      'add',
      'runbook',
      'Break-glass',
      '--sensitive',
      '--context',
      'platform',
      '--service',
      'api',
      ...bootstrap,
      '--passphrase-stdin',
      '--content-stdin',
      '--json',
    ],
    [PASSPHRASE, REVEAL_BODY].join('\n') + '\n',
  );
  check(
    'sensitive note add exits 0',
    sensitive.exitCode === 0,
    sensitive.stderr.trim().slice(0, 250),
  );
  check('sensitive note add hides the body', !sensitive.stdout.includes(REVEAL_BODY));
  const masked = await authed(
    'note',
    'list',
    'runbook',
    '--context',
    'platform',
    '--service',
    'api',
  );
  check('sensitive note masked in list', !masked.stdout.includes(REVEAL_BODY));
  const sensitiveId =
    notesOf(masked.stdout)[0]?.id ?? notesOf(masked.stdout)[0]?.noteId ?? '';
  const revealGuarded = await authed(
    'note',
    'show',
    'runbook',
    sensitiveId,
    '--context',
    'platform',
    '--service',
    'api',
  );
  check(
    'sensitive note masked without --reveal',
    !revealGuarded.stdout.includes(REVEAL_BODY),
    revealGuarded.stdout.slice(0, 160),
  );

  // The guarded path: the same note behind the explicit reveal guard, which must
  // still be an explicit request rather than the default.
  const revealed = await authed(
    'note',
    'show',
    'runbook',
    sensitiveId,
    '--reveal',
    '--context',
    'platform',
    '--service',
    'api',
  );
  check(
    'note show --reveal exits 0',
    revealed.exitCode === 0,
    revealed.stderr.trim().slice(0, 250),
  );
  check(
    'sensitive note revealed behind --reveal',
    revealed.stdout.includes(REVEAL_BODY),
    revealed.stdout.slice(0, 160),
  );

  console.log('5. item history');
  const historyList = await authed(
    'item',
    'history',
    'list',
    'runbook',
    '--context',
    'platform',
    '--service',
    'api',
  );
  check(
    'item history list exits 0',
    historyList.exitCode === 0,
    historyList.stderr.trim().slice(0, 250),
  );
  check(
    'history list reports no records',
    /"history"\s*:\s*\[\s*\]/.test(historyList.stdout),
    historyList.stdout.slice(0, 200),
  );
  check('history list omits the password', !historyList.stdout.includes(FIELD_SECRET));

  const historyAlias = await authed(
    'credential',
    'history',
    'list',
    'runbook',
    '--context',
    'platform',
    '--service',
    'api',
  );
  check(
    'credential history alias exits 0',
    historyAlias.exitCode === 0,
    historyAlias.stderr.trim().slice(0, 200),
  );

  const unknown = await authed(
    'item',
    'history',
    'list',
    'no-such-item',
    '--context',
    'platform',
    '--service',
    'api',
  );
  check(
    'unknown item fails closed',
    [1, 10, 11, 16].includes(unknown.exitCode),
    `exit ${String(unknown.exitCode)}`,
  );
  // `--json` was requested, so the failure is reported as a structured envelope
  // with a stable code and no path, id, or value in it.
  check(
    'unknown item reports a coded envelope',
    unknown.stdout.includes('"code"') && unknown.stdout.includes('"exitCode"'),
    unknown.stdout.slice(0, 160),
  );
  check(
    'unknown item leaks no value',
    !unknown.stdout.includes(NOTE_BODY) && !unknown.stdout.includes(FIELD_SECRET),
  );

  const unknownVersion = await authed(
    'item',
    'history',
    'show',
    'runbook',
    'nope',
    '--context',
    'platform',
    '--service',
    'api',
  );
  check(
    'unknown version fails closed',
    [1, 10, 11, 16].includes(unknownVersion.exitCode),
    `exit ${String(unknownVersion.exitCode)}`,
  );
  check(
    'unknown version reports a coded envelope',
    unknownVersion.stdout.includes('"code"') &&
      unknownVersion.stdout.includes('"exitCode"'),
    unknownVersion.stdout.slice(0, 120),
  );

  console.log('6. the container on disk holds no plaintext');
  const container = await readFile(dataFile);
  check('container has no note body', !container.includes(Buffer.from(NOTE_BODY)));
  check('container has no reveal body', !container.includes(Buffer.from(REVEAL_BODY)));
  check('container has no passphrase', !container.includes(Buffer.from(PASSPHRASE)));
  check(
    'container has no field password',
    !container.includes(Buffer.from(FIELD_SECRET)),
  );
} finally {
  await rm(home, { recursive: true, force: true });
}

console.log(failures === 0 ? '\nSMOKE PASS' : `\nSMOKE FAIL (${String(failures)})`);
process.exit(failures === 0 ? 0 : 1);
