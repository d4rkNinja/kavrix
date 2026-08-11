import { spawnSync } from 'node:child_process';
import { Buffer } from 'node:buffer';
import { createHash, randomFillSync } from 'node:crypto';
import { existsSync } from 'node:fs';
import {
  mkdtemp,
  mkdir,
  chmod,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { vaultProfileSchema } from '@kavrix/client';
import { SealedSecretStore, sealedEntryFactory } from '@kavrix/key-files';
import { NativeProtectedSyncState } from '@kavrix/keychain';
import {
  acquireLocalWriterLease,
  openSqliteSyncLocalStore,
  openSqliteVaultProfileStore,
} from '@kavrix/local-store';
import { protectedLocalDeviceStateSchema } from '@kavrix/schemas';

const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const manifest = JSON.parse(
  await readFile(resolve(packageDirectory, 'package.json'), 'utf8'),
);
const temporaryPrefix = join(tmpdir(), 'kavrix-packed-smoke-');
const temporaryRoot = await mkdtemp(temporaryPrefix);
const effWordListReference = 'urn:kavrix:data:eff-short-wordlist-for-passphrases-1';
const effWordListSourceDigest =
  '8f5ca830b8bffb6fe39c9736c024a00a6a6411adb3f83a9be8bfeeb6e067ae69';
if (!temporaryRoot.startsWith(temporaryPrefix)) {
  throw new Error('The operating system returned an unexpected smoke-test directory.');
}
const archiveDirectory = resolve(temporaryRoot, 'archive');
const installDirectory = resolve(temporaryRoot, 'install');
const suppliedArchive = process.argv[2];
let ownedStatusPassphrase;

try {
  await Promise.all([
    mkdir(archiveDirectory, { recursive: true }),
    mkdir(installDirectory, { recursive: true }),
  ]);
  await writeFile(
    resolve(installDirectory, 'package.json'),
    '{"name":"kavrix-package-smoke","private":true}\n',
    'utf8',
  );

  const archive =
    suppliedArchive === undefined
      ? await packArchive()
      : await requireSuppliedArchive(suppliedArchive);
  runNodeCli(
    resolveNpmCli(),
    [
      'install',
      '--ignore-scripts',
      '--offline',
      '--no-audit',
      '--no-fund',
      '--package-lock=false',
      archive,
    ],
    { cwd: installDirectory },
  );

  const installedManifestPath = resolve(
    installDirectory,
    'node_modules/kavrix/package.json',
  );
  const installedPackageDirectory = resolve(installDirectory, 'node_modules/kavrix');
  await assertInstalledFileAllowlist(installedPackageDirectory);
  const installedManifest = JSON.parse(await readFile(installedManifestPath, 'utf8'));
  const installedReadme = await readFile(
    resolve(installedPackageDirectory, 'README.md'),
    'utf8',
  );
  for (const marker of [
    'EFF Short Wordlist for Passphrases #1',
    'https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt',
    'https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases',
    'https://www.eff.org/copyright',
    'https://creativecommons.org/licenses/by/4.0/',
    'dice-code column',
  ]) {
    if (!installedReadme.includes(marker)) {
      throw new Error('The packed README omits the embedded word-list attribution.');
    }
  }
  for (const key of [
    'dependencies',
    'optionalDependencies',
    'peerDependencies',
    'bundledDependencies',
    'bundleDependencies',
  ]) {
    if (key in installedManifest) {
      throw new Error(`Packed package unexpectedly declares ${key}.`);
    }
  }
  if (existsSync(resolve(installDirectory, 'node_modules/@kavrix'))) {
    throw new Error('Packed installation resolved an unpublished @kavrix package.');
  }

  const executable = resolve(installDirectory, 'node_modules/kavrix/dist/bin.js');
  const sbomText = await readFile(
    resolve(installedPackageDirectory, 'dist/kavrix.cdx.json'),
    'utf8',
  );
  const sbom = JSON.parse(sbomText);
  const javascriptArtifacts = await collectJavaScriptArtifacts(
    installedPackageDirectory,
  );
  const expectedProperties = javascriptArtifacts.map(({ path, hash }) => ({
    name: `kavrix:artifact-sha256:${path}`,
    value: hash,
  }));
  const wordListComponents = sbom.components?.filter(
    (component) => component.type === 'data',
  );
  const wordListComponent = wordListComponents?.[0];
  const rootDependency = sbom.dependencies?.find(
    (dependency) => dependency.ref === sbom.metadata?.component?.['bom-ref'],
  );
  const wordListDependency = sbom.dependencies?.find(
    (dependency) => dependency.ref === effWordListReference,
  );
  if (
    sbom.bomFormat !== 'CycloneDX' ||
    sbom.specVersion !== '1.6' ||
    sbom.metadata?.component?.hashes?.[0]?.content !==
      aggregateArtifactHash(javascriptArtifacts) ||
    JSON.stringify(sbom.metadata?.component?.properties) !==
      JSON.stringify(expectedProperties) ||
    wordListComponents?.length !== 1 ||
    wordListComponent?.['bom-ref'] !== effWordListReference ||
    wordListComponent?.name !== 'EFF Short Wordlist for Passphrases #1' ||
    wordListComponent?.licenses?.[0]?.license?.id !== 'CC-BY-4.0' ||
    wordListComponent?.externalReferences?.[0]?.type !== 'distribution' ||
    wordListComponent?.externalReferences?.[0]?.url !==
      'https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt' ||
    wordListComponent?.properties?.[0]?.name !== 'kavrix:source-sha256' ||
    wordListComponent?.properties?.[0]?.value !== effWordListSourceDigest ||
    'purl' in (wordListComponent ?? {}) ||
    !rootDependency?.dependsOn?.includes(effWordListReference) ||
    wordListDependency?.dependsOn?.length !== 0 ||
    /(?:@kavrix\/|workspace:|file:\/\/|secret-password-canary)/u.test(sbomText)
  ) {
    throw new Error('The packed SBOM does not cover every JavaScript artifact.');
  }

  // Every chunk that reaches the AEAD primitive must stay off the metadata-only
  // path. Code splitting decides how many such chunks exist, so this asserts the
  // property that matters — none of them is evaluated — rather than a chunk count
  // that changes whenever a new caller of the primitive is added.
  const cryptoChunkNames = javascriptArtifacts
    .filter(({ bytes }) =>
      bytes.includes('crypto_aead_xchacha20poly1305_ietf_encrypt_detached'),
    )
    .map(({ path }) => path.split('/').at(-1));
  if (cryptoChunkNames.length === 0) {
    throw new Error('The packed portable-key crypto chunk could not be identified.');
  }
  const productionChunkNames = javascriptArtifacts
    .filter(({ bytes }) => bytes.includes('cli.writer.lock'))
    .map(({ path }) => path.split('/').at(-1));
  if (productionChunkNames.length === 0) {
    throw new Error('The packed production-status chunk could not be identified.');
  }
  const debugEnvironment = { ...process.env, NODE_DEBUG: 'esm' };
  for (const [arguments_, expectedStatus] of [
    [['--version'], 0],
    [['completion', 'bash'], 0],
    [['--help'], 0],
    [['status', '--help'], 0],
    [['unknown-command'], 2],
  ]) {
    const lazyResult = run(process.execPath, [executable, ...arguments_], {
      env: debugEnvironment,
    });
    if (
      lazyResult.status !== expectedStatus ||
      cryptoChunkNames.some((name) => lazyResult.stderr.includes(name)) ||
      productionChunkNames.some((name) => lazyResult.stderr.includes(name))
    ) {
      throw new Error(
        'A static, help, or invalid command evaluated a lazy production chunk.',
      );
    }
  }
  expectCommand(executable, ['--version'], `${manifest.version}\n`);
  expectIncludes(executable, ['--help'], 'completion <shell>');
  expectIncludes(executable, ['--help'], 'generate');
  expectIncludes(executable, ['--help'], 'totp');
  expectIncludes(
    executable,
    ['completion', 'bash'],
    'complete -F _creds_complete creds',
  );
  expectSecretPattern(
    executable,
    ['generate', 'password', '--stdout'],
    /^[!-~]{24}\n$/u,
  );
  expectSecretPattern(
    executable,
    ['generate', 'passphrase', '--stdout'],
    /^[a-z-]{23,}\n$/u,
  );
  const totp = run(
    process.execPath,
    [
      executable,
      'totp',
      '--secret-stdin',
      '--algorithm',
      'sha1',
      '--digits',
      '8',
      '--time',
      '59',
      '--stdout',
    ],
    { input: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' },
  );
  if (totp.status !== 0 || totp.stdout !== '94287082\n' || totp.stderr !== '') {
    throw new Error('Packed CLI TOTP generation failed.');
  }
  const keyDirectory = resolve(temporaryRoot, 'key-files');
  await mkdir(keyDirectory);
  await prepareSecureKeyDirectory(keyDirectory);
  const keyPath = resolve(keyDirectory, 'portable-key.cvk');
  const keyCreation = run(
    process.execPath,
    [executable, 'key', 'create', '--file', keyPath],
    { env: debugEnvironment },
  );
  const keyFile = await readFile(keyPath, 'ascii');
  if (
    keyCreation.status !== 0 ||
    keyCreation.stdout !== 'Portable key file created.\n' ||
    // The counterpart to the laziness check above: a command that really needs
    // the AEAD primitive must pull at least one of those chunks in on demand.
    !cryptoChunkNames.some((name) => keyCreation.stderr.includes(name)) ||
    !keyFile.includes('Version: 1') ||
    !keyFile.includes('Binding: unbound') ||
    keyCreation.stdout.includes('Key:')
  ) {
    throw new Error('Packed CLI portable key-file creation failed.');
  }
  for (const hidden of ['init', 'lock', 'show', 'copy', 'device']) {
    const unsupported = run(process.execPath, [executable, hidden]);
    if (
      unsupported.status !== 2 ||
      unsupported.stdout !== '' ||
      unsupported.stderr !==
        "Error [CLI_USAGE]: Invalid command usage. Run 'creds --help'.\n"
    ) {
      throw new Error('The packed executable exposed an unsupported vault family.');
    }
  }

  // Everything above runs the bundle through `node dist/bin.js`. The launcher
  // npm links into node_modules/.bin is what a real install actually puts on
  // PATH, and it is the one published artifact whose shape differs per
  // operating system: a symlink to the shebang script on POSIX, a generated
  // batch launcher on Windows. Exercising it is how this smoke test can claim
  // `creds` works on the platform it just ran on.
  const shim = await resolveInstalledCommandShim(installDirectory);
  const launched = runCommandShim(shim, ['--version']);
  if (
    launched.status !== 0 ||
    launched.stdout !== `${manifest.version}\n` ||
    launched.stderr !== ''
  ) {
    throw new Error('The installed creds launcher did not run on this platform.');
  }

  const statusHome = resolve(temporaryRoot, 'status-home');
  await mkdir(statusHome);
  await prepareSecureKeyDirectory(statusHome);
  ownedStatusPassphrase = generatedAsciiPassphrase(48);
  const statusFixture = await createPackedStatusFixture(
    statusHome,
    ownedStatusPassphrase,
  );
  // Node 24 still labels its built-in SQLite module experimental. Suppress only
  // that warning class in the child so stderr assertions remain about the CLI;
  // the status implementation and installed launcher are otherwise unchanged.
  const statusEnvironment = {
    ...process.env,
    CREDS_HOME: statusHome,
    NODE_OPTIONS: '--disable-warning=ExperimentalWarning',
  };
  const statusArguments = [
    'status',
    '--json',
    '--secret-backend',
    'sealed-file',
    '--backend-passphrase-stdin',
  ];
  if (
    stringsContainBytes(Object.values(statusEnvironment), ownedStatusPassphrase) ||
    stringsContainBytes(statusArguments, ownedStatusPassphrase)
  ) {
    throw new Error('The packed status passphrase reached argv or environment.');
  }
  const jsonInput = Buffer.from(ownedStatusPassphrase);
  const jsonStatus = runCommandShim(shim, statusArguments, {
    env: statusEnvironment,
    input: jsonInput,
  });
  jsonInput.fill(0);
  const expectedJson = `${JSON.stringify(statusFixture.expected, undefined, 2)}\n`;
  if (
    jsonStatus.status !== 0 ||
    jsonStatus.stdout !== expectedJson ||
    jsonStatus.stderr !== '' ||
    containsTerminalControl(jsonStatus.stdout)
  ) {
    throw new Error('The installed creds launcher did not return canonical status.');
  }
  await assertNoWriterLocks(statusHome);

  const textInput = Buffer.from(ownedStatusPassphrase);
  const textStatus = runCommandShim(
    shim,
    ['status', '--secret-backend', 'sealed-file', '--backend-passphrase-stdin'],
    { env: statusEnvironment, input: textInput },
  );
  textInput.fill(0);
  if (
    textStatus.status !== 0 ||
    textStatus.stdout !== statusFixture.expectedText ||
    textStatus.stderr !== ''
  ) {
    throw new Error('The installed creds launcher did not return text status.');
  }
  await assertNoWriterLocks(statusHome);

  const wrongInput = Buffer.from(ownedStatusPassphrase);
  wrongInput[0] = wrongInput[0] === 0x41 ? 0x42 : 0x41;
  const wrongStatus = runCommandShim(shim, statusArguments, {
    env: statusEnvironment,
    input: wrongInput,
  });
  wrongInput.fill(0);
  if (
    wrongStatus.status !== 1 ||
    wrongStatus.stdout !== '' ||
    wrongStatus.stderr !==
      'Error [UNEXPECTED_FAILURE]: The command failed without exposing internal details.\n'
  ) {
    throw new Error('The installed status command did not fail closed.');
  }
  await assertNoWriterLocks(statusHome);

  const heldLease = await acquireLocalWriterLease(
    resolve(statusHome, 'cli.writer.lock'),
  );
  try {
    const blockedInput = Buffer.from(ownedStatusPassphrase);
    const blockedStatus = runCommandShim(shim, statusArguments, {
      env: statusEnvironment,
      input: blockedInput,
    });
    blockedInput.fill(0);
    if (
      blockedStatus.status !== 1 ||
      blockedStatus.stdout !== '' ||
      blockedStatus.stderr !==
        'Error [UNEXPECTED_FAILURE]: The command failed without exposing internal details.\n' ||
      !existsSync(resolve(statusHome, 'cli.writer.lock')) ||
      stringsContainBytes(
        [blockedStatus.stdout, blockedStatus.stderr],
        ownedStatusPassphrase,
      )
    ) {
      throw new Error('The installed status command bypassed the global writer lease.');
    }
  } finally {
    await heldLease.release();
  }
  await assertNoWriterLocks(statusHome);

  const recoveredInput = Buffer.from(ownedStatusPassphrase);
  const recoveredStatus = runCommandShim(shim, statusArguments, {
    env: statusEnvironment,
    input: recoveredInput,
  });
  recoveredInput.fill(0);
  if (
    recoveredStatus.status !== 0 ||
    recoveredStatus.stdout !== expectedJson ||
    recoveredStatus.stderr !== ''
  ) {
    throw new Error('Status did not recover after the live lease was released.');
  }
  await assertNoWriterLocks(statusHome);

  const debugInput = Buffer.from(ownedStatusPassphrase);
  const debugStatus = run(process.execPath, [executable, ...statusArguments], {
    env: { ...statusEnvironment, NODE_DEBUG: 'esm' },
    input: debugInput,
    maxBuffer: 8 * 1_024 * 1_024,
  });
  debugInput.fill(0);
  if (
    debugStatus.status !== 0 ||
    debugStatus.stdout !== expectedJson ||
    !productionChunkNames.some((name) => debugStatus.stderr.includes(name))
  ) {
    throw new Error('A real status invocation did not evaluate production code.');
  }
  await assertNoWriterLocks(statusHome);

  for (const output of [
    jsonStatus,
    textStatus,
    wrongStatus,
    recoveredStatus,
    debugStatus,
  ]) {
    if (stringsContainBytes([output.stdout, output.stderr], ownedStatusPassphrase)) {
      throw new Error('The packed status passphrase reached command output.');
    }
  }
  if (await treeContains(statusHome, ownedStatusPassphrase)) {
    throw new Error('The packed status passphrase reached durable local state.');
  }
  if (
    existsSync(resolve(statusHome, 'init-journal.db')) ||
    existsSync(resolve(statusHome, 'join-journal.db'))
  ) {
    throw new Error('Status opened an unrelated lifecycle journal.');
  }

  process.stdout.write(
    `Verified dependency-free packed CLI ${archive.split(/[\\/]/u).at(-1)} on ${process.platform}.\n`,
  );
} finally {
  ownedStatusPassphrase?.fill(0);
  await rm(temporaryRoot, { recursive: true, force: true });
}

async function assertInstalledFileAllowlist(installedPackageDirectory) {
  const rootEntries = await readDirectoryShape(installedPackageDirectory);
  const distEntries = await readDirectoryShape(
    resolve(installedPackageDirectory, 'dist'),
  );
  const chunkEntries = await readDirectoryShape(
    resolve(installedPackageDirectory, 'dist/chunks'),
  );
  const chunksAreExact =
    chunkEntries.directories.length === 0 &&
    chunkEntries.files.length > 0 &&
    chunkEntries.files.every((name) => /^chunk-[A-Z0-9]+\.js$/u.test(name));
  if (
    JSON.stringify(rootEntries) !==
      JSON.stringify({
        directories: ['dist'],
        files: ['LICENSE', 'package.json', 'README.md'],
      }) ||
    JSON.stringify(distEntries) !==
      JSON.stringify({
        directories: ['chunks'],
        files: ['bin.js', 'index.d.ts', 'index.js', 'kavrix.cdx.json'],
      }) ||
    !chunksAreExact
  ) {
    throw new Error('The installed package contains a file outside the allowlist.');
  }
}

async function readDirectoryShape(directory) {
  const directories = [];
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) directories.push(entry.name);
    else if (entry.isFile()) files.push(entry.name);
    else throw new Error('The installed package contains a non-regular entry.');
  }
  return {
    directories: directories.sort((left, right) => left.localeCompare(right, 'en')),
    files: files.sort((left, right) => left.localeCompare(right, 'en')),
  };
}

async function collectJavaScriptArtifacts(installedPackageDirectory) {
  const paths = [];
  const visit = async (directory) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile() && entry.name.endsWith('.js')) paths.push(path);
    }
  };
  await visit(resolve(installedPackageDirectory, 'dist'));
  return Promise.all(
    paths
      .sort((left, right) => left.localeCompare(right, 'en'))
      .map(async (path) => {
        const bytes = await readFile(path);
        return {
          path: relative(installedPackageDirectory, path).replaceAll('\\', '/'),
          bytes,
          hash: createHash('sha256').update(bytes).digest('hex'),
        };
      }),
  );
}

function aggregateArtifactHash(artifacts) {
  const hash = createHash('sha256');
  for (const artifact of artifacts) {
    hash.update(artifact.path).update('\0').update(artifact.bytes).update('\0');
  }
  return hash.digest('hex');
}

async function packArchive() {
  runNodeCli(
    resolveNpmCli(),
    ['pack', '--ignore-scripts', '--pack-destination', archiveDirectory],
    { cwd: packageDirectory },
  );
  const archives = (await readdir(archiveDirectory)).filter((name) =>
    name.endsWith('.tgz'),
  );
  if (archives.length !== 1) {
    throw new Error(`Expected one packed archive, received ${archives.length}.`);
  }
  return resolve(archiveDirectory, archives[0]);
}

async function requireSuppliedArchive(value) {
  const archive = resolve(packageDirectory, value);
  const archiveStats = await stat(archive);
  if (!archiveStats.isFile() || !archive.endsWith('.tgz')) {
    throw new Error('The supplied package archive must be one .tgz file.');
  }
  return archive;
}

function expectCommand(executable, arguments_, expected) {
  const result = run(process.execPath, [executable, ...arguments_]);
  if (result.status !== 0 || result.stdout !== expected || result.stderr !== '') {
    throw new Error(
      `Packed CLI returned unexpected output for ${arguments_.join(' ')}.`,
    );
  }
}

function expectIncludes(executable, arguments_, expected) {
  const result = run(process.execPath, [executable, ...arguments_]);
  if (
    result.status !== 0 ||
    !result.stdout.includes(expected) ||
    result.stderr !== ''
  ) {
    throw new Error(
      `Packed CLI did not produce expected output for ${arguments_.join(' ')}.`,
    );
  }
}

function expectSecretPattern(executable, arguments_, expected) {
  const result = run(process.execPath, [executable, ...arguments_]);
  if (result.status !== 0 || !expected.test(result.stdout) || result.stderr !== '') {
    throw new Error('Packed CLI local secret generation failed.');
  }
}

async function prepareSecureKeyDirectory(path) {
  if (process.platform !== 'win32') {
    await chmod(path, 0o700);
    return;
  }
  const script = String.raw`
$ErrorActionPreference = 'Stop'
$target = [Environment]::GetEnvironmentVariable('KAVRIX_SMOKE_ACL_TARGET', 'Process')
if ([String]::IsNullOrWhiteSpace($target)) { exit 11 }
$item = [IO.DirectoryInfo]::new($target)
$item.Refresh()
if (-not $item.Exists) { exit 12 }
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 12 }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User
$security = [Security.AccessControl.DirectorySecurity]::new()
$security.SetOwner($sid)
$security.SetAccessRuleProtection($true, $false)
$fullControl = [Security.AccessControl.FileSystemRights]::FullControl
$allow = [Security.AccessControl.AccessControlType]::Allow
$inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
$propagation = [Security.AccessControl.PropagationFlags]::None
$rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, $fullControl, $inheritance, $propagation, $allow)
[void]$security.AddAccessRule($rule)
$item.SetAccessControl($security)
$item.Refresh()
$sections = [Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner
$acl = $item.GetAccessControl($sections)
if (-not $acl.AreAccessRulesProtected) { exit 13 }
if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { exit 14 }
$rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
if ($rules.Count -ne 1) { exit 15 }
$actual = $rules[0]
if ($actual.IsInherited) { exit 16 }
if ($actual.AccessControlType -ne $allow) { exit 17 }
if ($actual.IdentityReference.Value -ne $sid.Value) { exit 18 }
if (($actual.FileSystemRights -band $fullControl) -ne $fullControl) { exit 19 }
[Console]::Out.Write('OK')
`;
  const powershell = String.raw`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`;
  const prepared = run(
    powershell,
    [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy',
      'Bypass',
      '-EncodedCommand',
      Buffer.from(script, 'utf16le').toString('base64'),
    ],
    {
      env: {
        KAVRIX_SMOKE_ACL_TARGET: path,
        SystemRoot: String.raw`C:\Windows`,
        WINDIR: String.raw`C:\Windows`,
      },
      maxBuffer: 4_096,
      timeout: 15_000,
    },
  );
  if (prepared.status !== 0 || prepared.stdout !== 'OK' || prepared.stderr !== '') {
    throw new Error('Could not prepare the packed key-file smoke directory.');
  }
}

function generatedAsciiPassphrase(length) {
  const alphabet = Buffer.from(
    'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789',
    'ascii',
  );
  const passphrase = Buffer.alloc(length);
  randomFillSync(passphrase);
  for (let index = 0; index < passphrase.length; index += 1) {
    passphrase[index] = alphabet[passphrase[index] % alphabet.length];
  }
  return passphrase;
}

async function createPackedStatusFixture(home, passphrase) {
  const vaultId = 'vault.packed.status';
  const deviceId = 'device.packed.status';
  const updatedAt = '2026-08-10T01:02:03.000Z';
  const profile = vaultProfileSchema.parse({
    version: 1,
    serverUrl: 'https://network-must-not-run.invalid/',
    vaultId,
    deviceId,
    deviceLocator: {
      version: 1,
      vaultId,
      deviceId,
      keySlotId: 'slot.packed.status',
    },
    sessionLocator: { version: 1, vaultId, deviceId, purpose: 'api-session' },
  });
  const profiles = await openSqliteVaultProfileStore({
    path: resolve(home, 'profiles.db'),
  });
  try {
    await profiles.store(profile);
  } finally {
    await profiles.close();
  }
  const sync = await openSqliteSyncLocalStore({
    path: resolve(home, `vault-${vaultId}.db`),
  });
  sync.close();

  const sealed = new SealedSecretStore({
    directory: resolve(home, 'sealed'),
    passphrase: () => Promise.resolve(Buffer.from(passphrase)),
  });
  try {
    const protectedState = new NativeProtectedSyncState(sealedEntryFactory(sealed));
    await protectedState.save(
      protectedLocalDeviceStateSchema.parse({
        vaultId,
        deviceId,
        highestSeenVaultRevision: 9,
        updatedAt,
      }),
    );
  } finally {
    await sealed.close();
  }

  return {
    expected: {
      vaultState: 'locked',
      vaultId,
      deviceId,
      syncState: 'offline',
      pendingChanges: 0,
      lastSyncAt: updatedAt,
    },
    expectedText: `Vault: locked\nVault ID: ${vaultId}\nDevice ID: ${deviceId}\nSync: offline\nPending changes: 0\nLast sync: ${updatedAt}\n`,
  };
}

async function allRegularFiles(root) {
  const files = [];
  const visit = async (directory) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) files.push(path);
      else throw new Error('The status home contains a non-regular entry.');
    }
  };
  await visit(root);
  return files.sort((left, right) => left.localeCompare(right, 'en'));
}

async function assertNoWriterLocks(home) {
  if ((await allRegularFiles(home)).some((path) => path.endsWith('.writer.lock'))) {
    throw new Error('A completed status invocation left a writer lease behind.');
  }
}

async function treeContains(home, needle) {
  for (const path of await allRegularFiles(home)) {
    if ((await readFile(path)).includes(needle)) return true;
  }
  return false;
}

function containsTerminalControl(value) {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint !== undefined &&
      ((codePoint <= 0x1f && codePoint !== 0x0a) ||
        (codePoint >= 0x7f && codePoint <= 0x9f))
    ) {
      return true;
    }
  }
  return false;
}

function stringsContainBytes(values, needle) {
  for (const value of values) {
    if (typeof value !== 'string') continue;
    const bytes = Buffer.from(value, 'utf8');
    try {
      if (bytes.includes(needle)) return true;
    } finally {
      bytes.fill(0);
    }
  }
  return false;
}

function runNodeCli(cliPath, arguments_, options) {
  const result = run(process.execPath, [cliPath, ...arguments_], options);
  if (result.status !== 0) {
    throw new Error(`Command failed: ${result.stderr || result.stdout}`);
  }
  return result;
}

function run(command, arguments_, options = {}) {
  const result = spawnSync(command, arguments_, {
    ...options,
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  });
  if (result.error !== undefined) throw result.error;
  return {
    status: result.status,
    stdout: result.stdout.replaceAll('\r\n', '\n'),
    stderr: result.stderr.replaceAll('\r\n', '\n'),
  };
}

function resolveNpmCli() {
  const executableDirectory = dirname(process.execPath);
  const candidates = [
    resolve(executableDirectory, 'node_modules/npm/bin/npm-cli.js'),
    resolve(executableDirectory, '../lib/node_modules/npm/bin/npm-cli.js'),
  ];
  const candidate = candidates.find(existsSync);
  if (candidate === undefined)
    throw new Error('Could not locate npm-cli.js for package smoke.');
  return candidate;
}

async function resolveInstalledCommandShim(installDirectory) {
  if (process.platform !== 'win32') {
    return resolve(installDirectory, 'node_modules/.bin/creds');
  }
  // npm writes the batch launcher as `creds.cmd`; pnpm's .bin stores
  // `creds.CMD`. Match case-insensitively so either toolchain passes.
  const binDirectory = resolve(installDirectory, 'node_modules/.bin');
  const entries = await readdir(binDirectory);
  const shim = entries.find(
    (name) => name.toLowerCase() === 'creds.cmd' || name.toLowerCase() === 'creds.bat',
  );
  if (shim === undefined) {
    throw new Error('npm did not create a creds batch launcher for this install.');
  }
  return resolve(binDirectory, shim);
}

function runCommandShim(shim, arguments_, options = {}) {
  if (process.platform !== 'win32') return run(shim, arguments_, options);
  // A .cmd launcher can only be executed by cmd.exe: Node refuses to spawn one
  // without a shell since the CVE-2024-27980 hardening, returning EINVAL. The
  // interpreter is therefore named explicitly, by absolute path rather than via
  // ComSpec or PATH, and the launcher is passed as one element of the argument
  // array — so shell stays false and no command string is ever assembled.
  const cmd = String.raw`C:\Windows\System32\cmd.exe`;
  return run(cmd, ['/d', '/s', '/c', shim, ...arguments_], options);
}
