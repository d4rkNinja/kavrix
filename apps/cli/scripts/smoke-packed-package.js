import { spawnSync } from 'node:child_process';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
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
  const debugEnvironment = { ...process.env, NODE_DEBUG: 'esm' };
  for (const arguments_ of [['--version'], ['completion', 'bash']]) {
    const lazyResult = run(process.execPath, [executable, ...arguments_], {
      env: debugEnvironment,
    });
    if (
      lazyResult.status !== 0 ||
      cryptoChunkNames.some((name) => lazyResult.stderr.includes(name))
    ) {
      throw new Error(
        'A metadata-only command evaluated the portable-key crypto chunk.',
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
  const unsupported = run(process.execPath, [executable, 'status']);
  if (
    unsupported.status !== 2 ||
    unsupported.stdout !== '' ||
    unsupported.stderr !==
      "Error [CLI_USAGE]: Invalid command usage. Run 'creds --help'.\n"
  ) {
    throw new Error('The packed executable exposed unsupported production behavior.');
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

  process.stdout.write(
    `Verified dependency-free packed CLI ${archive.split(/[\\/]/u).at(-1)} on ${process.platform}.\n`,
  );
} finally {
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

function runCommandShim(shim, arguments_) {
  if (process.platform !== 'win32') return run(shim, arguments_);
  // A .cmd launcher can only be executed by cmd.exe: Node refuses to spawn one
  // without a shell since the CVE-2024-27980 hardening, returning EINVAL. The
  // interpreter is therefore named explicitly, by absolute path rather than via
  // ComSpec or PATH, and the launcher is passed as one element of the argument
  // array — so shell stays false and no command string is ever assembled.
  const cmd = String.raw`C:\Windows\System32\cmd.exe`;
  return run(cmd, ['/d', '/s', '/c', shim, ...arguments_]);
}
