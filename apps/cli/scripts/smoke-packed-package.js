/* global URL, process */

import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const cliRoot = fileURLToPath(new URL('..', import.meta.url));
const npmCommand = process.platform === 'win32' ? process.execPath : 'npm';
const npmArgsPrefix =
  process.platform === 'win32'
    ? [join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')]
    : [];

function fail(message) {
  throw new Error(message);
}

function assert(condition, message) {
  if (!condition) fail(message);
}

function run(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    timeout: 180_000,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error)
    fail(`${command} ${args.join(' ')} failed: ${result.error.message}`);
  if (result.status !== 0) {
    const detail = [result.stdout, result.stderr].filter(Boolean).join('\n').trim();
    fail(
      `${command} ${args.join(' ')} exited with ${result.status}${detail ? `\n${detail}` : ''}`,
    );
  }
  return { stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

async function walkFiles(root, current = root) {
  const entries = await readdir(current, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(current, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walkFiles(root, path)));
    } else if (entry.isFile()) {
      files.push(relative(root, path).replaceAll('\\', '/'));
    }
  }
  return files;
}

const forbiddenContent = [
  'secret-password-canary',
  'secret-note-canary',
  'runtime-vault-secret-canary',
  'KAVRIX-BACKUP-PLAINTEXT-CANARY',
  'plaintext-storage-canary',
  'unique-plaintext-canary-7ac19783',
  'canary-plaintext-value',
];

function assertSafeText(text, label) {
  for (const marker of forbiddenContent) {
    assert(!text.includes(marker), `${label} contains a forbidden plaintext canary`);
  }
  for (const path of [
    cliRoot,
    dirname(cliRoot),
    process.env['HOME'],
    process.env['USERPROFILE'],
  ]) {
    if (typeof path !== 'string' || path.length === 0) continue;
    const normalizedText = text.replaceAll('\\', '/');
    const normalizedPath = resolve(path).replaceAll('\\', '/');
    assert(
      !normalizedText.includes(normalizedPath),
      `${label} contains a private path`,
    );
  }
}

async function resolveArchive(argument, packDirectory) {
  if (argument) {
    const archive = resolve(cliRoot, argument);
    assert(existsSync(archive), `Package archive does not exist: ${archive}`);
    return archive;
  }
  assert(packDirectory !== undefined, 'Package temporary directory is missing');
  run(
    npmCommand,
    [...npmArgsPrefix, 'pack', '--pack-destination', packDirectory, '--ignore-scripts'],
    cliRoot,
  );
  const files = (await readdir(packDirectory)).filter((file) => file.endsWith('.tgz'));
  assert(files.length === 1, `Expected one packed archive, found ${files.length}`);
  return join(packDirectory, files[0]);
}

async function main() {
  const npmCache = await mkdtemp(join(tmpdir(), 'kavrix-npm-cache-'));
  const previousNpmCache = process.env['npm_config_cache'];
  process.env['npm_config_cache'] = npmCache;
  let installRoot;
  let packDirectory;
  let operationError;
  let verifiedVersion;
  try {
    if (process.argv[2] === undefined) {
      packDirectory = await mkdtemp(join(tmpdir(), 'kavrix-pack-'));
    }
    const archive = await resolveArchive(process.argv[2], packDirectory);
    installRoot = await mkdtemp(join(tmpdir(), 'kavrix-smoke-'));
    run(
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
        archive,
      ],
      installRoot,
    );

    const packageRoot = join(installRoot, 'node_modules', 'kavrix');
    if (!existsSync(packageRoot)) {
      const installedEntries = await readdir(join(installRoot, 'node_modules')).catch(
        () => [],
      );
      fail(
        `The packed kavrix package was not installed; found: ${installedEntries.join(', ')}`,
      );
    }

    const manifest = await readJson(join(packageRoot, 'package.json'));
    assert(manifest.name === 'kavrix', 'Packed package name must be kavrix');
    assert(manifest.private === false, 'Packed package must be publishable');
    assert(
      typeof manifest.version === 'string' && manifest.version.length > 0,
      'Packed package version is missing',
    );
    assert(manifest.bin?.kavrix === './dist/bin.js', 'Packed bin mapping is invalid');
    assert(
      manifest.dependencies?.mongodb === '7.5.0',
      'Packed runtime must pin mongodb 7.5.0',
    );
    assert(
      !manifest.devDependencies || Object.keys(manifest.devDependencies).length === 0,
      'Dev dependencies leaked into the packed manifest',
    );
    assert(
      !JSON.stringify(manifest).includes('workspace:'),
      'Workspace dependency leaked into the packed manifest',
    );
    assert(
      !JSON.stringify(manifest).includes('@kavrix/'),
      'Workspace package dependency leaked into the packed manifest',
    );

    const files = await walkFiles(packageRoot);
    const unexpected = files.filter(
      (file) =>
        !(
          file === 'package.json' ||
          file === 'README.md' ||
          file === 'LICENSE' ||
          /^dist\/(?:.+\.js|.+\.d\.ts|[^/]+\.cdx\.json)$/.test(file)
        ),
    );
    assert(
      unexpected.length === 0,
      `Unexpected files in package: ${unexpected.join(', ')}`,
    );
    assert(files.includes('README.md'), 'README.md is missing from the package');
    assert(files.includes('LICENSE'), 'LICENSE is missing from the package');
    assert(files.includes('dist/bin.js'), 'dist/bin.js is missing from the package');
    assert(
      files.includes('dist/index.js'),
      'dist/index.js is missing from the package',
    );
    assert(
      files.includes('dist/index.d.ts'),
      'dist/index.d.ts is missing from the package',
    );
    for (const file of files) {
      assertSafeText(await readFile(join(packageRoot, file), 'utf8'), file);
    }

    const readme = await readFile(join(packageRoot, 'README.md'), 'utf8');
    assert(
      readme.includes('zero-knowledge'),
      'README must describe the zero-knowledge boundary',
    );
    assert(
      readme.includes('https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt'),
      'README must include the exact EFF attribution URL',
    );
    assert(
      readme.includes('https://creativecommons.org/licenses/by/4.0/'),
      'README must include the exact CC BY 4.0 attribution URL',
    );

    const sbom = await readJson(join(packageRoot, 'dist', 'kavrix.cdx.json'));
    const components = Array.isArray(sbom.components) ? sbom.components : [];
    const componentVersions = new Map(
      components.map((component) => [component.name, component.version]),
    );
    for (const [name, version] of [
      ['commander', '15.0.0'],
      ['zod', '4.4.3'],
      ['mongodb', '7.5.0'],
      ['@mongodb-js/saslprep', '1.4.13'],
      ['@types/webidl-conversions', '7.0.3'],
      ['@types/whatwg-url', '13.0.0'],
      ['bson', '7.3.1'],
      ['memory-pager', '1.5.0'],
      ['mongodb-connection-string-url', '7.0.2'],
      ['punycode', '2.3.1'],
      ['sparse-bitfield', '3.0.3'],
      ['tr46', '5.1.1'],
      ['webidl-conversions', '7.0.0'],
      ['whatwg-url', '14.2.0'],
      ['tr46', '5.1.1'],
      ['punycode', '2.3.1'],
      ['libsodium-wrappers', '0.8.4'],
      ['libsodium', '0.8.4'],
    ]) {
      assert(
        componentVersions.get(name) === version,
        `SBOM is missing ${name}@${version}`,
      );
    }
    const sbomText = JSON.stringify(sbom);
    assert(!sbomText.includes('@kavrix/'), 'Workspace package leaked into the SBOM');
    assert(!sbomText.includes('workspace:'), 'Workspace protocol leaked into the SBOM');

    const bin = join(packageRoot, 'dist', 'bin.js');
    const version = run(process.execPath, [bin, '--version'], installRoot);
    assertSafeText(version.stdout + version.stderr, 'kavrix --version output');
    assert(version.stderr.trim() === '', 'kavrix --version wrote to stderr');
    assert(
      version.stdout.trim() === manifest.version,
      'Installed kavrix version does not match package.json',
    );
    for (const [args, marker] of [
      [['--help'], 'Local encrypted credential vault'],
      [['recovery', '--help'], 'Create protected recovery kits'],
      [['key', '--help'], 'Protected key-file lifecycle'],
      [['view', '--help'], 'Show a readable vault dashboard'],
    ]) {
      const result = run(process.execPath, [bin, ...args], installRoot);
      assertSafeText(result.stdout + result.stderr, `kavrix ${args.join(' ')} output`);
      assert(result.stderr.trim() === '', `kavrix ${args.join(' ')} wrote to stderr`);
      assert(
        result.stdout.includes(marker),
        `kavrix ${args.join(' ')} did not expose the expected command`,
      );
    }

    verifiedVersion = manifest.version;
  } catch (error) {
    operationError = error;
  }
  const cleanupErrors = [];
  try {
    if (installRoot !== undefined) {
      await rm(installRoot, { recursive: true, force: true });
    }
  } catch (error) {
    cleanupErrors.push(error);
  }
  try {
    if (packDirectory !== undefined) {
      await rm(packDirectory, { recursive: true, force: true });
    }
  } catch (error) {
    cleanupErrors.push(error);
  }
  try {
    await rm(npmCache, { recursive: true, force: true });
  } catch (error) {
    cleanupErrors.push(error);
  }
  if (previousNpmCache === undefined) {
    delete process.env['npm_config_cache'];
  } else {
    process.env['npm_config_cache'] = previousNpmCache;
  }
  if (operationError !== undefined && cleanupErrors.length > 0) {
    throw new AggregateError(
      [operationError, ...cleanupErrors],
      'Packed package verification and cleanup failed.',
    );
  }
  if (operationError !== undefined) throw operationError;
  if (cleanupErrors.length > 0) {
    throw new AggregateError(cleanupErrors, 'Packed package cleanup failed.');
  }
  process.stdout.write(
    `Verified packed kavrix ${verifiedVersion} with an allowlisted artifact set.\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
