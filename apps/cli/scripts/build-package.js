import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { builtinModules, createRequire } from 'node:module';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { build } from 'esbuild';

const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repositoryRoot = resolve(packageDirectory, '../..');
const outputDirectory = resolve(packageDirectory, 'dist');
const manifestPath = resolve(packageDirectory, 'package.json');
const effWordListSourceDigest =
  '8f5ca830b8bffb6fe39c9736c024a00a6a6411adb3f83a9be8bfeeb6e067ae69';
const effWordListComponent = Object.freeze({
  type: 'data',
  'bom-ref': 'urn:kavrix:data:eff-short-wordlist-for-passphrases-1',
  name: 'EFF Short Wordlist for Passphrases #1',
  copyright: 'Electronic Frontier Foundation',
  licenses: [{ license: { id: 'CC-BY-4.0' } }],
  externalReferences: [
    {
      type: 'distribution',
      url: 'https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt',
    },
  ],
  properties: [{ name: 'kavrix:source-sha256', value: effWordListSourceDigest }],
});
const require = createRequire(import.meta.url);
const cryptoRequire = createRequire(
  resolve(repositoryRoot, 'packages/crypto/package.json'),
);
const sodiumRequire = createRequire(cryptoRequire.resolve('libsodium-wrappers'));
const tuiRequire = createRequire(resolve(repositoryRoot, 'packages/tui/package.json'));
const externalRuntimePackages = new Set([
  'mongodb',
  'kerberos',
  '@mongodb-js/zstd',
  '@aws-sdk/credential-providers',
  'gcp-metadata',
  'snappy',
  'socks',
  'mongodb-client-encryption',
  // Ink's optional devtools peer. Its static import lives behind
  // `process.env.DEV === 'true'` plus a throwing `import.meta.resolve`
  // guard, so the external binding can never execute without the
  // operator explicitly installing the package.
  'react-devtools-core',
  // Optional WebSocket performance peers of `ws` inside Ink's opt-in
  // devtools chunk; `ws` feature-detects both through guarded requires
  // and runs fine without them.
  'bufferutil',
  'utf-8-validate',
]);
const allowedNodeImports = new Set(
  builtinModules.flatMap((name) => [name, `node:${name}`]),
);
for (const externalPackage of externalRuntimePackages) {
  allowedNodeImports.add(externalPackage);
}

const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
assertPublicManifest(manifest);

const reviewedRuntimePackages = await Promise.all(
  [
    ['commander', require],
    ['zod', require],
    ['yaml', require],
    ['mongodb', require],
    ['libsodium-wrappers', cryptoRequire],
    ['libsodium', sodiumRequire],
    ['ink', tuiRequire],
    ['react', tuiRequire],
  ].map(([name, resolver]) => readDependencyLicense(name, resolver, packageDirectory)),
);
const licenseBanner = renderLicenseBanner(reviewedRuntimePackages);
const builtinBridgeBanner = [
  "import { createRequire as __kavrixCreateRequire } from 'node:module';",
  'const __kavrixNodeRequire = __kavrixCreateRequire(import.meta.url);',
  'const __kavrixNodeBuiltin = (name) => __kavrixNodeRequire(`node:${name}`);',
].join('\n');

assertSafeOutputDirectory();
await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });

const bundle = await build({
  absWorkingDir: packageDirectory,
  plugins: [yamlBuiltinProcessShim()],
  banner: { js: `${licenseBanner}\n${builtinBridgeBanner}` },
  bundle: true,
  chunkNames: 'chunks/chunk-[hash]',
  entryNames: '[name]',
  entryPoints: { bin: 'src/bin.ts' },
  format: 'esm',
  legalComments: 'none',
  metafile: true,
  outdir: 'dist',
  packages: 'bundle',
  platform: 'node',
  sourcemap: 'inline',
  sourcesContent: false,
  splitting: true,
  external: [...externalRuntimePackages],
  // Must track the engines floor, not the newest supported runtime: emitted
  // syntax has to parse on the oldest Node the manifest admits.
  target: ['node24.12'],
  treeShaking: true,
});

const publicModule = `export const CLI_VERSION = ${JSON.stringify(manifest.version)};\n`;
const publicDeclaration = `export declare const CLI_VERSION: ${JSON.stringify(manifest.version)};\n`;
await Promise.all([
  writeFile(resolve(outputDirectory, 'index.js'), publicModule, 'utf8'),
  writeFile(resolve(outputDirectory, 'index.d.ts'), publicDeclaration, 'utf8'),
]);

const includedPackages = includedExternalPackages(
  bundle.metafile,
  reviewedRuntimePackages,
);
const sbomPackages = await collectRuntimePackages(includedPackages);
validateBundleImports(bundle.metafile);
// Every node_modules input must sit inside a package whose manifest and
// license metadata passed the reviewed inventory above, so the guard covers
// the full transitive closure rather than only its seed packages.
validateReviewedPackageInputs(bundle.metafile, sbomPackages);
validateSplitOutputs(bundle.metafile, reviewedRuntimePackages);
const javascriptArtifacts = await collectJavaScriptArtifacts();
await validateCompiledArtifacts(javascriptArtifacts);
const sbom = await createSbom(manifest, sbomPackages, javascriptArtifacts);
validateSbom(sbom, manifest, sbomPackages, javascriptArtifacts);
await writeFile(
  resolve(outputDirectory, 'kavrix.cdx.json'),
  `${JSON.stringify(sbom, null, 2)}\n`,
  'utf8',
);

/**
 * The reviewed YAML parser is CommonJS and requires bare builtin names
 * ('process', 'buffer'), which esbuild wraps as throwing dynamic requires
 * when emitting ESM. Bridge them through createRequire against the
 * `node:`-prefixed spellings Node resolves reliably.
 */

function yamlBuiltinProcessShim() {
  const BARE_BUILTINS = ['process', 'buffer', 'util', 'stream', 'path', 'fs'];
  return {
    name: 'yaml-builtin-process-shim',
    setup(build) {
      build.onLoad(
        { filter: /node_modules[\\/]+yaml[\\/]+dist[\\/].+\.js$/, namespace: 'file' },
        async (args) => {
          let text = await readFile(args.path, 'utf8');
          for (const builtinName of BARE_BUILTINS) {
            for (const quote of ["'", '"']) {
              text = text.replaceAll(
                `require(${quote}${builtinName}${quote})`,
                `__kavrixNodeBuiltin('${builtinName}')`,
              );
            }
          }
          if (text === (await readFile(args.path, 'utf8'))) return undefined;
          return { contents: text, loader: 'js' };
        },
      );
    },
  };
}

function assertPublicManifest(value) {
  if (value.name !== 'kavrix' || value.private !== false || value.type !== 'module') {
    throw new Error(
      'The public package manifest is not the expected kavrix ESM package.',
    );
  }
  for (const key of [
    'optionalDependencies',
    'peerDependencies',
    'bundledDependencies',
    'bundleDependencies',
  ]) {
    if (key in value) {
      throw new Error(`The public package must not declare ${key}.`);
    }
  }
  const dependencyNames = Object.keys(value.dependencies ?? {});
  if (dependencyNames.length !== 1 || dependencyNames[0] !== 'mongodb') {
    throw new Error(
      'The public package may depend only on the reviewed MongoDB runtime.',
    );
  }
  if (value.bin?.kavrix !== './dist/bin.js') {
    throw new Error(
      'The public kavrix executable must resolve to the compiled bundle.',
    );
  }
  if (
    value.publishConfig?.access !== 'public' ||
    value.publishConfig?.registry !== 'https://registry.npmjs.org/'
  ) {
    throw new Error(
      'The public package must be pinned to public access on the npm registry.',
    );
  }
}

function assertSafeOutputDirectory() {
  const relativeOutput = relative(packageDirectory, outputDirectory);
  if (
    relativeOutput !== 'dist' ||
    relativeOutput.startsWith('..') ||
    isAbsolute(relativeOutput)
  ) {
    throw new Error('Refusing to replace an unexpected build output directory.');
  }
}

async function readDependencyLicense(packageName, resolver, fromDirectory) {
  let entryPath;
  try {
    entryPath = resolver.resolve(`${packageName}/package.json`);
  } catch {
    try {
      entryPath = resolver.resolve(packageName);
    } catch {
      // ESM-only manifests without a `require` condition cannot be resolved by
      // the CJS resolver at all; fall back to walking node_modules directories
      // outward from the dependent package so the inventory reaches the exact
      // installed copy that esbuild bundles.
      entryPath = resolve(
        locateDependencyRoot(fromDirectory, packageName),
        'package.json',
      );
    }
  }
  const packageRoot = await findPackageRoot(entryPath, packageName);
  const dependencyManifest = JSON.parse(
    await readFile(resolve(packageRoot, 'package.json'), 'utf8'),
  );
  const licenseFile = (await readdir(packageRoot))
    .sort((left, right) => left.localeCompare(right, 'en'))
    .find((name) => /^licen[cs]e(?:[.-]|$)/iu.test(name));
  let licenseText;
  if (licenseFile === undefined) {
    // Reviewed exception: some upstream packages publish only the SPDX
    // `license` manifest field with no standalone file (observed for
    // yoga-layout). The attribution stays truthful and names the exact
    // declared license instead of silently dropping the notice.
    if (
      typeof dependencyManifest?.license !== 'string' ||
      dependencyManifest.license.length === 0
    ) {
      throw new Error(`No license file was found for bundled package ${packageName}.`);
    }
    licenseText =
      `${dependencyManifest.license} license as declared in the ` +
      `${packageName} package.json manifest; upstream ships no separate ` +
      'license file.';
  } else {
    licenseText = (await readFile(resolve(packageRoot, licenseFile), 'utf8')).trim();
    if (licenseText.length === 0) {
      throw new Error(`No license file was found for bundled package ${packageName}.`);
    }
  }
  if (
    dependencyManifest.name !== packageName ||
    typeof dependencyManifest.version !== 'string' ||
    typeof dependencyManifest.license !== 'string' ||
    licenseText.length === 0
  ) {
    throw new Error(`Bundled package ${packageName} has incomplete license metadata.`);
  }
  return {
    name: dependencyManifest.name,
    version: dependencyManifest.version,
    license: dependencyManifest.license,
    licenseText,
    root: packageRoot,
    runtimeDependencyNames: [
      ...new Set([
        ...Object.keys(dependencyManifest.dependencies ?? {}),
        ...Object.keys(dependencyManifest.optionalDependencies ?? {}),
      ]),
    ],
  };
}

async function collectRuntimePackages(seeds) {
  const packages = new Map();
  const queue = [...seeds];
  while (queue.length > 0) {
    const current = queue.shift();
    if (current === undefined) continue;
    const key = `${current.name}@${current.version}`;
    if (packages.has(key)) continue;
    packages.set(key, current);
    const resolver = createRequire(resolve(current.root, 'package.json'));
    for (const dependencyName of current.runtimeDependencyNames) {
      let dependency;
      try {
        dependency = await readDependencyLicense(
          dependencyName,
          resolver,
          current.root,
        );
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        throw new Error(
          `Could not inventory runtime dependency ${dependencyName} of ${key}: ${message}`,
          { cause: error },
        );
      }
      queue.push(dependency);
    }
  }
  return [...packages.values()].sort((left, right) =>
    `${left.name}@${left.version}`.localeCompare(
      `${right.name}@${right.version}`,
      'en',
    ),
  );
}

function validateReviewedPackageInputs(metafile, reviewedPackages) {
  const reviewedRoots = reviewedPackages.map((dependency) =>
    normalizePath(dependency.root),
  );
  const unreviewed = Object.keys(metafile.inputs)
    .map((input) => normalizePath(resolve(packageDirectory, input)))
    .filter((input) => input.includes('/node_modules/'))
    .filter(
      (input) =>
        !reviewedRoots.some((root) => input === root || input.startsWith(`${root}/`)),
    );
  if (unreviewed.length > 0) {
    const offenders = [...new Set(unreviewed)].slice(0, 20).join('\n  ');
    throw new Error(
      `The CLI bundle contains an unreviewed runtime package:\n  ${offenders}`,
    );
  }
}

async function findPackageRoot(entryPath, expectedName) {
  let current = dirname(entryPath);
  while (current !== dirname(current)) {
    const candidate = resolve(current, 'package.json');
    try {
      const value = JSON.parse(await readFile(candidate, 'utf8'));
      if (value.name === expectedName) return current;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    current = dirname(current);
  }
  throw new Error(`Could not locate package metadata for ${expectedName}.`);
}

/**
 * Locates the installed directory of one dependency without depending on CJS
 * `exports` conditions. Tries the pnpm/flat-layout sibling position first,
 * then walks the standard node_modules ancestor chain outward.
 */
function locateDependencyRoot(fromDirectory, packageName) {
  const siblingCandidate = resolve(dirname(fromDirectory), packageName);
  if (existsSync(resolve(siblingCandidate, 'package.json'))) {
    return siblingCandidate;
  }
  let base = fromDirectory;
  for (;;) {
    const candidate = resolve(base, 'node_modules', packageName);
    if (existsSync(resolve(candidate, 'package.json'))) return candidate;
    const parent = dirname(base);
    if (parent === base) {
      throw new Error(
        `Could not locate the installed copy of ${packageName} starting from ${fromDirectory}.`,
      );
    }
    base = parent;
  }
}

function renderLicenseBanner(packages) {
  const notices = packages
    .map(
      (dependency) =>
        `${dependency.name}@${dependency.version} (${dependency.license})\n${dependency.licenseText}`,
    )
    .join('\n\n');
  return `/*! Kavrix is MIT licensed. Bundled third-party notices:\n\n${notices.replaceAll('*/', '* /')}\n*/`;
}

function includedExternalPackages(metafile, reviewedPackages) {
  const externalImports = new Set(
    Object.values(metafile.outputs)
      .flatMap((output) => output.imports)
      .filter((item) => item.external)
      .map((item) => item.path),
  );
  return reviewedPackages.filter((dependency) => {
    const normalizedRoot = normalizePath(dependency.root);
    return (
      Object.keys(metafile.inputs).some((input) => {
        const absoluteInput = normalizePath(resolve(packageDirectory, input));
        return (
          absoluteInput === normalizedRoot ||
          absoluteInput.startsWith(`${normalizedRoot}/`)
        );
      }) || externalImports.has(dependency.name)
    );
  });
}

function validateBundleImports(metafile) {
  const invalidImports = Object.values(metafile.outputs)
    .flatMap((output) => output.imports)
    .filter((item) => item.external && !allowedNodeImports.has(item.path))
    .map((item) => item.path);
  if (invalidImports.length > 0) {
    throw new Error(
      `The public bundle retains runtime package imports: ${invalidImports.join(', ')}`,
    );
  }
}

function validateSplitOutputs(metafile, reviewedPackages) {
  const outputs = Object.entries(metafile.outputs);
  const entryOutputs = outputs.filter(
    ([path]) => normalizeRelativePath(path) === 'dist/bin.js',
  );
  if (entryOutputs.length !== 1 || entryOutputs[0][1].entryPoint === undefined) {
    throw new Error('The CLI bundle must contain exactly one executable entry point.');
  }
  const chunks = outputs.filter(([path]) => {
    const normalized = normalizeRelativePath(path);
    return normalized !== 'dist/bin.js' && normalized.endsWith('.js');
  });
  if (
    chunks.some(
      ([path]) =>
        !/^dist\/chunks\/chunk-[A-Z0-9]+\.js$/u.test(normalizeRelativePath(path)),
    )
  ) {
    throw new Error('The CLI bundle did not emit deterministic named ESM chunks.');
  }
  if (chunks.length === 0) return;

  const cryptoRoots = reviewedPackages
    .filter(({ name }) => name === 'libsodium' || name === 'libsodium-wrappers')
    .map(({ root }) => normalizePath(root));
  const hasCryptoInput = (output) =>
    Object.keys(output.inputs).some((input) => {
      const absoluteInput = normalizePath(resolve(packageDirectory, input));
      return cryptoRoots.some(
        (root) => absoluteInput === root || absoluteInput.startsWith(`${root}/`),
      );
    });
  // The single-entry CLI keeps the portable-key crypto graph inside the entry
  // artifact; lazy feature chunks (for example the interactive showcase) must
  // never fragment that graph across additional artifacts, which would break
  // artifact-level integrity attribution and invite accidental duplication.
  const cryptoOutputs = outputs.filter(([, output]) => hasCryptoInput(output));
  if (cryptoOutputs.length !== 1) {
    throw new Error(
      `The portable-key crypto graph spans ${String(cryptoOutputs.length)} artifacts; it must stay contiguous in exactly one.`,
    );
  }
}

async function collectJavaScriptArtifacts() {
  const paths = [];
  const visit = async (directory) => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = resolve(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile() && entry.name.endsWith('.js')) paths.push(path);
    }
  };
  await visit(outputDirectory);
  return Promise.all(
    paths
      .sort((left, right) => left.localeCompare(right, 'en'))
      .map(async (path) => {
        const bytes = await readFile(path);
        return {
          path: normalizeRelativePath(relative(packageDirectory, path)),
          bytes,
          hash: sha256Bytes(bytes),
        };
      }),
  );
}

async function validateCompiledArtifacts(artifacts) {
  const declaration = await readFile(resolve(outputDirectory, 'index.d.ts'), 'utf8');
  const compiled = `${artifacts.map(({ bytes }) => bytes.toString('utf8')).join('\n')}\n${declaration}`;
  const artifactPaths = artifacts.map(({ path }) => path);
  if (
    !artifactPaths.includes('dist/bin.js') ||
    !artifactPaths.includes('dist/index.js') ||
    artifactPaths.some(
      (path) =>
        path !== 'dist/bin.js' &&
        path !== 'dist/index.js' &&
        !/^dist\/chunks\/chunk-[A-Z0-9]+\.js$/u.test(path),
    )
  ) {
    throw new Error('The compiled JavaScript artifact set has an unexpected shape.');
  }
  for (const prohibited of [
    '@kavrix/',
    'workspace:',
    'secret-password-canary',
    'secret-note-canary',
    'runtime-vault-secret-canary',
    'KAVRIX-BACKUP-PLAINTEXT-CANARY',
    'plaintext-storage-canary',
    'unique-plaintext-canary-7ac19783',
    'canary-plaintext-value',
  ]) {
    if (compiled.includes(prohibited)) {
      throw new Error(
        `A prohibited package reference or test canary reached dist: ${prohibited}`,
      );
    }
  }
  const bin = artifacts
    .find(({ path }) => path === 'dist/bin.js')
    ?.bytes.toString('utf8');
  if (bin === undefined) throw new Error('The compiled CLI entry is missing.');
  if (!bin.startsWith('#!/usr/bin/env node\n')) {
    throw new Error('The compiled CLI bundle is missing its portable Node.js shebang.');
  }
  if (compiled.includes('"sourcesContent"')) {
    throw new Error('The inline source map must not embed private source text.');
  }
}

async function createSbom(packageManifest, dependencies, artifacts) {
  const rootReference = npmPurl(packageManifest.name, packageManifest.version);
  const libraryComponents = dependencies.map((dependency) => ({
    type: 'library',
    'bom-ref': npmPurl(dependency.name, dependency.version),
    name: dependency.name,
    version: dependency.version,
    licenses: [{ license: { id: dependency.license } }],
    purl: npmPurl(dependency.name, dependency.version),
  }));
  const components = [...libraryComponents, effWordListComponent];
  const referencesByName = new Map(
    dependencies.map((dependency) => [
      dependency.name,
      npmPurl(dependency.name, dependency.version),
    ]),
  );
  const dependencyEntries = dependencies.map((dependency) => ({
    ref: npmPurl(dependency.name, dependency.version),
    dependsOn: dependency.runtimeDependencyNames
      .map((name) => referencesByName.get(name))
      .filter((reference) => reference !== undefined)
      .sort(),
  }));
  return {
    $schema: 'https://cyclonedx.org/schema/bom-1.6.schema.json',
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${deterministicUuid(`${packageManifest.name}@${packageManifest.version}`)}`,
    version: 1,
    metadata: {
      component: {
        type: 'application',
        'bom-ref': rootReference,
        name: packageManifest.name,
        version: packageManifest.version,
        licenses: [{ license: { id: packageManifest.license } }],
        purl: rootReference,
        hashes: [
          {
            alg: 'SHA-256',
            content: aggregateArtifactHash(artifacts),
          },
        ],
        properties: artifacts.map(({ path, hash }) => ({
          name: `kavrix:artifact-sha256:${path}`,
          value: hash,
        })),
      },
    },
    components,
    dependencies: [
      {
        ref: rootReference,
        dependsOn: Object.keys(packageManifest.dependencies ?? {})
          .map((name) => referencesByName.get(name))
          .filter((reference) => reference !== undefined)
          .concat(effWordListComponent['bom-ref'])
          .sort(),
      },
      ...dependencyEntries,
      { ref: effWordListComponent['bom-ref'], dependsOn: [] },
    ],
  };
}

function validateSbom(sbom, packageManifest, dependencies, artifacts) {
  const serialized = JSON.stringify(sbom);
  if (
    sbom.bomFormat !== 'CycloneDX' ||
    sbom.specVersion !== '1.6' ||
    sbom.version !== 1 ||
    sbom.metadata?.component?.name !== packageManifest.name ||
    sbom.metadata?.component?.version !== packageManifest.version ||
    !/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      sbom.serialNumber,
    )
  ) {
    throw new Error('The generated CycloneDX 1.6 SBOM has an invalid root shape.');
  }
  const expectedComponents = dependencies
    .map((dependency) => `${dependency.name}@${dependency.version}`)
    .sort();
  const actualComponents = sbom.components
    .filter((component) => component.type === 'library')
    .map((component) => `${component.name}@${component.version}`)
    .sort();
  if (JSON.stringify(actualComponents) !== JSON.stringify(expectedComponents)) {
    throw new Error('The generated SBOM does not match the bundled dependency set.');
  }
  const dataComponents = sbom.components.filter(
    (component) => component.type === 'data',
  );
  if (
    dataComponents.length !== 1 ||
    JSON.stringify(dataComponents[0]) !== JSON.stringify(effWordListComponent) ||
    !sbom.dependencies[0]?.dependsOn.includes(effWordListComponent['bom-ref']) ||
    !sbom.dependencies.some(
      (dependency) =>
        dependency.ref === effWordListComponent['bom-ref'] &&
        dependency.dependsOn.length === 0,
    )
  ) {
    throw new Error('The generated SBOM omits the attributed embedded word list.');
  }
  const expectedProperties = artifacts.map(({ path, hash }) => ({
    name: `kavrix:artifact-sha256:${path}`,
    value: hash,
  }));
  if (
    sbom.metadata.component.hashes?.[0]?.content !== aggregateArtifactHash(artifacts) ||
    JSON.stringify(sbom.metadata.component.properties) !==
      JSON.stringify(expectedProperties)
  ) {
    throw new Error('The generated SBOM does not cover every JavaScript artifact.');
  }
  const normalized = serialized.replaceAll('\\', '/');
  for (const prohibited of [
    repositoryRoot.replaceAll('\\', '/'),
    packageDirectory.replaceAll('\\', '/'),
    'file://',
    '@kavrix/',
    'workspace:',
    'secret-password-canary',
    'secret-note-canary',
  ]) {
    if (normalized.includes(prohibited)) {
      throw new Error('The generated SBOM contains a path or private build marker.');
    }
  }
}

function npmPurl(name, version) {
  return `pkg:npm/${encodeURIComponent(name).replaceAll('%40', '@')}@${version}`;
}

function deterministicUuid(value) {
  const hex = createHash('sha256').update(value).digest('hex').slice(0, 32).split('');
  hex[12] = '5';
  hex[16] = ((Number.parseInt(hex[16], 16) & 0x3) | 0x8).toString(16);
  return `${hex.slice(0, 8).join('')}-${hex.slice(8, 12).join('')}-${hex.slice(12, 16).join('')}-${hex.slice(16, 20).join('')}-${hex.slice(20).join('')}`;
}

function aggregateArtifactHash(artifacts) {
  const hash = createHash('sha256');
  for (const artifact of artifacts) {
    hash.update(artifact.path).update('\0').update(artifact.bytes).update('\0');
  }
  return hash.digest('hex');
}

function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function normalizeRelativePath(path) {
  return path.replaceAll('\\', '/');
}

function normalizePath(path) {
  return pathToFileURL(path).href.replace(/\/$/u, '');
}
