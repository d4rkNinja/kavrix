import { createHash } from 'node:crypto';
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
const allowedNodeImports = new Set(
  builtinModules.flatMap((name) => [name, `node:${name}`]),
);

const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
assertPublicManifest(manifest);

const reviewedRuntimePackages = await Promise.all(
  [
    ['commander', require],
    ['zod', require],
    ['libsodium-wrappers', cryptoRequire],
    ['libsodium', sodiumRequire],
  ].map(([name, resolver]) => readDependencyLicense(name, resolver)),
);
const licenseBanner = renderLicenseBanner(reviewedRuntimePackages);

assertSafeOutputDirectory();
await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });

const bundle = await build({
  absWorkingDir: packageDirectory,
  banner: { js: licenseBanner },
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
  target: ['node24.19'],
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
validateBundleImports(bundle.metafile);
validateReviewedPackageInputs(bundle.metafile, reviewedRuntimePackages);
validateSplitOutputs(bundle.metafile, reviewedRuntimePackages);
const javascriptArtifacts = await collectJavaScriptArtifacts();
await validateCompiledArtifacts(javascriptArtifacts);
const sbom = await createSbom(manifest, includedPackages, javascriptArtifacts);
validateSbom(sbom, manifest, includedPackages, javascriptArtifacts);
await writeFile(
  resolve(outputDirectory, 'kavrix.cdx.json'),
  `${JSON.stringify(sbom, null, 2)}\n`,
  'utf8',
);

function assertPublicManifest(value) {
  if (value.name !== 'kavrix' || value.private !== false || value.type !== 'module') {
    throw new Error(
      'The public package manifest is not the expected kavrix ESM package.',
    );
  }
  for (const key of [
    'dependencies',
    'optionalDependencies',
    'peerDependencies',
    'bundledDependencies',
    'bundleDependencies',
  ]) {
    if (key in value) {
      throw new Error(`The self-contained public package must not declare ${key}.`);
    }
  }
  if (value.bin?.creds !== './dist/bin.js') {
    throw new Error('The public creds executable must resolve to the compiled bundle.');
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

async function readDependencyLicense(packageName, resolver) {
  const packageRoot = await findPackageRoot(resolver.resolve(packageName), packageName);
  const dependencyManifest = JSON.parse(
    await readFile(resolve(packageRoot, 'package.json'), 'utf8'),
  );
  const licenseFile = (await readdir(packageRoot))
    .sort((left, right) => left.localeCompare(right, 'en'))
    .find((name) => /^licen[cs]e(?:\.|$)/iu.test(name));
  if (licenseFile === undefined) {
    throw new Error(`No license file was found for bundled package ${packageName}.`);
  }
  const licenseText = (
    await readFile(resolve(packageRoot, licenseFile), 'utf8')
  ).trim();
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
  };
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
    throw new Error('The CLI bundle contains an unreviewed runtime package.');
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
  return reviewedPackages.filter((dependency) => {
    const normalizedRoot = normalizePath(dependency.root);
    return Object.keys(metafile.inputs).some((input) => {
      const absoluteInput = normalizePath(resolve(packageDirectory, input));
      return (
        absoluteInput === normalizedRoot ||
        absoluteInput.startsWith(`${normalizedRoot}/`)
      );
    });
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
    chunks.length === 0 ||
    chunks.some(
      ([path]) =>
        !/^dist\/chunks\/chunk-[A-Z0-9]+\.js$/u.test(normalizeRelativePath(path)),
    )
  ) {
    throw new Error('The CLI bundle did not emit deterministic named ESM chunks.');
  }

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
  if (
    hasCryptoInput(entryOutputs[0][1]) ||
    !chunks.some(([, output]) => hasCryptoInput(output))
  ) {
    throw new Error('The portable-key crypto graph was not isolated from the entry.');
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
    !artifactPaths.some((path) => path.startsWith('dist/chunks/')) ||
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
        dependsOn: components.map((component) => component['bom-ref']).sort(),
      },
      ...components.map((component) => ({ ref: component['bom-ref'], dependsOn: [] })),
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
  return `pkg:npm/${encodeURIComponent(name).replace('%40', '@')}@${version}`;
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
