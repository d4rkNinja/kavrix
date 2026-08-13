import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { delimiter, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { CLI_VERSION } from '../src/index.js';

const packageDirectory = fileURLToPath(new URL('..', import.meta.url));

const packageSchema = z
  .object({
    name: z.literal('kavrix'),
    version: z.string(),
    private: z.literal(false),
    type: z.literal('module'),
    bin: z.object({ creds: z.literal('./dist/bin.js') }).strict(),
    files: z.tuple([
      z.literal('dist/**/*.js'),
      z.literal('dist/**/*.d.ts'),
      z.literal('dist/*.cdx.json'),
    ]),
    // The floor is the highest runtime API this package actually needs, not a
    // preference: `DatabaseSync.enableDefensive` landed on main in v25.1.0 and
    // was backported to v24.12.0, so 25.0.x is the one gap in the range. An open
    // upper bound is deliberate — `crypto.argon2` and `node:sqlite` are both
    // release candidates, so a missing or changed primitive is caught by the
    // runtime preflight, which fails closed with an actionable error, rather
    // than by an engine ceiling that would block install on every newer Node.
    engines: z.object({ node: z.literal('>=24.12.0 <25 || >=25.1.0') }).strict(),
    publishConfig: z
      .object({
        access: z.literal('public'),
        registry: z.literal('https://registry.npmjs.org/'),
      })
      .strict(),
    license: z.literal('MIT'),
    repository: z.object({
      type: z.literal('git'),
      url: z.url(),
      directory: z.literal('apps/cli'),
    }),
    keywords: z.array(z.string()).min(3),
    scripts: z.record(z.string(), z.string()),
  })
  .loose();

const packOutputSchema = z.object({
  files: z.array(z.object({ path: z.string() }).loose()),
});
const sbomSchema = z.object({
  components: z.array(
    z
      .object({
        type: z.enum(['library', 'data']),
        'bom-ref': z.string(),
        name: z.string(),
        version: z.string().optional(),
        licenses: z.array(z.object({ license: z.object({ id: z.string() }) })),
        externalReferences: z
          .array(z.object({ type: z.string(), url: z.string() }))
          .optional(),
        properties: z
          .array(z.object({ name: z.string(), value: z.string() }))
          .optional(),
      })
      .loose(),
  ),
});

describe('public package', () => {
  it('declares the real public bin and has no install lifecycle hook', () => {
    const manifest = packageSchema.parse(
      JSON.parse(readFileSync(`${packageDirectory}/package.json`, 'utf8')),
    );
    expect(manifest.version).toBe(CLI_VERSION);
    expect(manifest.scripts).not.toHaveProperty('install');
    expect(manifest.scripts).not.toHaveProperty('postinstall');
    expect(manifest.scripts).not.toHaveProperty('prepare');
  });

  it('packs only metadata and compiled dist artifacts', () => {
    // pnpm colorizes its notices whenever FORCE_COLOR is set, even into a pipe,
    // which would wrap the `[WARN]` prefixes in escape codes and defeat the
    // preamble check below. This asks for the machine-readable form explicitly
    // so the report parses identically regardless of the caller's terminal.
    const output = execFileSync(
      process.execPath,
      [resolvePnpmEntrypoint(), 'pack', '--dry-run', '--json'],
      {
        cwd: packageDirectory,
        encoding: 'utf8',
        env: { ...process.env, FORCE_COLOR: '0' },
      },
    );
    const pack = packOutputSchema.parse(JSON.parse(extractJsonDocument(output)));
    const paths = pack.files.map(({ path }) => path);
    expect(paths).toContain('dist/bin.js');
    expect(
      paths.some((path) => /^dist\/chunks\/chunk-[A-Z0-9]+\.js$/u.test(path)),
    ).toBe(true);
    expect(paths).toContain('dist/index.d.ts');
    expect(paths).toContain('dist/kavrix.cdx.json');
    expect(paths).toContain('package.json');
    expect(
      paths.every(
        (path) =>
          path === 'package.json' ||
          path === 'LICENSE' ||
          path === 'README.md' ||
          path.startsWith('dist/'),
      ),
    ).toBe(true);
    expect(
      paths.some((path) => /(?:^|\/)(?:src|test|coverage)(?:\/|$)/u.test(path)),
    ).toBe(false);
    expect(paths.some((path) => path.endsWith('.tsbuildinfo'))).toBe(false);
  }, 30_000);

  it('records every bundled third-party runtime and no workspace path', () => {
    const sbomText = readFileSync(`${packageDirectory}/dist/kavrix.cdx.json`, 'utf8');
    const sbom = sbomSchema.parse(JSON.parse(sbomText));
    expect(
      sbom.components
        .filter(({ type }) => type === 'library')
        .map(({ name, version, licenses }) => ({
          name,
          version,
          license: licenses[0]?.license.id,
        })),
    ).toEqual([
      { name: 'commander', version: '15.0.0', license: 'MIT' },
      { name: 'zod', version: '4.4.3', license: 'MIT' },
      { name: 'libsodium-wrappers', version: '0.8.4', license: 'ISC' },
      { name: 'libsodium', version: '0.8.4', license: 'ISC' },
    ]);
    expect(sbom.components.filter(({ type }) => type === 'data')).toEqual([
      expect.objectContaining({
        type: 'data',
        'bom-ref': 'urn:kavrix:data:eff-short-wordlist-for-passphrases-1',
        name: 'EFF Short Wordlist for Passphrases #1',
        licenses: [{ license: { id: 'CC-BY-4.0' } }],
        externalReferences: [
          {
            type: 'distribution',
            url: 'https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt',
          },
        ],
        properties: [
          {
            name: 'kavrix:source-sha256',
            value: '8f5ca830b8bffb6fe39c9736c024a00a6a6411adb3f83a9be8bfeeb6e067ae69',
          },
        ],
      }),
    ]);
    expect(sbomText).not.toMatch(/@kavrix\/|workspace:|file:\/\/|[A-Z]:\\/u);

    const compiled = readFileSync(`${packageDirectory}/dist/bin.js`, 'utf8');
    expect(compiled).toContain('libsodium-wrappers@0.8.4 (ISC)');
    expect(compiled).toContain('libsodium@0.8.4 (ISC)');
    expect(compiled).not.toContain('@kavrix/');
  });
});

function extractJsonDocument(output: string): string {
  const documentStart = /^\{$/mu.exec(output);
  const end = output.lastIndexOf('}');
  if (documentStart?.index === undefined || end < documentStart.index) {
    throw new Error('The pack report did not contain a JSON document.');
  }
  const preamble = output.slice(0, documentStart.index);
  if (!/^(?:\[(?:WARN|INFO)\][^\n]*\n)*$/u.test(preamble)) {
    throw new Error(`The pack report emitted unexpected output: ${preamble}`);
  }
  if (output.slice(end + 1).trim().length > 0) {
    throw new Error('The pack report emitted trailing output after the JSON document.');
  }
  return output.slice(documentStart.index, end + 1);
}

function resolvePnpmEntrypoint(): string {
  const pathDirectories = (process.env['PATH'] ?? '')
    .split(delimiter)
    .filter((value) => value.length > 0);
  const nodeDirectory = dirname(process.execPath);
  const candidates = [
    process.env['npm_execpath'],
    process.env['PNPM_HOME'] === undefined
      ? undefined
      : resolve(process.env['PNPM_HOME'], '..', 'pnpm', 'bin', 'pnpm.cjs'),
    // Corepack ships pnpm as a managed shim inside the Node installation.
    resolve(nodeDirectory, 'node_modules', 'corepack', 'dist', 'pnpm.js'),
    ...pathDirectories.flatMap((directory) => [
      resolve(directory, '..', 'pnpm', 'bin', 'pnpm.cjs'),
      resolve(directory, '..', 'dist', 'pnpm.js'),
      resolve(directory, 'node_modules', 'corepack', 'dist', 'pnpm.js'),
    ]),
  ];
  const entrypoint = candidates.find(
    (candidate): candidate is string =>
      candidate !== undefined && existsSync(candidate),
  );
  if (entrypoint === undefined) {
    throw new Error('The pnpm entrypoint is unavailable for package inspection.');
  }
  return entrypoint;
}
