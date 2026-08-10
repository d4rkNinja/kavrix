import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
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
    engines: z.object({ node: z.literal('>=24.19.0 <25') }).strict(),
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
    const output = execFileSync(
      process.execPath,
      [
        resolve(dirname(process.execPath), 'node_modules/corepack/dist/pnpm.js'),
        'pack',
        '--dry-run',
        '--json',
      ],
      { cwd: packageDirectory, encoding: 'utf8' },
    );
    const pack = packOutputSchema.parse(JSON.parse(output));
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
