import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

const cliRoot = fileURLToPath(new URL('..', import.meta.url));
const packageManifest = JSON.parse(
  readFileSync(join(cliRoot, 'package.json'), 'utf8'),
) as {
  name: string;
  version: string;
  private: boolean;
  bin: { kavrix: string };
  files: string[];
  dependencies: Record<string, string>;
};
const distRoot = join(cliRoot, 'dist');

function listFiles(root: string, current = root): string[] {
  return readdirSync(current, { withFileTypes: true }).flatMap((entry) => {
    const path = join(current, entry.name);
    return entry.isDirectory()
      ? listFiles(root, path)
      : [relative(root, path).replaceAll('\\', '/')];
  });
}

describe('npm package contract', () => {
  it('declares a publishable kavrix package with one runtime dependency', () => {
    expect(packageManifest.name).toBe('kavrix');
    expect(packageManifest.private).toBe(false);
    expect(packageManifest.bin).toEqual({ kavrix: './dist/bin.js' });
    expect(packageManifest.files).toEqual([
      'dist/**/*.js',
      'dist/**/*.d.ts',
      'dist/*.cdx.json',
      'README.md',
      'LICENSE',
    ]);
    expect(packageManifest.dependencies).toEqual({ mongodb: '7.5.0' });
  });

  it('contains only compiled artifacts and release metadata', () => {
    expect(existsSync(distRoot)).toBe(true);
    const files = listFiles(distRoot);
    expect(files).toContain('bin.js');
    expect(files).toContain('index.js');
    expect(files).toContain('index.d.ts');
    expect(files).toContain('kavrix.cdx.json');
    expect(
      files.every((file) => /^(?:.+\.js|.+\.d\.ts|[^/]+\.cdx\.json)$/.test(file)),
    ).toBe(true);
    expect(existsSync(join(cliRoot, 'README.md'))).toBe(true);
    expect(existsSync(join(cliRoot, 'LICENSE'))).toBe(true);
    expect(readFileSync(join(cliRoot, 'README.md'), 'utf8')).toContain('eff.org');
  });

  it('records the bundled and runtime dependency inventory in the SBOM', () => {
    const sbom = JSON.parse(
      readFileSync(join(distRoot, 'kavrix.cdx.json'), 'utf8'),
    ) as {
      components?: Array<{ name?: string; version?: string }>;
    };
    const versions = new Map(
      (sbom.components ?? []).map((component) => [component.name, component.version]),
    );
    expect(versions.get('commander')).toBe('15.0.0');
    expect(versions.get('zod')).toBe('4.4.3');
    expect(versions.get('mongodb')).toBe('7.5.0');
    expect(versions.get('@mongodb-js/saslprep')).toBe('1.4.13');
    expect(versions.get('@types/webidl-conversions')).toBe('7.0.3');
    expect(versions.get('@types/whatwg-url')).toBe('13.0.0');
    expect(versions.get('bson')).toBe('7.3.1');
    expect(versions.get('memory-pager')).toBe('1.5.0');
    expect(versions.get('mongodb-connection-string-url')).toBe('7.0.2');
    expect(versions.get('punycode')).toBe('2.3.1');
    expect(versions.get('sparse-bitfield')).toBe('3.0.3');
    expect(versions.get('tr46')).toBe('5.1.1');
    expect(versions.get('webidl-conversions')).toBe('7.0.0');
    expect(versions.get('whatwg-url')).toBe('14.2.0');
    expect(versions.get('libsodium-wrappers')).toBe('0.8.4');
    expect(versions.get('libsodium')).toBe('0.8.4');
    const serialized = JSON.stringify(sbom);
    expect(serialized).not.toContain('@kavrix/');
    expect(serialized).not.toContain('workspace:');
  });

  it('does not leave source or local-state artifacts in dist', () => {
    const files = listFiles(distRoot);
    expect(files.some((file) => file.endsWith('.ts') && !file.endsWith('.d.ts'))).toBe(
      false,
    );
    expect(files.some((file) => file.includes('node_modules'))).toBe(false);
    expect(files.some((file) => file.includes('coverage'))).toBe(false);
    expect(files.every((file) => statSync(join(distRoot, file)).isFile())).toBe(true);
  });
});
