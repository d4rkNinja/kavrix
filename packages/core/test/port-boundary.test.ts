import { readdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const portsDirectory = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  'src',
  'ports',
);

/**
 * Architectural fitness function: the persistence ports are core-owned
 * contracts and must never re-fuse with an adapter implementation. Their
 * only allowed external dependency is the canonical schema package.
 */
describe('persistence port boundary', () => {
  it('keeps every port module free of adapter dependencies', async () => {
    const files = (await readdir(portsDirectory)).filter((name) =>
      name.endsWith('.ts'),
    );
    expect(files).toEqual(
      expect.arrayContaining([
        'encrypted-database-store.ts',
        'encrypted-vault-store.ts',
        'collaborative-vault-store.ts',
      ]),
    );

    const offenders: string[] = [];
    for (const file of files) {
      const source = await readFile(join(portsDirectory, file), 'utf8');
      for (const match of source.matchAll(/from\s+'([^']+)'/gu)) {
        const specifier = match[1] ?? '';
        if (specifier.startsWith('.') || specifier === '@kavrix/schemas') {
          continue;
        }
        offenders.push(`${file}: ${specifier}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('exports the three persistence ports from the core barrel', async () => {
    const core = await import('../src/index.js');
    expect(core.EncryptedDatabaseStoreError).toBeTypeOf('function');
    expect(core.EncryptedVaultStoreError).toBeTypeOf('function');
    expect(Object.keys(core)).toContain('EncryptedDatabaseStoreError');
  });
});
