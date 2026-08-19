import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { encodeBase64Url, generateDatabaseRootKey, zeroize } from '@kavrix/crypto';
import {
  databaseIdSchema,
  databaseRevisionSchema,
  sha256DigestSchema,
  vaultIdSchema,
  vaultRevisionSchema,
} from '@kavrix/schemas';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  databaseRevisionAnchorPath,
  readDatabaseRevisionAnchor,
  verifyDatabaseRevisionAnchor,
  writeDatabaseRevisionAnchor,
  type DatabaseRevisionAnchor,
} from '../src/index.js';

let directory = '';
beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-database-anchor-'));
});
afterEach(async () => {
  await rm(directory, { force: true, recursive: true });
});

function digest(value: string): ReturnType<typeof sha256DigestSchema.parse> {
  return sha256DigestSchema.parse(
    encodeBase64Url(new Uint8Array(32).fill(value.charCodeAt(0))),
  );
}
function anchor(databaseRevision = 4, vaultRevision = 7): DatabaseRevisionAnchor {
  return {
    databaseId: databaseIdSchema.parse('db_test'),
    databaseRevision: databaseRevisionSchema.parse(databaseRevision),
    catalogMetadataDigest: digest('A'),
    vaultHeads: {
      [vaultIdSchema.parse('vault_a')]: {
        revision: vaultRevisionSchema.parse(vaultRevision),
        metadataDigest: digest('B'),
      },
      [vaultIdSchema.parse('vault_z')]: {
        revision: vaultRevisionSchema.parse(vaultRevision),
        metadataDigest: digest('C'),
      },
    },
  };
}
function path(name = 'database.anchor'): string {
  return join(directory, name);
}

describe('DRK-authenticated database revision anchors', () => {
  it('writes a canonical sorted bounded anchor, authenticates it, and derives an adjacent path', async () => {
    const file = path();
    const drk = generateDatabaseRootKey();
    try {
      await writeDatabaseRevisionAnchor(file, drk, anchor(), 'create');
      expect(databaseRevisionAnchorPath('/safe/database.cvkx')).toBe(
        '/safe/database.cvkx.database-anchor',
      );
      const raw = await readFile(file, 'utf8');
      expect(raw.indexOf('vault_a')).toBeLessThan(raw.indexOf('vault_z'));
      await expect(
        readDatabaseRevisionAnchor(file, drk, anchor(), { requireExactVaultSet: true }),
      ).resolves.toEqual(anchor());
    } finally {
      zeroize(drk);
    }
  });

  it('rejects another database, wrong DRK, malformed tag, lower revisions, and same-revision forks', async () => {
    const file = path();
    const drk = generateDatabaseRootKey();
    const wrongDrk = generateDatabaseRootKey();
    try {
      await writeDatabaseRevisionAnchor(file, drk, anchor(), 'create');
      await expect(readDatabaseRevisionAnchor(file, wrongDrk)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
      await expect(
        readDatabaseRevisionAnchor(file, drk, {
          ...anchor(),
          databaseId: databaseIdSchema.parse('db_other'),
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        readDatabaseRevisionAnchor(file, drk, anchor(3, 7)),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        readDatabaseRevisionAnchor(file, drk, {
          ...anchor(),
          catalogMetadataDigest: digest('D'),
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        readDatabaseRevisionAnchor(file, drk, {
          ...anchor(),
          vaultHeads: {
            ...anchor().vaultHeads,
            vault_a: {
              revision: vaultRevisionSchema.parse(7),
              metadataDigest: digest('D'),
            },
          },
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      const raw = await readFile(file, 'utf8');
      await writeFile(
        file,
        raw.replace(/"authenticationTag":"[^"]+"/, '"authenticationTag":"bad"'),
        { mode: 0o600 },
      );
      await expect(readDatabaseRevisionAnchor(file, drk)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
    } finally {
      zeroize(drk);
      zeroize(wrongDrk);
    }
  });

  it('supports a newer observation while rejecting lower vault heads and exact-set omissions/additions', () => {
    const trusted = anchor();
    expect(() =>
      verifyDatabaseRevisionAnchor(trusted, {
        ...anchor(5, 8),
        catalogMetadataDigest: digest('D'),
      }),
    ).not.toThrow();
    expect(() => verifyDatabaseRevisionAnchor(trusted, anchor(5, 6))).toThrow();
    expect(() =>
      verifyDatabaseRevisionAnchor(
        trusted,
        { ...anchor(), vaultHeads: { vault_a: anchor().vaultHeads.vault_a! } },
        { requireExactVaultSet: true },
      ),
    ).toThrow();
    expect(() =>
      verifyDatabaseRevisionAnchor(
        trusted,
        {
          ...anchor(),
          vaultHeads: {
            ...anchor().vaultHeads,
            vault_new: {
              revision: vaultRevisionSchema.parse(1),
              metadataDigest: digest('D'),
            },
          },
        },
        { requireExactVaultSet: true },
      ),
    ).toThrow();
  });

  it('rejects unsafe permissions, symlinks, trailing data, and preserves atomic publication', async () => {
    const file = path();
    const drk = generateDatabaseRootKey();
    try {
      await writeDatabaseRevisionAnchor(file, drk, anchor(), 'create');
      if (process.platform !== 'win32') {
        await chmod(file, 0o644);
        await expect(readDatabaseRevisionAnchor(file, drk)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
        await chmod(file, 0o600);
        const target = path('target');
        await writeFile(target, 'x', { mode: 0o600 });
        const linked = path('link');
        await symlink(target, linked);
        await expect(readDatabaseRevisionAnchor(linked, drk)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
      }
      const raw = await readFile(file, 'utf8');
      await writeFile(file, `${raw}trailing`, { mode: 0o600 });
      await expect(readDatabaseRevisionAnchor(file, drk)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
      await writeDatabaseRevisionAnchor(file, drk, anchor(5), 'replace');
      await expect(readDatabaseRevisionAnchor(file, drk)).resolves.toEqual(anchor(5));
    } finally {
      zeroize(drk);
    }
  });
});
