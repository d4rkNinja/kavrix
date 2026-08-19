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
  type VaultId,
} from '@kavrix/schemas';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  cleanupOwnedDatabaseRevisionAnchor,
  createOwnedDatabaseRevisionAnchor,
  databaseRevisionAnchorPath,
  readDatabaseRevisionAnchor,
  transitionDatabaseRevisionAnchor,
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

function anchorWithVaultCount(count: number, revision = 4): DatabaseRevisionAnchor {
  const vaultHeads: Record<string, DatabaseRevisionAnchor['vaultHeads'][VaultId]> = {};
  for (let index = 0; index < count; index += 1) {
    vaultHeads[`vault_${String(index).padStart(4, '0')}`] = {
      revision: vaultRevisionSchema.parse(index + 1),
      metadataDigest: digest(String.fromCharCode(65 + (index % 20))),
    };
  }
  return {
    ...anchor(revision),
    vaultHeads: vaultHeads as DatabaseRevisionAnchor['vaultHeads'],
  };
}

describe('DRK-authenticated database revision anchors', () => {
  it('returns an opaque consumed ownership capability for create-only cleanup', async () => {
    const file = path();
    const drk = generateDatabaseRootKey();
    try {
      const created = await createOwnedDatabaseRevisionAnchor(file, drk, anchor());
      expect(created.status).toBe('published');
      if (created.status !== 'published') throw created.error;
      expect(Object.keys(created.publication)).toEqual([]);
      await cleanupOwnedDatabaseRevisionAnchor(created.publication);
      await expect(readFile(file)).resolves.toHaveLength(0);
      await expect(
        cleanupOwnedDatabaseRevisionAnchor(created.publication),
      ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
    } finally {
      zeroize(drk);
    }
  });

  it('writes, reads, and verifies all 1,000 bounded vault heads while rejecting count and byte excess', async () => {
    const file = path();
    const drk = generateDatabaseRootKey();
    try {
      const maximum = anchorWithVaultCount(1_000);
      await writeDatabaseRevisionAnchor(file, drk, maximum, 'create');
      await expect(
        readDatabaseRevisionAnchor(file, drk, maximum, { requireExactVaultSet: true }),
      ).resolves.toEqual(maximum);
      await expect(
        writeDatabaseRevisionAnchor(
          path('too-many.anchor'),
          drk,
          anchorWithVaultCount(1_001),
          'create',
        ),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await writeFile(path('oversized.anchor'), Buffer.alloc(128 * 1024 + 1), {
        mode: 0o600,
      });
      await expect(
        readDatabaseRevisionAnchor(path('oversized.anchor'), drk),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(drk);
    }
  });

  it('holds one exclusive protected transition across verification, callback, and publication', async () => {
    const file = path();
    const drk = generateDatabaseRootKey();
    let begin!: () => void;
    let release!: () => void;
    const entered = new Promise<void>((resolve) => {
      begin = resolve;
    });
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    try {
      const initial = anchor();
      const newer = anchor(5, 8);
      await writeDatabaseRevisionAnchor(file, drk, initial, 'create');
      const first = transitionDatabaseRevisionAnchor(file, drk, initial, async () => {
        begin();
        await blocked;
        return { nextAnchor: newer, result: 'advanced' };
      });
      await entered;
      await expect(
        transitionDatabaseRevisionAnchor(file, drk, initial, async () => ({
          nextAnchor: anchor(5, 9),
          result: 'stale',
        })),
      ).rejects.toMatchObject({ code: 'KEY_FILE_BUSY' });
      release();
      await expect(first).resolves.toBe('advanced');
      await expect(
        transitionDatabaseRevisionAnchor(file, drk, initial, async () => ({
          nextAnchor: anchor(6, 10),
          result: 'stale-retry',
        })),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(readDatabaseRevisionAnchor(file, drk)).resolves.toEqual(newer);
    } finally {
      zeroize(drk);
    }
  });

  it('cleans the exclusive transition lock after a callback failure', async () => {
    const file = path();
    const drk = generateDatabaseRootKey();
    try {
      const initial = anchor();
      await writeDatabaseRevisionAnchor(file, drk, initial, 'create');
      await expect(
        transitionDatabaseRevisionAnchor(file, drk, initial, async () => {
          throw new Error('callback failed');
        }),
      ).rejects.toThrow('callback failed');
      await expect(
        transitionDatabaseRevisionAnchor(file, drk, initial, async () => ({
          nextAnchor: anchor(5),
          result: undefined,
        })),
      ).resolves.toBeUndefined();
      await expect(readDatabaseRevisionAnchor(file, drk)).resolves.toEqual(anchor(5));
    } finally {
      zeroize(drk);
    }
  });

  it('rejects a callback that returns an anchor older than the accepted observation', async () => {
    const file = path();
    const drk = generateDatabaseRootKey();
    try {
      const trusted = anchor();
      const observed = {
        ...anchor(5, 8),
        vaultHeads: {
          ...anchor(5, 8).vaultHeads,
          vault_new: {
            revision: vaultRevisionSchema.parse(1),
            metadataDigest: digest('D'),
          },
        },
      } as DatabaseRevisionAnchor;
      await writeDatabaseRevisionAnchor(file, drk, trusted, 'create');
      await expect(
        transitionDatabaseRevisionAnchor(file, drk, observed, async () => ({
          nextAnchor: trusted,
          result: 'stale',
        })),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(readDatabaseRevisionAnchor(file, drk)).resolves.toEqual(trusted);
    } finally {
      zeroize(drk);
    }
  });
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
