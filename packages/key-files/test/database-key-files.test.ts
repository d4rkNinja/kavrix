import {
  chmod,
  link,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  encodeBase64Url,
  generatePortableKey,
  generateRecoveryKey,
  zeroize,
} from '@kavrix/crypto';
import {
  databaseIdSchema,
  databaseRevisionSchema,
  keySlotIdSchema,
  sha256DigestSchema,
  vaultIdSchema,
  vaultRevisionSchema,
} from '@kavrix/schemas';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  cleanupOwnedDatabaseKeyFile,
  consumeDatabaseLocalShareBootstrap,
  createOwnedDatabaseKeyFile,
  createOwnedDatabaseLocalShareKeyFile,
  readDatabaseKeyFile,
  readDatabaseKeyFileBinding,
  writeDatabaseRecoveryKitFile,
  writeDatabaseKeyFile,
  type DatabaseKeyBinding,
  type DatabaseRevisionAnchor,
} from '../src/index.js';

let directory = '';
const binding: DatabaseKeyBinding = {
  databaseId: databaseIdSchema.parse('db_test'),
  keySlotId: keySlotIdSchema.parse('database-key-slot'),
};

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-database-key-'));
});
afterEach(async () => {
  await rm(directory, { force: true, recursive: true });
});

function path(name = 'database.cvkx'): string {
  return join(directory, name);
}
function passphrase(value = 'correct horse battery staple'): Uint8Array {
  return new TextEncoder().encode(value);
}
function options(secret: Uint8Array, mode: 'create' | 'replace' = 'create') {
  return { mode, protection: { kind: 'passphrase' as const, passphrase: secret } };
}

function digest(value: number) {
  return sha256DigestSchema.parse(encodeBase64Url(new Uint8Array(32).fill(value)));
}

function shareAnchor(): DatabaseRevisionAnchor {
  return {
    databaseId: binding.databaseId,
    databaseRevision: databaseRevisionSchema.parse(2),
    catalogMetadataDigest: digest(1),
    vaultHeads: {
      [vaultIdSchema.parse('vault_alpha')]: {
        revision: vaultRevisionSchema.parse(3),
        metadataDigest: digest(2),
      },
    },
  };
}

describe('protected database key files', () => {
  it('round-trips a protected key and leaves no portable-key or passphrase canary on disk', async () => {
    const file = path();
    const key = generatePortableKey();
    const expected = Uint8Array.from(key);
    const secret = passphrase('database-key-canary');
    try {
      await writeDatabaseKeyFile(file, key, binding, options(secret));
      const serialized = await readFile(file, 'utf8');
      expect(serialized).toContain('-----BEGIN KAVRIX DATABASE KEY-----');
      expect(serialized).not.toContain('database-key-canary');
      expect(serialized).not.toContain(Buffer.from(expected).toString('base64url'));
      await expect(readDatabaseKeyFileBinding(file)).resolves.toEqual(binding);
      const parsed = await readDatabaseKeyFile(file, secret, binding);
      try {
        expect(parsed.binding).toEqual(binding);
        expect(parsed.portableKey).toEqual(expected);
      } finally {
        zeroize(parsed.portableKey);
      }
    } finally {
      zeroize(key);
      zeroize(expected);
      zeroize(secret);
    }
  });

  it('returns an opaque consumed ownership capability for create-only cleanup', async () => {
    const file = path();
    const key = generatePortableKey();
    const secret = passphrase();
    try {
      const created = await createOwnedDatabaseKeyFile(
        file,
        key,
        binding,
        options(secret),
      );
      expect(created.status).toBe('published');
      if (created.status !== 'published') throw created.error;
      expect(Object.keys(created.publication)).toEqual([]);
      await cleanupOwnedDatabaseKeyFile(created.publication);
      await expect(readFile(file)).resolves.toHaveLength(0);
      await expect(
        cleanupOwnedDatabaseKeyFile(created.publication),
      ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
      await expect(
        cleanupOwnedDatabaseKeyFile(Object.freeze({}) as never),
      ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
    } finally {
      zeroize(key);
      zeroize(secret);
    }
  });

  it('round-trips and irreversibly consumes an authenticated local-share bootstrap', async () => {
    const file = path('shared.key');
    const key = generatePortableKey();
    const secret = passphrase();
    const anchor = shareAnchor();
    try {
      const created = await createOwnedDatabaseLocalShareKeyFile(
        file,
        key,
        binding,
        anchor,
        options(secret),
      );
      expect(created.status).toBe('published');
      const serialized = await readFile(file, 'utf8');
      expect(serialized).toContain('Version: 2');
      expect(serialized).not.toContain(anchor.catalogMetadataDigest);
      const parsed = await readDatabaseKeyFile(file, secret, binding);
      try {
        expect(parsed.portableKey).toEqual(key);
        expect(parsed.localShareBootstrap).toEqual(anchor);
      } finally {
        zeroize(parsed.portableKey);
      }

      await consumeDatabaseLocalShareBootstrap(file, key, binding, secret);
      const consumed = await readDatabaseKeyFile(file, secret, binding);
      try {
        expect(consumed.portableKey).toEqual(key);
        expect(consumed.localShareBootstrap).toBeNull();
      } finally {
        zeroize(consumed.portableKey);
      }
      const consumedText = await readFile(file, 'utf8');
      const tampered = consumedText.replace(
        /Ciphertext: ([A-Za-z0-9_-])/u,
        (_match, first: string) => `Ciphertext: ${first === 'A' ? 'B' : 'A'}`,
      );
      await writeFile(file, tampered, { mode: 0o600 });
      await expect(readDatabaseKeyFile(file, secret, binding)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
    } finally {
      zeroize(key);
      zeroize(secret);
    }
  });

  it('fails closed for passphrase, database, and key-slot mismatches', async () => {
    const file = path();
    const key = generatePortableKey();
    const secret = passphrase();
    const wrong = passphrase('wrong');
    try {
      await writeDatabaseKeyFile(file, key, binding, options(secret));
      await expect(readDatabaseKeyFile(file, wrong)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
      await expect(
        readDatabaseKeyFile(file, secret, {
          ...binding,
          databaseId: databaseIdSchema.parse('db_other'),
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        readDatabaseKeyFile(file, secret, {
          ...binding,
          keySlotId: keySlotIdSchema.parse('other-slot'),
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(key);
      zeroize(secret);
      zeroize(wrong);
    }
  });

  it('rejects version mutation, trailing bytes, and oversized input', async () => {
    const file = path();
    const key = generatePortableKey();
    const secret = passphrase();
    try {
      await writeDatabaseKeyFile(file, key, binding, options(secret));
      const valid = await readFile(file, 'utf8');
      for (const mutation of [
        valid.replace('Version: 1', 'Version: 2'),
        `${valid}trailing`,
      ]) {
        await writeFile(file, mutation, { mode: 0o600 });
        await expect(readDatabaseKeyFile(file, secret, binding)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
        await expect(readDatabaseKeyFileBinding(file)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
      }
      await writeFile(file, Buffer.alloc(256 * 1024 + 1), { mode: 0o600 });
      await expect(readDatabaseKeyFile(file, secret, binding)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
      await expect(readDatabaseKeyFileBinding(file)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
    } finally {
      zeroize(key);
      zeroize(secret);
    }
  });

  it('rejects unsafe permissions, symlinks, hardlinks, and initially existing targets', async () => {
    const file = path();
    const key = generatePortableKey();
    const secret = passphrase();
    try {
      await writeDatabaseKeyFile(file, key, binding, options(secret));
      await expect(
        writeDatabaseKeyFile(file, key, binding, options(secret)),
      ).rejects.toMatchObject({ code: 'KEY_FILE_ALREADY_EXISTS' });
      if (process.platform !== 'win32') {
        await chmod(file, 0o644);
        await expect(readDatabaseKeyFile(file, secret, binding)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
        await expect(readDatabaseKeyFileBinding(file)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
        await chmod(file, 0o600);
        const hardlink = path('linked.cvkx');
        await link(file, hardlink);
        await expect(readDatabaseKeyFile(file, secret, binding)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
        await expect(readDatabaseKeyFileBinding(file)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
        await rm(hardlink);
        const target = path('target.cvkx');
        await writeFile(target, 'not-a-key', { mode: 0o600 });
        const linked = path('symlink.cvkx');
        await symlink(target, linked);
        await expect(
          readDatabaseKeyFile(linked, secret, binding),
        ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
        await expect(readDatabaseKeyFileBinding(linked)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
      }
    } finally {
      zeroize(key);
      zeroize(secret);
    }
  });

  it('rejects cross-format public reads and authenticated replacement after pre-binding', async () => {
    const file = path();
    const recoveryFile = path('database.recovery');
    const first = generatePortableKey();
    const second = generatePortableKey();
    const recoveryKey = generateRecoveryKey();
    const secret = passphrase();
    const replacementBinding: DatabaseKeyBinding = {
      databaseId: databaseIdSchema.parse('db_replaced'),
      keySlotId: keySlotIdSchema.parse('replacement-slot'),
    };
    try {
      await writeDatabaseKeyFile(file, first, binding, options(secret));
      const publicBinding = await readDatabaseKeyFileBinding(file);
      expect(Object.keys(publicBinding).sort()).toEqual(['databaseId', 'keySlotId']);
      expect(JSON.stringify(publicBinding)).not.toContain('Ciphertext');
      await writeDatabaseKeyFile(
        file,
        second,
        replacementBinding,
        options(secret, 'replace'),
      );
      await expect(
        readDatabaseKeyFile(file, secret, publicBinding),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });

      await writeDatabaseRecoveryKitFile(
        recoveryFile,
        recoveryKey,
        {
          databaseId: binding.databaseId,
          recoverySlotId: keySlotIdSchema.parse('recovery-slot'),
        },
        { passphrase: secret },
      );
      await expect(readDatabaseKeyFileBinding(recoveryFile)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
    } finally {
      zeroize(first);
      zeroize(second);
      zeroize(recoveryKey);
      zeroize(secret);
    }
  });

  it('atomically replaces an existing complete document', async () => {
    const file = path();
    const first = generatePortableKey();
    const second = generatePortableKey();
    const secret = passphrase();
    try {
      await writeDatabaseKeyFile(file, first, binding, options(secret));
      await writeDatabaseKeyFile(file, second, binding, options(secret, 'replace'));
      const parsed = await readDatabaseKeyFile(file, secret, binding);
      try {
        expect(parsed.portableKey).toEqual(second);
      } finally {
        zeroize(parsed.portableKey);
      }
    } finally {
      zeroize(first);
      zeroize(second);
      zeroize(secret);
    }
  });

  it('uses create-only publication under a destination race', async () => {
    const file = path();
    const first = generatePortableKey();
    const second = generatePortableKey();
    const secret = passphrase();
    try {
      const results = await Promise.allSettled([
        writeDatabaseKeyFile(file, first, binding, options(secret)),
        writeDatabaseKeyFile(file, second, binding, options(secret)),
      ]);
      expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      const parsed = await readDatabaseKeyFile(file, secret, binding);
      try {
        expect([first, second]).toContainEqual(parsed.portableKey);
      } finally {
        zeroize(parsed.portableKey);
      }
    } finally {
      zeroize(first);
      zeroize(second);
      zeroize(secret);
    }
  });
});
