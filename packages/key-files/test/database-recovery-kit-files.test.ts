import { chmod, link, readFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { generateRecoveryKey, zeroize } from '@kavrix/crypto';
import { databaseIdSchema, keySlotIdSchema, vaultIdSchema } from '@kavrix/schemas';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  cleanupOwnedDatabaseRecoveryKitFile,
  createOwnedDatabaseRecoveryKitFile,
  readDatabaseRecoveryKitFileBinding,
  readDatabaseRecoveryKitFile,
  readRecoveryKitFile,
  writeDatabaseRecoveryKitFile,
  writeRecoveryKitFile,
  type DatabaseRecoveryBinding,
} from '../src/index.js';
import {
  createSecureTestDirectory as mkdtemp,
  writeSecureTestFile as writeFile,
} from './secure-temporary-directory.js';

let directory = '';
const binding: DatabaseRecoveryBinding = {
  databaseId: databaseIdSchema.parse('db_test'),
  recoverySlotId: keySlotIdSchema.parse('database-recovery-slot'),
};

beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'kavrix-database-recovery-'));
});
afterEach(async () => {
  await rm(directory, { force: true, recursive: true });
});

function path(name = 'database.recovery'): string {
  return join(directory, name);
}
function passphrase(value = 'correct horse battery staple'): Uint8Array {
  return new TextEncoder().encode(value);
}
function options(secret: Uint8Array, mode: 'create' | 'replace' = 'create') {
  return { mode, passphrase: secret };
}

describe('protected database recovery-kit files', () => {
  it('round-trips without persisting recovery-key or passphrase canaries', async () => {
    const file = path();
    const key = generateRecoveryKey();
    const expected = Uint8Array.from(key);
    const secret = passphrase('database-recovery-canary');
    try {
      await writeDatabaseRecoveryKitFile(file, key, binding, options(secret));
      const serialized = await readFile(file, 'utf8');
      expect(serialized).toContain('"format":"kavrix-database-recovery-kit"');
      expect(serialized).not.toContain('database-recovery-canary');
      expect(serialized).not.toContain(Buffer.from(expected).toString('base64url'));
      await expect(readDatabaseRecoveryKitFileBinding(file)).resolves.toEqual(binding);
      const parsed = await readDatabaseRecoveryKitFile(file, secret, binding);
      try {
        expect(parsed.binding).toEqual(binding);
        expect(parsed.recoveryKey).toEqual(expected);
      } finally {
        zeroize(parsed.recoveryKey);
      }
    } finally {
      zeroize(key);
      zeroize(expected);
      zeroize(secret);
    }
  });

  it('returns an opaque consumed ownership capability for create-only cleanup', async () => {
    const file = path();
    const key = generateRecoveryKey();
    const secret = passphrase();
    try {
      const created = await createOwnedDatabaseRecoveryKitFile(
        file,
        key,
        binding,
        options(secret),
      );
      expect(created.status).toBe('published');
      if (created.status !== 'published') throw created.error;
      expect(Object.keys(created.publication)).toEqual([]);
      await cleanupOwnedDatabaseRecoveryKitFile(created.publication);
      await expect(readFile(file)).resolves.toHaveLength(0);
      await expect(
        cleanupOwnedDatabaseRecoveryKitFile(created.publication),
      ).rejects.toMatchObject({ code: 'KEY_FILE_OPERATION_FAILED' });
    } finally {
      zeroize(key);
      zeroize(secret);
    }
  });

  it('fails closed for passphrase/binding/version/trailing/oversized failures', async () => {
    const file = path();
    const key = generateRecoveryKey();
    const secret = passphrase();
    const wrong = passphrase('wrong');
    try {
      await writeDatabaseRecoveryKitFile(file, key, binding, options(secret));
      await expect(
        readDatabaseRecoveryKitFile(file, wrong, binding),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        readDatabaseRecoveryKitFile(file, secret, {
          ...binding,
          databaseId: databaseIdSchema.parse('db_other'),
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        readDatabaseRecoveryKitFile(file, secret, {
          ...binding,
          recoverySlotId: keySlotIdSchema.parse('other-slot'),
        }),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      const valid = await readFile(file, 'utf8');
      for (const mutation of [
        valid.replace('"version":1', '"version":2'),
        `${valid}trailing`,
      ]) {
        await writeFile(file, mutation, { mode: 0o600 });
        await expect(
          readDatabaseRecoveryKitFile(file, secret, binding),
        ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
        await expect(readDatabaseRecoveryKitFileBinding(file)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
      }
      await writeFile(file, Buffer.alloc(16_385), { mode: 0o600 });
      await expect(
        readDatabaseRecoveryKitFile(file, secret, binding),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(readDatabaseRecoveryKitFileBinding(file)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
    } finally {
      zeroize(key);
      zeroize(secret);
      zeroize(wrong);
    }
  });

  it('rejects unsafe filesystem states and atomically replaces only an existing target', async () => {
    const file = path();
    const first = generateRecoveryKey();
    const second = generateRecoveryKey();
    const secret = passphrase();
    try {
      await writeDatabaseRecoveryKitFile(file, first, binding, options(secret));
      await expect(
        writeDatabaseRecoveryKitFile(file, second, binding, options(secret)),
      ).rejects.toMatchObject({ code: 'KEY_FILE_ALREADY_EXISTS' });
      if (process.platform !== 'win32') {
        await chmod(file, 0o644);
        await expect(
          readDatabaseRecoveryKitFile(file, secret, binding),
        ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
        await expect(readDatabaseRecoveryKitFileBinding(file)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
        await chmod(file, 0o600);
        const hardlink = path('hardlink');
        await link(file, hardlink);
        await expect(
          readDatabaseRecoveryKitFile(file, secret, binding),
        ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
        await expect(readDatabaseRecoveryKitFileBinding(file)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
        await rm(hardlink);
        const target = path('target');
        await writeFile(target, 'x', { mode: 0o600 });
        const linked = path('link');
        await symlink(target, linked);
        await expect(
          readDatabaseRecoveryKitFile(linked, secret, binding),
        ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
        await expect(readDatabaseRecoveryKitFileBinding(linked)).rejects.toMatchObject({
          code: 'KEY_FILE_UNSAFE',
        });
      }
      await writeDatabaseRecoveryKitFile(
        file,
        second,
        binding,
        options(secret, 'replace'),
      );
      const parsed = await readDatabaseRecoveryKitFile(file, secret, binding);
      try {
        expect(parsed.recoveryKey).toEqual(second);
      } finally {
        zeroize(parsed.recoveryKey);
      }
    } finally {
      zeroize(first);
      zeroize(second);
      zeroize(secret);
    }
  });

  it('rejects database and legacy recovery formats across readers', async () => {
    const databasePath = path('database.recovery');
    const legacyPath = path('legacy.recovery');
    const key = generateRecoveryKey();
    const secret = passphrase();
    try {
      await writeDatabaseRecoveryKitFile(databasePath, key, binding, options(secret));
      await expect(readRecoveryKitFile(databasePath, secret)).rejects.toMatchObject({
        code: 'KEY_FILE_UNSAFE',
      });
      await writeRecoveryKitFile(legacyPath, key, secret, {
        vaultId: vaultIdSchema.parse('vault'),
        recoverySlotId: keySlotIdSchema.parse('legacy-slot'),
      });
      await expect(
        readDatabaseRecoveryKitFile(legacyPath, secret),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
      await expect(
        readDatabaseRecoveryKitFileBinding(legacyPath),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(key);
      zeroize(secret);
    }
  });

  it('rejects authenticated replacement after public pre-binding without exposing ciphertext', async () => {
    const file = path();
    const first = generateRecoveryKey();
    const second = generateRecoveryKey();
    const secret = passphrase();
    const replacementBinding: DatabaseRecoveryBinding = {
      databaseId: databaseIdSchema.parse('db_replaced'),
      recoverySlotId: keySlotIdSchema.parse('replacement-slot'),
    };
    try {
      await writeDatabaseRecoveryKitFile(file, first, binding, options(secret));
      const publicBinding = await readDatabaseRecoveryKitFileBinding(file);
      expect(Object.keys(publicBinding).sort()).toEqual([
        'databaseId',
        'recoverySlotId',
      ]);
      expect(JSON.stringify(publicBinding)).not.toContain('ciphertext');
      await writeDatabaseRecoveryKitFile(
        file,
        second,
        replacementBinding,
        options(secret, 'replace'),
      );
      await expect(
        readDatabaseRecoveryKitFile(file, secret, publicBinding),
      ).rejects.toMatchObject({ code: 'KEY_FILE_UNSAFE' });
    } finally {
      zeroize(first);
      zeroize(second);
      zeroize(secret);
    }
  });

  it('serializes replacement races without ever publishing a partial recovery document', async () => {
    const file = path();
    const first = generateRecoveryKey();
    const second = generateRecoveryKey();
    const third = generateRecoveryKey();
    const secret = passphrase();
    try {
      await writeDatabaseRecoveryKitFile(file, first, binding, options(secret));
      const results = await Promise.allSettled([
        writeDatabaseRecoveryKitFile(file, second, binding, options(secret, 'replace')),
        writeDatabaseRecoveryKitFile(file, third, binding, options(secret, 'replace')),
      ]);
      expect(results.some((result) => result.status === 'fulfilled')).toBe(true);
      const parsed = await readDatabaseRecoveryKitFile(file, secret, binding);
      try {
        expect([second, third]).toContainEqual(parsed.recoveryKey);
      } finally {
        zeroize(parsed.recoveryKey);
      }
    } finally {
      zeroize(first);
      zeroize(second);
      zeroize(third);
      zeroize(secret);
    }
  });
});
