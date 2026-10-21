import fc from 'fast-check';
import { describe, expect, it } from 'vitest';

import type { VaultExportEntry } from '@kavrix/schemas';

import { AuthenticationError, CryptoInputError } from '../src/errors.js';
import {
  openVaultExportArchive,
  parseVaultExportArchive,
  sealVaultExportArchive,
} from '../src/vault-export-envelope.js';
import { sealDatabaseBackupArchive } from '../src/backup-envelope.js';
import { databaseIdSchema } from '@kavrix/schemas';

const PASSPHRASE = (): Uint8Array => new TextEncoder().encode('export-passphrase-16b');
const AT = '2026-10-21T00:00:00.000Z';
const CANARY = 'vault-export-plaintext-canary-91f2';

function entries(): VaultExportEntry[] {
  return [
    { name: 'prod/DATABASE_URL', value: CANARY, updatedAt: AT },
    { name: 'API_KEY', value: 'multi\nline\nvalue', updatedAt: AT },
  ];
}

function serialize(archive: object): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(archive));
}

describe('vault export archive', () => {
  it('round-trips entries without exposing plaintext in the archive', async () => {
    const archive = await sealVaultExportArchive(entries(), PASSPHRASE());
    const bytes = serialize(archive);
    expect(Buffer.from(bytes).toString('utf8')).not.toContain(CANARY);
    expect(Buffer.from(bytes).toString('utf8')).not.toContain('DATABASE_URL');
    expect(archive.entryCount).toBe(2);
    const opened = await openVaultExportArchive(
      parseVaultExportArchive(bytes),
      PASSPHRASE(),
    );
    expect(opened.entries).toEqual(entries());
  });

  it('rejects a wrong passphrase generically', async () => {
    const archive = await sealVaultExportArchive(entries(), PASSPHRASE());
    await expect(
      openVaultExportArchive(archive, new TextEncoder().encode('wrong-passphrase-16')),
    ).rejects.toThrow(AuthenticationError);
  });

  it('fails authentication when any header field is altered', async () => {
    const archive = await sealVaultExportArchive(entries(), PASSPHRASE());
    for (const tampered of [
      { ...archive, createdAt: '2027-01-01T00:00:00.000Z' },
      { ...archive, entryCount: 1 },
    ]) {
      await expect(openVaultExportArchive(tampered, PASSPHRASE())).rejects.toThrow(
        AuthenticationError,
      );
    }
  });

  it('fails authentication when any ciphertext bit flips', async () => {
    const archive = await sealVaultExportArchive(entries(), PASSPHRASE());
    const ciphertext = Buffer.from(archive.ciphertext, 'base64url');
    await fc.assert(
      fc.asyncProperty(
        fc.integer({ min: 0, max: ciphertext.byteLength * 8 - 1 }),
        async (bit) => {
          const flipped = Buffer.from(ciphertext);
          flipped[bit >> 3] = (flipped[bit >> 3] ?? 0) ^ (1 << (bit & 7));
          await expect(
            openVaultExportArchive(
              { ...archive, ciphertext: flipped.toString('base64url') },
              PASSPHRASE(),
            ),
          ).rejects.toThrow(AuthenticationError);
        },
      ),
      { numRuns: 8 },
    );
  });

  it('cannot be confused with a database backup archive', async () => {
    const backup = await sealDatabaseBackupArchive(
      new TextEncoder().encode('{"entries":[]}'),
      PASSPHRASE(),
      { datastore: 'file', databaseId: databaseIdSchema.parse('db_test123') },
    );
    expect(() => parseVaultExportArchive(serialize(backup))).toThrow(CryptoInputError);
  });

  it('rejects malformed archive documents before key derivation', () => {
    for (const bytes of [
      new TextEncoder().encode('not json'),
      serialize({ format: 'kavrix-vault-export' }),
    ]) {
      expect(() => parseVaultExportArchive(bytes)).toThrow(CryptoInputError);
    }
  });

  it('refuses duplicate or empty entry sets at seal time', async () => {
    await expect(sealVaultExportArchive([], PASSPHRASE())).rejects.toThrow();
    const [first] = entries();
    if (first === undefined) throw new Error('fixture');
    await expect(
      sealVaultExportArchive([first, first], PASSPHRASE()),
    ).rejects.toThrow();
  });
});
