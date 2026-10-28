import { describe, expect, it } from 'vitest';
import { databaseIdSchema } from '@kavrix/schemas';
import {
  sealDatabaseBackupArchive,
  openDatabaseBackupArchive,
} from '../src/backup-envelope.js';

describe('firewall backup version binding', () => {
  it('separates full bundles from legacy byte-only backup semantics', async () => {
    const passphrase = new TextEncoder().encode('firewall-backup-envelope-passphrase');
    const archive = await sealDatabaseBackupArchive(
      new TextEncoder().encode('encrypted-record-fixture'),
      passphrase,
      {
        datastore: 'file',
        databaseId: databaseIdSchema.parse('db_firewall'),
        version: 2,
      },
    );
    expect(archive.version).toBe(2);
    expect((await openDatabaseBackupArchive(archive, passphrase)).plaintext).toEqual(
      new TextEncoder().encode('encrypted-record-fixture'),
    );
    await expect(
      openDatabaseBackupArchive({ ...archive, version: 1 }, passphrase),
    ).rejects.toThrow();
  });
});
