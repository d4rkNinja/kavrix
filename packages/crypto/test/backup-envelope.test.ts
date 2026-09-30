import { describe, expect, it } from 'vitest';

import { databaseIdSchema } from '@kavrix/schemas';

import { AuthenticationError, CryptoInputError } from '../src/errors.js';
import {
  openDatabaseBackupArchive,
  parseDatabaseBackupArchive,
  sealDatabaseBackupArchive,
} from '../src/backup-envelope.js';

const PASSPHRASE = (): Uint8Array => new TextEncoder().encode('backup-passphrase-16b');
const HEADER = {
  datastore: 'file' as const,
  databaseId: databaseIdSchema.parse('db_test123'),
};

function serialize(archive: object): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(archive));
}

describe('database backup archive', () => {
  it('round-trips one database file', async () => {
    const plaintext = new TextEncoder().encode('encrypted-database-file-bytes');
    const archive = await sealDatabaseBackupArchive(plaintext, PASSPHRASE(), HEADER);
    expect(archive.format).toBe('kavrix-database-backup');
    expect(archive.version).toBe(1);
    expect(archive.datastore).toBe('file');
    expect(archive.databaseId).toBe(HEADER.databaseId);
    expect(archive.plaintextBytes).toBe(plaintext.byteLength);
    const parsed = parseDatabaseBackupArchive(serialize(archive));
    const opened = await openDatabaseBackupArchive(parsed, PASSPHRASE());
    expect(Buffer.from(opened.plaintext).toString('utf8')).toBe(
      'encrypted-database-file-bytes',
    );
    expect(opened.header.databaseId).toBe(HEADER.databaseId);
  });

  it('rejects a wrong passphrase with a generic authentication error', async () => {
    const archive = await sealDatabaseBackupArchive(
      new TextEncoder().encode('canary'),
      PASSPHRASE(),
      HEADER,
    );
    const parsed = parseDatabaseBackupArchive(serialize(archive));
    await expect(
      openDatabaseBackupArchive(
        parsed,
        new TextEncoder().encode('wrong-passphrase-16'),
      ),
    ).rejects.toThrow(AuthenticationError);
  });

  it('fails closed when the ciphertext is modified', async () => {
    const archive = await sealDatabaseBackupArchive(
      new TextEncoder().encode('canary'),
      PASSPHRASE(),
      HEADER,
    );
    const bytes = Buffer.from(archive.ciphertext, 'base64url');
    bytes[0] = (bytes[0] ?? 0) ^ 0x20;
    archive.ciphertext = bytes.toString('base64url');
    const parsed = parseDatabaseBackupArchive(serialize(archive));
    await expect(openDatabaseBackupArchive(parsed, PASSPHRASE())).rejects.toThrow(
      AuthenticationError,
    );
  });

  it('fails closed when the authentication tag is modified', async () => {
    const archive = await sealDatabaseBackupArchive(
      new TextEncoder().encode('canary'),
      PASSPHRASE(),
      HEADER,
    );
    const bytes = Buffer.from(archive.authenticationTag, 'base64url');
    bytes[0] = (bytes[0] ?? 0) ^ 0x08;
    archive.authenticationTag = bytes.toString('base64url');
    const parsed = parseDatabaseBackupArchive(serialize(archive));
    await expect(openDatabaseBackupArchive(parsed, PASSPHRASE())).rejects.toThrow(
      AuthenticationError,
    );
  });

  it('fails closed when a header field is transplanted (AAD binding)', async () => {
    const archive = await sealDatabaseBackupArchive(
      new TextEncoder().encode('canary'),
      PASSPHRASE(),
      HEADER,
    );
    archive.databaseId = databaseIdSchema.parse('db_other456');
    const parsed = parseDatabaseBackupArchive(serialize(archive));
    await expect(openDatabaseBackupArchive(parsed, PASSPHRASE())).rejects.toThrow(
      AuthenticationError,
    );
  });

  it('fails closed when the declared length does not match the ciphertext', async () => {
    const archive = await sealDatabaseBackupArchive(
      new TextEncoder().encode('canary-value'),
      PASSPHRASE(),
      HEADER,
    );
    archive.plaintextBytes = archive.plaintextBytes - 1;
    const parsed = parseDatabaseBackupArchive(serialize(archive));
    await expect(openDatabaseBackupArchive(parsed, PASSPHRASE())).rejects.toThrow(
      AuthenticationError,
    );
  });

  it('rejects unknown formats, versions, and malformed documents before any key work', () => {
    expect(() =>
      parseDatabaseBackupArchive(new TextEncoder().encode('not json')),
    ).toThrow(CryptoInputError);
    expect(() =>
      parseDatabaseBackupArchive(new TextEncoder().encode('{"format":"other"}')),
    ).toThrow();
    expect(() =>
      parseDatabaseBackupArchive(
        new TextEncoder().encode(
          '{"format":"kavrix-database-backup","version":2,"createdAt":"2026-01-01T00:00:00.000Z","datastore":"file","databaseId":"db_x","plaintextBytes":1,"derivation":{},"nonce":"","authenticationTag":"","ciphertext":""}',
        ),
      ),
    ).toThrow();
  });

  it('rejects unknown top-level fields in a well-formed archive shell', async () => {
    const archive = await sealDatabaseBackupArchive(
      new TextEncoder().encode('canary'),
      PASSPHRASE(),
      HEADER,
    );
    const extended = { ...archive, extra: 'field' };
    expect(() => parseDatabaseBackupArchive(serialize(extended))).toThrow();
  });

  it('rejects plaintext outside the supported range', async () => {
    await expect(
      sealDatabaseBackupArchive(new Uint8Array(0), PASSPHRASE(), HEADER),
    ).rejects.toThrow(CryptoInputError);
  });
});
