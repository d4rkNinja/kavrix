import { describe, expect, it } from 'vitest';

import {
  attachmentChunkCiphertextHash,
  attachmentHeaderContentHash,
  attachmentRecordHashMatchesCanonicalContent,
  canonicalJson,
  createBackupStagedEntryCommitment,
  encryptedBackupEntrySchema,
  MAX_CANONICAL_BACKUP_ENTRY_BYTES,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  sha256DigestSchema,
  type EncryptedBackupEntry,
  type PersistedAttachmentChunkRecord,
  type PersistedAttachmentHeaderRecord,
} from '../src/index.js';

const DIGEST = Buffer.alloc(32, 0x11).toString('base64url');

describe('canonical JSON', () => {
  it('sorts object keys recursively while preserving array order', () => {
    expect(
      canonicalJson({ z: true, a: [{ y: 2, x: 1 }, null], omitted: undefined }),
    ).toBe('{"a":[{"x":1,"y":2},null],"z":true}');
  });

  it('rejects values outside the JSON wire domain', () => {
    expect(() => canonicalJson(Number.POSITIVE_INFINITY)).toThrow(TypeError);
    expect(() => canonicalJson(undefined)).toThrow(TypeError);
    expect(() => canonicalJson(new Date('2026-08-10T00:00:00.000Z'))).toThrow(
      TypeError,
    );
  });
});

describe('canonical attachment hashes', () => {
  it.each(['header', 'chunk'] as const)(
    'constant-compares the advertised %s hash with carried content',
    (kind) => {
      const record = attachmentRecord(kind);
      expect(attachmentRecordHashMatchesCanonicalContent(record)).toBe(true);

      const wrongHash = sha256DigestSchema.parse(
        Buffer.alloc(32, 0xff).toString('base64url'),
      );
      const mismatched =
        record.entityType === 'attachment-header'
          ? { ...record, contentHash: wrongHash }
          : { ...record, ciphertextHash: wrongHash };
      expect(attachmentRecordHashMatchesCanonicalContent(mismatched)).toBe(false);
    },
  );
});

describe('backup staged-entry commitment', () => {
  const first = tombstoneEntry('group.1', 1);
  const second = tombstoneEntry('group.2', 2);

  it('matches the frozen ordered canonical-entry golden vector', () => {
    const commitment = createBackupStagedEntryCommitment();
    commitment.update(first);
    commitment.update(second);
    expect(commitment.finalize()).toBe('qusZFkz3E05O8NeqbzyhrDZ7av2_6-oxjQFY2gxhX2E');
  });

  it('is streaming-equivalent and sensitive to entry order and content', () => {
    const digest = (...entries: EncryptedBackupEntry[]): string => {
      const commitment = createBackupStagedEntryCommitment();
      for (const entry of entries) commitment.update(entry);
      return commitment.finalize();
    };

    expect(digest(first, second)).toBe(digest(...[first, second]));
    expect(digest(first, second)).not.toBe(digest(second, first));
    expect(digest(first, second)).not.toBe(digest(first, tombstoneEntry('group.2', 3)));
  });

  it('enforces exact configured and supported maximum canonical lengths', () => {
    const entryBytes = Buffer.byteLength(canonicalJson(first), 'utf8');
    const exact = createBackupStagedEntryCommitment({
      maximumEntryBytes: entryBytes,
    });
    exact.update(first);
    expect(exact.finalize()).toHaveLength(43);

    const oneByteShort = createBackupStagedEntryCommitment({
      maximumEntryBytes: entryBytes - 1,
    });
    expect(() => {
      oneByteShort.update(first);
    }).toThrow(RangeError);

    const supportedMaximum = createBackupStagedEntryCommitment({
      maximumEntryBytes: MAX_CANONICAL_BACKUP_ENTRY_BYTES,
    });
    supportedMaximum.update(first);
    expect(supportedMaximum.finalize()).toHaveLength(43);
  });

  it('rejects invalid configured limits and all updates after one-shot finalization', () => {
    for (const maximumEntryBytes of [
      0,
      1.5,
      MAX_CANONICAL_BACKUP_ENTRY_BYTES + 1,
      Number.MAX_SAFE_INTEGER + 1,
    ]) {
      expect(() => createBackupStagedEntryCommitment({ maximumEntryBytes })).toThrow(
        RangeError,
      );
    }

    const commitment = createBackupStagedEntryCommitment();
    commitment.update(first);
    commitment.finalize();
    expect(() => commitment.finalize()).toThrow(Error);
    expect(() => {
      commitment.update(second);
    }).toThrow(Error);
  });
});

function attachmentRecord(
  kind: 'header' | 'chunk',
): PersistedAttachmentHeaderRecord | PersistedAttachmentChunkRecord {
  const identity = {
    version: 1,
    algorithm: 'secretstream-xchacha20-poly1305',
    streamVersion: 1,
    schemaVersion: 1,
    keyVersion: 1,
    vaultId: 'vault.1',
    groupId: 'group.1',
    itemId: 'item.1',
    attachmentId: 'attachment.1',
  } as const;
  const placeholder = sha256DigestSchema.parse(Buffer.alloc(32).toString('base64url'));
  if (kind === 'header') {
    const base = persistedAttachmentHeaderRecordSchema.parse({
      entityType: 'attachment-header',
      record: {
        ...identity,
        recordType: 'header',
        header: Buffer.alloc(24).toString('base64url'),
      },
      recordRevision: 0,
      contentHash: placeholder,
      createdAt: '2026-08-10T00:00:00.000Z',
      updatedAt: '2026-08-10T00:00:00.000Z',
    });
    return persistedAttachmentHeaderRecordSchema.parse({
      ...base,
      contentHash: attachmentHeaderContentHash(base),
    });
  }
  const base = persistedAttachmentChunkRecordSchema.parse({
    entityType: 'attachment-chunk',
    record: {
      ...identity,
      recordType: 'chunk',
      index: 0,
      ciphertext: Buffer.alloc(17).toString('base64url'),
      tag: 'final',
    },
    plaintextBytes: 0,
    recordRevision: 0,
    ciphertextHash: placeholder,
    createdAt: '2026-08-10T00:00:00.000Z',
    updatedAt: '2026-08-10T00:00:00.000Z',
  });
  return persistedAttachmentChunkRecordSchema.parse({
    ...base,
    ciphertextHash: attachmentChunkCiphertextHash(base),
  });
}

function tombstoneEntry(
  entityId: string,
  tombstoneRevision: number,
): EncryptedBackupEntry {
  return encryptedBackupEntrySchema.parse({
    kind: 'tombstone',
    record: {
      entityType: 'group',
      entityId,
      vaultId: 'vault.1',
      state: 'deleted',
      tombstoneRevision,
      lastRecordRevision: tombstoneRevision - 1,
      lastCiphertextHash: DIGEST,
      deletedAt: '2026-08-12T00:00:00.000Z',
    },
  });
}
