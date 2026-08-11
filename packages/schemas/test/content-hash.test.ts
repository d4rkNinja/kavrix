import { describe, expect, it } from 'vitest';

import {
  attachmentChunkCiphertextHash,
  attachmentHeaderContentHash,
  attachmentRecordHashMatchesCanonicalContent,
  canonicalJson,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  sha256DigestSchema,
  type PersistedAttachmentChunkRecord,
  type PersistedAttachmentHeaderRecord,
} from '../src/index.js';

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
