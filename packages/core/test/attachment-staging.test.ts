import { describe, expect, it } from 'vitest';

import {
  MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES,
  MAX_ATTACHMENT_STREAM_CIPHERTEXT_BYTES,
  MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES,
  attachmentStreamProgressSchema,
  attachmentStreamStartInputSchema,
  attachmentHeaderContentHash,
  encryptedAttachmentRecordSchema,
  groupIdSchema,
  itemIdSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  sha256DigestSchema,
  type AttachmentStreamProgress,
  type AttachmentStreamStartInput,
  type EncryptedAttachmentRecord,
  type PersistedAttachmentChunkRecord,
} from '@kavrix/schemas';

import {
  ValidationError,
  advanceAttachmentStaging,
  createAttachmentStagingProgress,
  validateAttachmentStagingFinalization,
} from '../src/index.js';

const timestamp = '2026-08-10T00:00:00.000Z';
const digest = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

const purposeByEntity: Readonly<Record<string, string>> = {
  attachment: 'attachment-metadata',
  'wrapped-attachment-key': 'attachment-key',
};

function envelope(
  entityType: 'attachment' | 'wrapped-attachment-key',
  keyVersion = 1,
): Record<string, unknown> {
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext: 'AQID',
    authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion,
      vaultId: 'vault.1',
      entityType,
      entityId: 'attachment.1',
      groupId: 'group.1',
      parentId: 'item.1',
      purpose: purposeByEntity[entityType],
    },
    keyVersion,
  };
}

function start(): AttachmentStreamStartInput {
  const header = persistedAttachmentHeaderRecordSchema.parse({
    entityType: 'attachment-header',
    record: {
      version: 1,
      algorithm: 'secretstream-xchacha20-poly1305',
      streamVersion: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: 'vault.1',
      groupId: 'group.1',
      itemId: 'item.1',
      attachmentId: 'attachment.1',
      recordType: 'header',
      header: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
    recordRevision: 0,
    contentHash: digest,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  return attachmentStreamStartInputSchema.parse({
    version: 1,
    idempotencyKey: 'attachment-staging-key-1',
    expectedAttachmentRevision: null,
    header: {
      ...header,
      contentHash: attachmentHeaderContentHash(header),
    },
  });
}

function chunk(
  index: number,
  tag: 'message' | 'final',
  plaintextBytes = 0,
): PersistedAttachmentChunkRecord {
  const identity = start().header.record;
  return persistedAttachmentChunkRecordSchema.parse({
    entityType: 'attachment-chunk',
    record: {
      version: identity.version,
      algorithm: identity.algorithm,
      streamVersion: identity.streamVersion,
      schemaVersion: identity.schemaVersion,
      keyVersion: identity.keyVersion,
      vaultId: identity.vaultId,
      groupId: identity.groupId,
      itemId: identity.itemId,
      attachmentId: identity.attachmentId,
      recordType: 'chunk',
      index,
      ciphertext: Buffer.alloc(plaintextBytes + 17).toString('base64url'),
      tag,
    },
    plaintextBytes,
    recordRevision: 0,
    ciphertextHash: digest,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

function finalRecord(chunkCount: number): EncryptedAttachmentRecord {
  return encryptedAttachmentRecordSchema.parse({
    id: 'attachment.1',
    vaultId: 'vault.1',
    groupId: 'group.1',
    itemId: 'item.1',
    schemaVersion: 1,
    wrappedAttachmentKey: envelope('wrapped-attachment-key'),
    encryptedManifest: envelope('attachment'),
    chunkCount,
    recordRevision: 0,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

describe('incremental attachment staging policy', () => {
  it('rejects a caller-supplied hash that does not cover the exact header', () => {
    const valid = start();
    const malformed = {
      ...valid,
      header: { ...valid.header, contentHash: digest },
    };
    expect(attachmentStreamStartInputSchema.safeParse(malformed).success).toBe(false);
    expect(() =>
      advanceAttachmentStaging(
        malformed as AttachmentStreamStartInput,
        createAttachmentStagingProgress(),
        chunk(0, 'final'),
      ),
    ).toThrow();
  });

  it('resumes from persisted progress and accepts an idempotent retry', () => {
    const first = advanceAttachmentStaging(
      start(),
      createAttachmentStagingProgress(),
      chunk(0, 'message', 3),
    );
    expect(first.disposition).toBe('staged');

    const retry = advanceAttachmentStaging(
      start(),
      first.progress,
      chunk(0, 'message', 3),
    );
    expect(retry).toEqual({
      disposition: 'idempotent-retry',
      progress: first.progress,
    });

    const resumedProgress = attachmentStreamProgressSchema.parse(
      JSON.parse(JSON.stringify(first.progress)),
    );
    const final = advanceAttachmentStaging(
      start(),
      resumedProgress,
      chunk(1, 'final', 2),
    );
    expect(final.progress.state).toBe('ready-to-finalize');
    expect(() => {
      validateAttachmentStagingFinalization(start(), final.progress, {
        version: 1,
        record: finalRecord(2),
      });
    }).not.toThrow();
  });

  it('fails closed on gaps, replacements, writes after final, and count mismatch', () => {
    const empty = createAttachmentStagingProgress();
    expect(() => advanceAttachmentStaging(start(), empty, chunk(1, 'message'))).toThrow(
      ValidationError,
    );

    const first = advanceAttachmentStaging(start(), empty, chunk(0, 'message', 1));
    expect(() =>
      advanceAttachmentStaging(start(), first.progress, {
        ...chunk(0, 'message', 1),
        ciphertextHash: sha256DigestSchema.parse(
          'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE',
        ),
      }),
    ).toThrow(ValidationError);

    const final = advanceAttachmentStaging(start(), first.progress, chunk(1, 'final'));
    expect(() =>
      advanceAttachmentStaging(start(), final.progress, chunk(2, 'final')),
    ).toThrow(ValidationError);
    expect(() => {
      validateAttachmentStagingFinalization(start(), final.progress, {
        version: 1,
        record: finalRecord(1),
      });
    }).toThrow(ValidationError);
  });

  it('binds every chunk and final record to the staged identity and revision', () => {
    expect(() =>
      advanceAttachmentStaging(start(), createAttachmentStagingProgress(), {
        ...chunk(0, 'final'),
        record: {
          ...chunk(0, 'final').record,
          itemId: itemIdSchema.parse('item.other'),
        },
      }),
    ).toThrow(ValidationError);

    const final = advanceAttachmentStaging(
      start(),
      createAttachmentStagingProgress(),
      chunk(0, 'final'),
    );
    expect(() => {
      validateAttachmentStagingFinalization(start(), final.progress, {
        version: 1,
        record: {
          ...finalRecord(1),
          groupId: groupIdSchema.parse('group.other'),
        },
      });
    }).toThrow();
  });

  it('rejects split and header-mismatched attachment key versions', () => {
    const final = advanceAttachmentStaging(
      start(),
      createAttachmentStagingProgress(),
      chunk(0, 'final'),
    );
    const base = finalRecord(1);
    const splitRecord = {
      ...base,
      wrappedAttachmentKey: envelope('wrapped-attachment-key', 2),
    } as EncryptedAttachmentRecord;
    const headerMismatchedRecord = encryptedAttachmentRecordSchema.parse({
      ...base,
      wrappedAttachmentKey: envelope('wrapped-attachment-key', 2),
      encryptedManifest: envelope('attachment', 2),
    });

    expect(() => {
      validateAttachmentStagingFinalization(start(), final.progress, {
        version: 1,
        record: splitRecord,
      });
    }).toThrow();
    expect(() => {
      validateAttachmentStagingFinalization(start(), final.progress, {
        version: 1,
        record: headerMismatchedRecord,
      });
    }).toThrow(ValidationError);
  });

  it('enforces aggregate protocol caps from counters without large allocations', () => {
    const nearPlaintextCap: AttachmentStreamProgress =
      attachmentStreamProgressSchema.parse({
        version: 1,
        state: 'writing',
        nextChunkIndex: 512,
        totalPlaintextBytes: MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES,
        totalCiphertextBytes: MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES + 512 * 17,
        lastChunkIndex: 511,
        lastChunkCiphertextHash: digest,
        lastChunkPlaintextBytes: MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES,
      });
    expect(() =>
      advanceAttachmentStaging(start(), nearPlaintextCap, chunk(512, 'final', 1)),
    ).toThrow(ValidationError);

    expect(
      attachmentStreamProgressSchema.safeParse({
        version: 1,
        state: 'writing',
        nextChunkIndex: 512,
        totalPlaintextBytes: MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES,
        totalCiphertextBytes: MAX_ATTACHMENT_STREAM_CIPHERTEXT_BYTES + 1,
        lastChunkIndex: 511,
        lastChunkCiphertextHash: digest,
        lastChunkPlaintextBytes: MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES,
      }).success,
    ).toBe(false);

    const nearChunkCap = attachmentStreamProgressSchema.parse({
      version: 1,
      state: 'writing',
      nextChunkIndex: 999_999,
      totalPlaintextBytes: 0,
      totalCiphertextBytes: 999_999 * 17,
      lastChunkIndex: 999_998,
      lastChunkCiphertextHash: digest,
      lastChunkPlaintextBytes: 0,
    });
    expect(() =>
      advanceAttachmentStaging(start(), nearChunkCap, chunk(999_999, 'message')),
    ).toThrow(ValidationError);
  });
});
