import {
  MAX_ATTACHMENT_CHUNKS,
  MAX_ATTACHMENT_STREAM_CIPHERTEXT_BYTES,
  MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES,
  SECRETSTREAM_CHUNK_OVERHEAD_BYTES,
  attachmentStreamFinalizeInputSchema,
  attachmentStreamProgressSchema,
  attachmentStreamStartInputSchema,
  persistedAttachmentChunkRecordSchema,
  type AttachmentStreamFinalizeInput,
  type AttachmentStreamProgress,
  type AttachmentStreamStartInput,
  type PersistedAttachmentChunkRecord,
} from '@kavrix/schemas';

import { ValidationError } from '../errors.js';

export function createAttachmentStagingProgress(): AttachmentStreamProgress {
  return attachmentStreamProgressSchema.parse({
    version: 1,
    state: 'empty',
    nextChunkIndex: 0,
    totalPlaintextBytes: 0,
    totalCiphertextBytes: 0,
  });
}

export function advanceAttachmentStaging(
  startInput: AttachmentStreamStartInput,
  currentProgress: AttachmentStreamProgress,
  chunkInput: PersistedAttachmentChunkRecord,
): Readonly<{
  disposition: 'staged' | 'idempotent-retry';
  progress: AttachmentStreamProgress;
}> {
  const start = attachmentStreamStartInputSchema.parse(startInput);
  const progress = attachmentStreamProgressSchema.parse(currentProgress);
  const chunk = persistedAttachmentChunkRecordSchema.parse(chunkInput);
  assertChunkBinding(start, chunk);

  if (progress.state !== 'empty' && chunk.record.index === progress.lastChunkIndex) {
    const expectedTag = progress.state === 'ready-to-finalize' ? 'final' : 'message';
    if (
      chunk.ciphertextHash === progress.lastChunkCiphertextHash &&
      chunk.plaintextBytes === progress.lastChunkPlaintextBytes &&
      chunk.record.tag === expectedTag
    ) {
      return { disposition: 'idempotent-retry', progress };
    }
    throw new ValidationError(
      'A repeated attachment chunk index must exactly match the staged chunk.',
    );
  }

  if (progress.state === 'ready-to-finalize') {
    throw new ValidationError('No attachment chunk may follow the final chunk.');
  }
  if (chunk.record.index !== progress.nextChunkIndex) {
    throw new ValidationError('Attachment chunks must be staged contiguously.');
  }
  if (
    chunk.record.index === MAX_ATTACHMENT_CHUNKS - 1 &&
    chunk.record.tag !== 'final'
  ) {
    throw new ValidationError('The maximum numbered attachment chunk must be final.');
  }

  const ciphertextBytes = chunk.plaintextBytes + SECRETSTREAM_CHUNK_OVERHEAD_BYTES;
  const totalPlaintextBytes = progress.totalPlaintextBytes + chunk.plaintextBytes;
  const totalCiphertextBytes = progress.totalCiphertextBytes + ciphertextBytes;
  if (totalPlaintextBytes > MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES) {
    throw new ValidationError('Attachment plaintext exceeds the stream protocol cap.');
  }
  if (totalCiphertextBytes > MAX_ATTACHMENT_STREAM_CIPHERTEXT_BYTES) {
    throw new ValidationError('Attachment ciphertext exceeds the stream protocol cap.');
  }

  return {
    disposition: 'staged',
    progress: attachmentStreamProgressSchema.parse({
      version: 1,
      state: chunk.record.tag === 'final' ? 'ready-to-finalize' : 'writing',
      nextChunkIndex: progress.nextChunkIndex + 1,
      totalPlaintextBytes,
      totalCiphertextBytes,
      lastChunkIndex: chunk.record.index,
      lastChunkCiphertextHash: chunk.ciphertextHash,
      lastChunkPlaintextBytes: chunk.plaintextBytes,
    }),
  };
}

export function validateAttachmentStagingFinalization(
  startInput: AttachmentStreamStartInput,
  progressInput: AttachmentStreamProgress,
  finalizeInput: AttachmentStreamFinalizeInput,
): void {
  const start = attachmentStreamStartInputSchema.parse(startInput);
  const progress = attachmentStreamProgressSchema.parse(progressInput);
  const finalize = attachmentStreamFinalizeInputSchema.parse(finalizeInput);
  if (progress.state !== 'ready-to-finalize') {
    throw new ValidationError(
      'An attachment stream requires exactly one final chunk before publication.',
    );
  }

  const header = start.header.record;
  const record = finalize.record;
  if (
    record.id !== header.attachmentId ||
    record.vaultId !== header.vaultId ||
    record.groupId !== header.groupId ||
    record.itemId !== header.itemId ||
    record.schemaVersion !== header.schemaVersion ||
    record.wrappedAttachmentKey.keyVersion !== header.keyVersion ||
    record.encryptedManifest.keyVersion !== header.keyVersion ||
    record.recordRevision !== start.header.recordRevision
  ) {
    throw new ValidationError(
      'Final attachment metadata must match the staged stream identity and version.',
    );
  }
  if (record.chunkCount !== progress.nextChunkIndex) {
    throw new ValidationError(
      'Final attachment metadata must declare the exact staged chunk count.',
    );
  }
}

function assertChunkBinding(
  start: AttachmentStreamStartInput,
  chunk: PersistedAttachmentChunkRecord,
): void {
  const header = start.header.record;
  const record = chunk.record;
  if (
    record.schemaVersion !== header.schemaVersion ||
    record.keyVersion !== header.keyVersion ||
    record.vaultId !== header.vaultId ||
    record.groupId !== header.groupId ||
    record.itemId !== header.itemId ||
    record.attachmentId !== header.attachmentId ||
    chunk.recordRevision !== start.header.recordRevision
  ) {
    throw new ValidationError(
      'Attachment chunk identity and versions must match the staged header.',
    );
  }
}
