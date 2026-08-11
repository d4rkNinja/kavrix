import {
  MAX_ATTACHMENT_STREAM_CIPHERTEXT_BYTES,
  MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES,
  MAX_ATTACHMENT_CHUNKS,
  apiBearerTokenSchema,
  attachmentChunkCiphertextHash,
  attachmentHeaderContentHash,
  attachmentChunkStageRequestSchema,
  attachmentFinalizeRequestSchema,
  attachmentStreamProgressSchema,
  attachmentStreamStartInputSchema,
  attachmentTransferPathSchema,
  encryptedAttachmentRecordSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  type ApiBearerToken,
  type AttachmentStreamFinalizeInput,
  type AttachmentStreamProgress,
  type AttachmentStreamStartInput,
  type AttachmentTransferPath,
  type EncryptedAttachmentRecord,
  type PersistedAttachmentChunkRecord,
  type PersistedAttachmentHeaderRecord,
} from '@kavrix/schemas';
import { SyncProtocolError } from '@kavrix/sync';

import { SecureFetchClient, type SecureFetchOptions } from './secure-fetch.js';
import { throwMappedSecureFetchError } from './secure-fetch-sync-errors.js';

export type AttachmentTransferTransportOptions = SecureFetchOptions &
  Readonly<{ bearerToken: ApiBearerToken }>;

/** Opaque HTTPS attachment transfer. It never accepts or returns plaintext keys. */
export class AttachmentTransferTransport {
  readonly #fetch: SecureFetchClient;
  readonly #bearerToken: ApiBearerToken;

  constructor(options: AttachmentTransferTransportOptions) {
    this.#fetch = new SecureFetchClient(options);
    const token = apiBearerTokenSchema.safeParse(options.bearerToken);
    if (!token.success) throw new TypeError('The bearer token is invalid.');
    this.#bearerToken = token.data;
  }

  async open(
    startValue: AttachmentStreamStartInput,
  ): Promise<AttachmentStreamProgress> {
    const start = parseStart(startValue);
    const value = await this.#requestJson({
      method: 'POST',
      path: [...attachmentPath(start), 'stream', 'open'],
      expectedStatus: 200,
      bearerToken: this.#bearerToken,
      body: JSON.stringify(start),
    });
    return parseProgress(value);
  }

  async stageChunk(
    startValue: AttachmentStreamStartInput,
    chunkValue: PersistedAttachmentChunkRecord,
  ): Promise<AttachmentStreamProgress> {
    const request = attachmentChunkStageRequestSchema.safeParse({
      start: startValue,
      chunk: chunkValue,
    });
    if (
      !request.success ||
      attachmentChunkCiphertextHash(request.data.chunk) !==
        request.data.chunk.ciphertextHash
    ) {
      throw new SyncProtocolError();
    }
    const value = await this.#requestJson({
      method: 'PUT',
      path: [
        ...attachmentPath(request.data.start),
        'stream',
        'chunks',
        String(request.data.chunk.record.index),
      ],
      expectedStatus: 200,
      bearerToken: this.#bearerToken,
      body: JSON.stringify(request.data),
    });
    return parseStagedProgress(value, request.data.chunk);
  }

  async finalize(
    startValue: AttachmentStreamStartInput,
    finalizeValue: AttachmentStreamFinalizeInput,
  ): Promise<void> {
    const request = attachmentFinalizeRequestSchema.safeParse({
      start: startValue,
      finalize: finalizeValue,
    });
    if (!request.success) throw new SyncProtocolError();
    await this.#requestEmpty({
      method: 'POST',
      path: [...attachmentPath(request.data.start), 'stream', 'finalize'],
      expectedStatus: 204,
      bearerToken: this.#bearerToken,
      body: JSON.stringify(request.data),
    });
  }

  async abort(startValue: AttachmentStreamStartInput): Promise<void> {
    const start = parseStart(startValue);
    await this.#requestEmpty({
      method: 'POST',
      path: [...attachmentPath(start), 'stream', 'abort'],
      expectedStatus: 204,
      bearerToken: this.#bearerToken,
      body: JSON.stringify(start),
    });
  }

  async getMetadata(
    pathValue: AttachmentTransferPath,
  ): Promise<EncryptedAttachmentRecord> {
    const path = parsePath(pathValue);
    const value = await this.#requestJson({
      method: 'GET',
      path: attachmentPath(path),
      expectedStatus: 200,
      bearerToken: this.#bearerToken,
    });
    const parsed = encryptedAttachmentRecordSchema.safeParse(value);
    if (
      !parsed.success ||
      parsed.data.vaultId !== path.vaultId ||
      parsed.data.groupId !== path.groupId ||
      parsed.data.itemId !== path.itemId ||
      parsed.data.id !== path.attachmentId ||
      parsed.data.tombstonedAt !== undefined
    ) {
      throw new SyncProtocolError();
    }
    return parsed.data;
  }

  async getHeader(
    pathValue: AttachmentTransferPath,
  ): Promise<PersistedAttachmentHeaderRecord> {
    const path = parsePath(pathValue);
    const value = await this.#requestJson({
      method: 'GET',
      path: [...attachmentPath(path), 'header'],
      expectedStatus: 200,
      bearerToken: this.#bearerToken,
    });
    const parsed = persistedAttachmentHeaderRecordSchema.safeParse(value);
    if (
      !parsed.success ||
      !recordMatchesPath(parsed.data.record, path) ||
      attachmentHeaderContentHash(parsed.data) !== parsed.data.contentHash
    ) {
      throw new SyncProtocolError();
    }
    return parsed.data;
  }

  async getChunk(
    pathValue: AttachmentTransferPath,
    chunkIndex: number,
  ): Promise<PersistedAttachmentChunkRecord> {
    const path = parsePath(pathValue);
    if (
      !Number.isSafeInteger(chunkIndex) ||
      chunkIndex < 0 ||
      chunkIndex >= MAX_ATTACHMENT_CHUNKS
    ) {
      throw new SyncProtocolError();
    }
    const value = await this.#requestJson({
      method: 'GET',
      path: [...attachmentPath(path), 'chunks', String(chunkIndex)],
      expectedStatus: 200,
      bearerToken: this.#bearerToken,
    });
    const parsed = persistedAttachmentChunkRecordSchema.safeParse(value);
    if (
      !parsed.success ||
      parsed.data.record.index !== chunkIndex ||
      !recordMatchesPath(parsed.data.record, path) ||
      attachmentChunkCiphertextHash(parsed.data) !== parsed.data.ciphertextHash
    ) {
      throw new SyncProtocolError();
    }
    return parsed.data;
  }

  async *download(
    pathValue: AttachmentTransferPath,
  ): AsyncGenerator<
    PersistedAttachmentHeaderRecord | PersistedAttachmentChunkRecord,
    void,
    void
  > {
    const path = parsePath(pathValue);
    const metadata = await this.getMetadata(path);
    if (
      metadata.wrappedAttachmentKey.keyVersion !== metadata.encryptedManifest.keyVersion
    ) {
      throw new SyncProtocolError();
    }
    const header = await this.getHeader(path);
    if (
      header.recordRevision !== metadata.recordRevision ||
      header.record.schemaVersion !== metadata.schemaVersion ||
      header.record.keyVersion !== metadata.encryptedManifest.keyVersion
    ) {
      throw new SyncProtocolError();
    }
    yield header;
    let totalPlaintextBytes = 0;
    let totalCiphertextBytes = 0;
    for (let index = 0; index < metadata.chunkCount; index += 1) {
      const chunk = await this.getChunk(path, index);
      if (
        chunk.recordRevision !== metadata.recordRevision ||
        chunk.record.schemaVersion !== metadata.schemaVersion ||
        chunk.record.keyVersion !== metadata.encryptedManifest.keyVersion ||
        chunk.record.tag !== (index === metadata.chunkCount - 1 ? 'final' : 'message')
      ) {
        throw new SyncProtocolError();
      }
      const totals = advanceAttachmentDownloadTotals(
        totalPlaintextBytes,
        totalCiphertextBytes,
        chunk,
      );
      totalPlaintextBytes = totals.totalPlaintextBytes;
      totalCiphertextBytes = totals.totalCiphertextBytes;
      yield chunk;
    }
  }

  async #requestJson(
    options: Parameters<SecureFetchClient['requestJson']>[0],
  ): Promise<unknown> {
    try {
      return await this.#fetch.requestJson(options);
    } catch (error) {
      throwMappedSecureFetchError(error);
    }
  }

  async #requestEmpty(
    options: Parameters<SecureFetchClient['requestEmpty']>[0],
  ): Promise<void> {
    try {
      await this.#fetch.requestEmpty(options);
    } catch (error) {
      throwMappedSecureFetchError(error);
    }
  }
}

export function advanceAttachmentDownloadTotals(
  currentPlaintextBytes: number,
  currentCiphertextBytes: number,
  chunk: PersistedAttachmentChunkRecord,
): Readonly<{ totalPlaintextBytes: number; totalCiphertextBytes: number }> {
  if (
    !Number.isSafeInteger(currentPlaintextBytes) ||
    currentPlaintextBytes < 0 ||
    !Number.isSafeInteger(currentCiphertextBytes) ||
    currentCiphertextBytes < 0
  ) {
    throw new SyncProtocolError();
  }
  const totalPlaintextBytes = currentPlaintextBytes + chunk.plaintextBytes;
  const totalCiphertextBytes =
    currentCiphertextBytes +
    Buffer.from(chunk.record.ciphertext, 'base64url').byteLength;
  if (
    totalPlaintextBytes > MAX_ATTACHMENT_STREAM_PLAINTEXT_BYTES ||
    totalCiphertextBytes > MAX_ATTACHMENT_STREAM_CIPHERTEXT_BYTES
  ) {
    throw new SyncProtocolError();
  }
  return { totalPlaintextBytes, totalCiphertextBytes };
}

function parseStart(value: AttachmentStreamStartInput): AttachmentStreamStartInput {
  const parsed = attachmentStreamStartInputSchema.safeParse(value);
  if (
    !parsed.success ||
    attachmentHeaderContentHash(parsed.data.header) !== parsed.data.header.contentHash
  ) {
    throw new SyncProtocolError();
  }
  return parsed.data;
}

function parseProgress(value: unknown): AttachmentStreamProgress {
  const parsed = attachmentStreamProgressSchema.safeParse(value);
  if (!parsed.success) throw new SyncProtocolError();
  return parsed.data;
}

function parseStagedProgress(
  value: unknown,
  chunk: PersistedAttachmentChunkRecord,
): AttachmentStreamProgress {
  const progress = parseProgress(value);
  if (
    progress.state === 'empty' ||
    progress.lastChunkIndex !== chunk.record.index ||
    progress.nextChunkIndex !== chunk.record.index + 1 ||
    progress.lastChunkCiphertextHash !== chunk.ciphertextHash ||
    progress.lastChunkPlaintextBytes !== chunk.plaintextBytes ||
    progress.state !== (chunk.record.tag === 'final' ? 'ready-to-finalize' : 'writing')
  ) {
    throw new SyncProtocolError();
  }
  return progress;
}

function parsePath(value: AttachmentTransferPath): AttachmentTransferPath {
  const parsed = attachmentTransferPathSchema.safeParse(value);
  if (!parsed.success) throw new SyncProtocolError();
  return parsed.data;
}

function attachmentPath(
  value: AttachmentStreamStartInput | AttachmentTransferPath,
): string[] {
  const source = 'header' in value ? value.header.record : value;
  return [
    'v1',
    'vaults',
    source.vaultId,
    'groups',
    source.groupId,
    'items',
    source.itemId,
    'attachments',
    source.attachmentId,
  ];
}

function recordMatchesPath(
  record: Readonly<{
    vaultId: string;
    groupId: string;
    itemId: string;
    attachmentId: string;
  }>,
  path: AttachmentTransferPath,
): boolean {
  return (
    record.vaultId === path.vaultId &&
    record.groupId === path.groupId &&
    record.itemId === path.itemId &&
    record.attachmentId === path.attachmentId
  );
}
