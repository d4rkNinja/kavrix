import { createHash } from 'node:crypto';

import {
  attachmentSecretStreamManifestSchema,
  attachmentSecretStreamRecordSchema,
  attachmentIdSchema,
  associatedDataSchema,
  itemIdSchema,
  MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES,
  type AssociatedData,
  type AttachmentSecretStreamManifest,
  type AttachmentSecretStreamRecord,
} from '@kavrix/schemas';
import sodium from 'libsodium-wrappers';

import { canonicalAttachmentChunkData } from './aead.js';
import {
  constantTimeEqual,
  copyBytes,
  decodeBase64Url,
  encodeBase64Url,
  requireByteLength,
  zeroize,
} from './bytes.js';
import { AuthenticationError, CryptoInputError } from './errors.js';

// Eight MiB leaves room for secretstream overhead within the canonical schema's
// encoded ciphertext limit.
export const MAX_ATTACHMENT_CHUNK_BYTES = MAX_ATTACHMENT_CHUNK_PLAINTEXT_BYTES;
export const MAX_ATTACHMENT_CHUNKS = 1_000_000;
export const MAX_ATTACHMENT_TOTAL_BYTES = 4 * 1024 * 1024 * 1024;

export interface AttachmentStreamLimits {
  readonly maximumChunkBytes: number;
  readonly maximumChunks: number;
  readonly maximumTotalBytes: number;
}

export interface AttachmentPlaintextStager {
  readonly write: (chunk: Uint8Array) => void | Promise<void>;
  readonly commit: () => void | Promise<void>;
  readonly abort: () => void | Promise<void>;
}

export interface AttachmentEncryptedRecordStager {
  readonly write: (record: AttachmentSecretStreamRecord) => void | Promise<void>;
  readonly commit: (manifest: AttachmentSecretStreamManifest) => void | Promise<void>;
  readonly abort: () => void | Promise<void>;
}

type SecretStreamState = ReturnType<
  typeof sodium.crypto_secretstream_xchacha20poly1305_init_pull
>;

interface RawSodiumRuntime {
  readonly HEAPU8: Uint8Array;
  readonly _crypto_secretstream_xchacha20poly1305_statebytes: () => number;
  readonly _free: (address: number) => void;
}

type AttachmentChunkContext = Extract<
  AssociatedData,
  { readonly entityType: 'attachment-chunk' }
>;
type StreamIdentity = Omit<
  Extract<AttachmentSecretStreamRecord, { readonly recordType: 'header' }>,
  'recordType' | 'header'
>;

export async function* encryptAttachmentStream(
  plaintextChunks: Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
  attachmentKey: Uint8Array,
  context: AssociatedData,
  limitOverrides: Partial<AttachmentStreamLimits> = {},
): AsyncGenerator<AttachmentSecretStreamRecord, AttachmentSecretStreamManifest, void> {
  const parsedContext = validateAttachmentContext(context);
  requireByteLength(attachmentKey, 32, 'attachment key');
  const limits = resolveLimits(limitOverrides);
  await sodium.ready;
  const initialized =
    sodium.crypto_secretstream_xchacha20poly1305_init_push(attachmentKey);
  const hash = createHash('sha256');
  let pending: Uint8Array | undefined;
  try {
    const headerRecord = attachmentSecretStreamRecordSchema.parse({
      ...streamIdentity(parsedContext),
      recordType: 'header',
      header: encodeBase64Url(initialized.header),
    });
    if (headerRecord.recordType !== 'header') {
      throw new CryptoInputError('Invalid secretstream header');
    }
    yield headerRecord;

    let totalBytes = 0;
    let chunkCount = 0;
    for await (const callerPlaintext of plaintextChunks) {
      validatePlaintextChunk(callerPlaintext, limits);
      if (chunkCount >= limits.maximumChunks) {
        throw new CryptoInputError('Attachment has too many chunks');
      }

      // Own the bytes before advancing the producer. Producers may mutate or
      // reuse their buffers as soon as yield resumes.
      const ownedPlaintext = copyBytes(callerPlaintext);
      let retained = false;
      try {
        totalBytes = checkedTotal(totalBytes, ownedPlaintext.byteLength, limits);
        chunkCount += 1;
        hash.update(ownedPlaintext);
        if (pending !== undefined) {
          const toEncrypt = pending;
          pending = ownedPlaintext;
          retained = true;
          try {
            yield encryptChunk(
              initialized.state,
              toEncrypt,
              parsedContext,
              chunkCount - 2,
              false,
            );
          } finally {
            zeroize(toEncrypt);
          }
        } else {
          pending = ownedPlaintext;
          retained = true;
        }
      } finally {
        if (!retained) {
          zeroize(ownedPlaintext);
        }
      }
    }

    const finalPlaintext = pending ?? new Uint8Array();
    pending = undefined;
    try {
      yield encryptChunk(
        initialized.state,
        finalPlaintext,
        parsedContext,
        Math.max(0, chunkCount - 1),
        true,
      );
    } finally {
      zeroize(finalPlaintext);
    }

    const digest = hash.digest();
    try {
      return attachmentSecretStreamManifestSchema.parse({
        ...streamIdentity(parsedContext),
        manifestVersion: 1,
        header: headerRecord.header,
        chunkCount: Math.max(1, chunkCount),
        totalPlaintextBytes: totalBytes,
        plaintextSha256: encodeBase64Url(digest),
      });
    } finally {
      zeroize(digest);
    }
  } finally {
    zeroize(pending);
    clearAndFreeSecretStreamState(initialized.state);
  }
}

/**
 * Encrypts into a staging sink and commits the canonical manifest only after
 * every record has been written and the stream has produced its FINAL tag.
 * The sink must keep staged records invisible until commit.
 */
export async function encryptAttachmentStreamToStager(
  plaintextChunks: Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
  attachmentKey: Uint8Array,
  context: AssociatedData,
  stager: AttachmentEncryptedRecordStager,
  limitOverrides: Partial<AttachmentStreamLimits> = {},
): Promise<AttachmentSecretStreamManifest> {
  const stream = encryptAttachmentStream(
    plaintextChunks,
    attachmentKey,
    context,
    limitOverrides,
  );
  try {
    for (;;) {
      const next = await stream.next();
      if (next.done) {
        const manifest = Object.freeze(
          attachmentSecretStreamManifestSchema.parse(next.value),
        );
        await stager.commit(manifest);
        return manifest;
      }
      await stager.write(Object.freeze(next.value));
    }
  } catch (error) {
    try {
      await stream.return(undefined as never);
    } finally {
      await stager.abort();
    }
    throw error;
  }
}

/**
 * Yields provisionally authenticated plaintext chunks. Consumers must not make
 * them visible or durable until the generator reaches authenticated completion.
 * Prefer decryptAttachmentStreamToStager for a stage-and-commit boundary.
 */
export async function* decryptAttachmentStream(
  encryptedRecords:
    | Iterable<AttachmentSecretStreamRecord>
    | AsyncIterable<AttachmentSecretStreamRecord>,
  attachmentKey: Uint8Array,
  context: AssociatedData,
  limitOverrides: Partial<AttachmentStreamLimits> = {},
): AsyncGenerator<Uint8Array, void, void> {
  let state: SecretStreamState | undefined;
  let expectedIndex = 0;
  let totalBytes = 0;
  let finalSeen = false;
  try {
    const parsedContext = validateAttachmentContext(context);
    requireByteLength(attachmentKey, 32, 'attachment key');
    const limits = resolveLimits(limitOverrides);
    await sodium.ready;

    for await (const unknownRecord of encryptedRecords) {
      if (state === undefined) {
        const headerRecord = validateHeaderRecord(unknownRecord, parsedContext);
        const header = decodeBase64Url(headerRecord.header, {
          exactBytes: sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES,
        });
        try {
          state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(
            header,
            attachmentKey,
          );
        } finally {
          zeroize(header);
        }
        continue;
      }

      if (finalSeen || expectedIndex >= limits.maximumChunks) {
        throw new AuthenticationError();
      }
      const chunkRecord = validateChunkRecord(
        unknownRecord,
        parsedContext,
        expectedIndex,
      );
      const ciphertext = decodeBase64Url(chunkRecord.ciphertext, {
        maximumBytes:
          limits.maximumChunkBytes +
          sodium.crypto_secretstream_xchacha20poly1305_ABYTES,
      });
      const aad = canonicalAttachmentChunkData(parsedContext, expectedIndex);
      try {
        if (
          ciphertext.byteLength < sodium.crypto_secretstream_xchacha20poly1305_ABYTES
        ) {
          throw new AuthenticationError();
        }
        const pulled = sodium.crypto_secretstream_xchacha20poly1305_pull(
          state,
          ciphertext,
          aad,
        );
        if (pulled === false) {
          throw new AuthenticationError();
        }
        totalBytes = checkedTotal(totalBytes, pulled.message.byteLength, limits);
        if (
          pulled.tag !== sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE &&
          pulled.tag !== sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        ) {
          zeroize(pulled.message);
          throw new AuthenticationError();
        }
        const pulledTag =
          pulled.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
            ? 'final'
            : 'message';
        if (chunkRecord.tag !== pulledTag) {
          zeroize(pulled.message);
          throw new AuthenticationError();
        }
        finalSeen =
          pulled.tag === sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
        expectedIndex += 1;
        yield pulled.message;
      } finally {
        zeroize(ciphertext);
        zeroize(aad);
      }
    }

    if (state === undefined || !finalSeen || expectedIndex === 0) {
      throw new AuthenticationError();
    }
  } catch {
    throw new AuthenticationError();
  } finally {
    if (state !== undefined) {
      clearAndFreeSecretStreamState(state);
    }
  }
}

/**
 * Stages provisional plaintext and commits only after the FINAL tag and the
 * encrypted manifest's count, size, header, and plaintext hash all authenticate.
 */
export async function decryptAttachmentStreamToStager(
  encryptedRecords:
    | Iterable<AttachmentSecretStreamRecord>
    | AsyncIterable<AttachmentSecretStreamRecord>,
  attachmentKey: Uint8Array,
  context: AssociatedData,
  manifest: AttachmentSecretStreamManifest,
  stager: AttachmentPlaintextStager,
  limitOverrides: Partial<AttachmentStreamLimits> = {},
): Promise<void> {
  let chunkCount = 0;
  let totalBytes = 0;
  const hash = createHash('sha256');
  let firstRecord: AttachmentSecretStreamRecord | undefined;
  try {
    const parsedContext = validateAttachmentContext(context);
    const parsedManifest = attachmentSecretStreamManifestSchema.parse(manifest);
    verifyStreamIdentity(parsedManifest, parsedContext);

    async function* observeRecords(): AsyncGenerator<AttachmentSecretStreamRecord> {
      for await (const record of encryptedRecords) {
        firstRecord ??= record;
        yield record;
      }
    }

    for await (const plaintext of decryptAttachmentStream(
      observeRecords(),
      attachmentKey,
      parsedContext,
      limitOverrides,
    )) {
      try {
        chunkCount += 1;
        totalBytes += plaintext.byteLength;
        hash.update(plaintext);
        await stager.write(plaintext);
      } finally {
        zeroize(plaintext);
      }
    }

    const headerRecord = attachmentSecretStreamRecordSchema.safeParse(firstRecord);
    const digest = hash.digest();
    const expectedDigest = decodeBase64Url(parsedManifest.plaintextSha256, {
      exactBytes: 32,
    });
    try {
      if (
        !headerRecord.success ||
        headerRecord.data.recordType !== 'header' ||
        parsedManifest.header !== headerRecord.data.header ||
        parsedManifest.chunkCount !== chunkCount ||
        parsedManifest.totalPlaintextBytes !== totalBytes ||
        !constantTimeEqual(digest, expectedDigest)
      ) {
        throw new AuthenticationError();
      }
    } finally {
      zeroize(digest);
      zeroize(expectedDigest);
    }
    await stager.commit();
  } catch {
    await stager.abort();
    throw new AuthenticationError();
  }
}

export function parseAttachmentStreamRecord(
  value: unknown,
): AttachmentSecretStreamRecord {
  return attachmentSecretStreamRecordSchema.parse(value);
}

function encryptChunk(
  state: SecretStreamState,
  plaintext: Uint8Array,
  context: AttachmentChunkContext,
  index: number,
  final: boolean,
): AttachmentSecretStreamRecord {
  const aad = canonicalAttachmentChunkData(context, index);
  try {
    const ciphertext = sodium.crypto_secretstream_xchacha20poly1305_push(
      state,
      plaintext,
      aad,
      final
        ? sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE,
    );
    try {
      return attachmentSecretStreamRecordSchema.parse({
        ...streamIdentity(context),
        recordType: 'chunk',
        index,
        ciphertext: encodeBase64Url(ciphertext),
        tag: final ? 'final' : 'message',
      });
    } finally {
      zeroize(ciphertext);
    }
  } finally {
    zeroize(aad);
  }
}

function validateAttachmentContext(context: AssociatedData): AttachmentChunkContext {
  const parsed = associatedDataSchema.parse(context);
  if (parsed.entityType !== 'attachment-chunk') {
    throw new CryptoInputError('Invalid attachment stream context');
  }
  return parsed;
}

function streamIdentity(context: AttachmentChunkContext): StreamIdentity {
  return {
    version: 1,
    algorithm: 'secretstream-xchacha20-poly1305',
    streamVersion: 1,
    schemaVersion: context.schemaVersion,
    keyVersion: context.keyVersion,
    vaultId: context.vaultId,
    groupId: context.groupId,
    itemId: itemIdSchema.parse(context.parentId),
    attachmentId: attachmentIdSchema.parse(context.entityId),
  };
}

function verifyStreamIdentity(
  record: {
    readonly version: 1;
    readonly algorithm: 'secretstream-xchacha20-poly1305';
    readonly streamVersion: 1;
    readonly schemaVersion: number;
    readonly keyVersion: number;
    readonly vaultId: string;
    readonly groupId: string;
    readonly itemId: string;
    readonly attachmentId: string;
  },
  context: AttachmentChunkContext,
): void {
  const expected = streamIdentity(context);
  if (
    record.schemaVersion !== expected.schemaVersion ||
    record.keyVersion !== expected.keyVersion ||
    record.vaultId !== expected.vaultId ||
    record.groupId !== expected.groupId ||
    record.itemId !== expected.itemId ||
    record.attachmentId !== expected.attachmentId
  ) {
    throw new AuthenticationError();
  }
}

function validatePlaintextChunk(
  plaintext: unknown,
  limits: AttachmentStreamLimits,
): asserts plaintext is Uint8Array {
  if (
    !(plaintext instanceof Uint8Array) ||
    plaintext.byteLength > limits.maximumChunkBytes
  ) {
    throw new CryptoInputError('Attachment chunk is too large');
  }
}

function validateHeaderRecord(
  record: unknown,
  context: AttachmentChunkContext,
): Extract<AttachmentSecretStreamRecord, { readonly recordType: 'header' }> {
  const parsed = attachmentSecretStreamRecordSchema.parse(record);
  if (parsed.recordType !== 'header') {
    throw new AuthenticationError();
  }
  verifyStreamIdentity(parsed, context);
  return parsed;
}

function validateChunkRecord(
  record: unknown,
  context: AttachmentChunkContext,
  expectedIndex: number,
): Extract<AttachmentSecretStreamRecord, { readonly recordType: 'chunk' }> {
  const parsed = attachmentSecretStreamRecordSchema.parse(record);
  if (parsed.recordType !== 'chunk' || parsed.index !== expectedIndex) {
    throw new AuthenticationError();
  }
  verifyStreamIdentity(parsed, context);
  return parsed;
}

function resolveLimits(
  overrides: Partial<AttachmentStreamLimits>,
): AttachmentStreamLimits {
  const limits = {
    maximumChunkBytes: overrides.maximumChunkBytes ?? MAX_ATTACHMENT_CHUNK_BYTES,
    maximumChunks: overrides.maximumChunks ?? MAX_ATTACHMENT_CHUNKS,
    maximumTotalBytes: overrides.maximumTotalBytes ?? MAX_ATTACHMENT_TOTAL_BYTES,
  };
  if (
    !isPositiveBoundedInteger(limits.maximumChunkBytes, MAX_ATTACHMENT_CHUNK_BYTES) ||
    !isPositiveBoundedInteger(limits.maximumChunks, MAX_ATTACHMENT_CHUNKS) ||
    !isPositiveBoundedInteger(limits.maximumTotalBytes, MAX_ATTACHMENT_TOTAL_BYTES)
  ) {
    throw new CryptoInputError('Invalid attachment stream limits');
  }
  return limits;
}

function checkedTotal(
  current: number,
  added: number,
  limits: AttachmentStreamLimits,
): number {
  const next = current + added;
  if (!Number.isSafeInteger(next) || next > limits.maximumTotalBytes) {
    throw new CryptoInputError('Attachment exceeds the total byte limit');
  }
  return next;
}

function isPositiveBoundedInteger(value: number, maximum: number): boolean {
  return Number.isSafeInteger(value) && value >= 1 && value <= maximum;
}

function clearAndFreeSecretStreamState(state: SecretStreamState): void {
  const runtime = (sodium as unknown as { readonly libsodium?: RawSodiumRuntime })
    .libsodium;
  if (runtime === undefined) {
    throw new CryptoInputError('Libsodium runtime is unavailable');
  }
  const stateBytes = runtime._crypto_secretstream_xchacha20poly1305_statebytes();
  const address = state as unknown as number;
  runtime.HEAPU8.fill(0, address, address + stateBytes);
  runtime._free(address);
}
