import { createHash, timingSafeEqual } from 'node:crypto';

import type {
  PersistedAttachmentChunkRecord,
  PersistedAttachmentHeaderRecord,
  EncryptedAttachmentRecord,
  EncryptedGroupRecord,
  EncryptedItemRecord,
  VaultRecord,
} from './encrypted-records.js';
import { sha256DigestSchema, type Sha256Digest } from './primitives.js';

export type HashableOpaqueRecord =
  VaultRecord | EncryptedGroupRecord | EncryptedItemRecord | EncryptedAttachmentRecord;

/**
 * Deterministic JSON used only for canonical wire-contract digests. Inputs must
 * already have crossed their runtime-schema boundary.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('Canonical JSON rejects non-finite numbers.');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  if (typeof value !== 'object') {
    throw new TypeError('Canonical JSON accepts only JSON values.');
  }

  const prototype = Object.getPrototypeOf(value) as object | null;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError('Canonical JSON rejects non-plain objects.');
  }
  const object = value as Readonly<Record<string, unknown>>;
  return `{${Object.keys(object)
    .sort()
    .filter((key) => object[key] !== undefined)
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
    .join(',')}}`;
}

/** The single digest contract used by sync producers and consumers. */
export function contentHashForRecord(record: HashableOpaqueRecord): Sha256Digest {
  if ('ciphertextHash' in record) {
    return sha256DigestSchema.parse(record.ciphertextHash);
  }
  return sha256DigestSchema.parse(
    createHash('sha256').update(canonicalJson(record), 'utf8').digest('base64url'),
  );
}

/** Digest of the exact opaque attachment chunk bytes carried over storage/HTTP. */
export function attachmentChunkCiphertextHash(
  chunk: PersistedAttachmentChunkRecord,
): Sha256Digest {
  return sha256DigestSchema.parse(
    createHash('sha256')
      .update(Buffer.from(chunk.record.ciphertext, 'base64url'))
      .digest('base64url'),
  );
}

/** Digest of the canonical persisted secretstream header identity and bytes. */
export function attachmentHeaderContentHash(
  header: PersistedAttachmentHeaderRecord,
): Sha256Digest {
  return sha256DigestSchema.parse(
    createHash('sha256')
      .update(canonicalJson(header.record), 'utf8')
      .digest('base64url'),
  );
}

/** Constant-time comparison of an attachment record's advertised and canonical digest. */
export function attachmentRecordHashMatchesCanonicalContent(
  record: PersistedAttachmentHeaderRecord | PersistedAttachmentChunkRecord,
): boolean {
  const canonical =
    record.entityType === 'attachment-header'
      ? attachmentHeaderContentHash(record)
      : attachmentChunkCiphertextHash(record);
  const supplied =
    record.entityType === 'attachment-header'
      ? record.contentHash
      : record.ciphertextHash;
  return timingSafeEqual(
    Buffer.from(canonical, 'base64url'),
    Buffer.from(supplied, 'base64url'),
  );
}
