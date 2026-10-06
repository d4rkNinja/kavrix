import { createHash, timingSafeEqual } from 'node:crypto';

import type { EncryptedBackupEntry } from './backup.js';
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

export const MAX_CANONICAL_BACKUP_ENTRY_BYTES = 0xffff_ffff;
const BACKUP_STAGED_ENTRIES_DOMAIN = Buffer.from(
  'kavrix/backup-staged-entries/v1',
  'utf8',
);

export type BackupStagedEntryCommitment = Readonly<{
  update(entry: EncryptedBackupEntry): void;
  finalize(): Sha256Digest;
}>;

/**
 * Ordered canonical commitment used to bind entries after strict backup-schema
 * parsing. Callers must pass the parsed value, not the untrusted input object.
 */
export function createBackupStagedEntryCommitment(options?: {
  readonly maximumEntryBytes?: number;
}): BackupStagedEntryCommitment {
  const maximumEntryBytes =
    options?.maximumEntryBytes ?? MAX_CANONICAL_BACKUP_ENTRY_BYTES;
  if (
    !Number.isSafeInteger(maximumEntryBytes) ||
    maximumEntryBytes < 1 ||
    maximumEntryBytes > MAX_CANONICAL_BACKUP_ENTRY_BYTES
  ) {
    throw new RangeError(
      'Canonical backup entry limit is outside the supported range.',
    );
  }

  const hash = createHash('sha256').update(BACKUP_STAGED_ENTRIES_DOMAIN);
  let finalized = false;
  return {
    update(entryInput): void {
      if (finalized) {
        throw new Error('Backup staged-entry commitment is already finalized.');
      }
      const bytes = Buffer.from(canonicalJson(entryInput), 'utf8');
      if (bytes.byteLength > maximumEntryBytes) {
        throw new RangeError('Canonical backup entry exceeds the supported limit.');
      }
      const length = Buffer.allocUnsafe(4);
      try {
        length.writeUInt32BE(bytes.byteLength);
        hash.update(length).update(bytes);
      } finally {
        length.fill(0);
        bytes.fill(0);
      }
    },
    finalize(): Sha256Digest {
      if (finalized) {
        throw new Error('Backup staged-entry commitment is already finalized.');
      }
      finalized = true;
      return sha256DigestSchema.parse(hash.digest('base64url'));
    },
  };
}

/**
 * Object keys that need no JSON escaping. Quoting such a key directly is
 * byte-identical to `JSON.stringify` on it, and canonical objects are dominated
 * by keys of this shape.
 */
const UNESCAPED_KEY = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;

/**
 * Deterministic JSON used only for canonical wire-contract digests. Inputs must
 * already have crossed their runtime-schema boundary.
 *
 * Canonicalization runs on every persisted digest and on every protected
 * document read and write, so it accumulates work through string building
 * rather than intermediate arrays: one array per level is enough to collect
 * sibling values, and each level sorts its keys once. Output is byte-identical
 * to a straightforward map/filter/join formulation.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return 'null';
  const kind = typeof value;
  if (kind === 'string' || kind === 'boolean') {
    return JSON.stringify(value);
  }
  if (kind === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('Canonical JSON rejects non-finite numbers.');
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    let out = '[';
    for (let index = 0; index < value.length; index += 1) {
      if (index > 0) out += ',';
      out += canonicalJson(value[index]);
    }
    return `${out}]`;
  }
  if (kind !== 'object') {
    throw new TypeError('Canonical JSON accepts only JSON values.');
  }

  const prototype = Object.getPrototypeOf(value) as object | null;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError('Canonical JSON rejects non-plain objects.');
  }
  const object = value as Readonly<Record<string, unknown>>;
  const keys = Object.keys(object);
  // Present in insertion order more often than not, because schemas build their
  // output in a fixed order; only pay for a sort when the order actually differs.
  if (!isSorted(keys)) keys.sort();

  let out = '';
  let written = 0;
  for (const key of keys) {
    const entry = object[key];
    if (entry === undefined) continue;
    if (written > 0) out += ',';
    out += UNESCAPED_KEY.test(key) ? `"${key}"` : JSON.stringify(key);
    out += ':';
    out += canonicalJson(entry);
    written += 1;
  }
  return `{${out}}`;
}

function isSorted(keys: readonly string[]): boolean {
  let previous: string | undefined;
  for (const key of keys) {
    if (previous !== undefined && previous > key) return false;
    previous = key;
  }
  return true;
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
