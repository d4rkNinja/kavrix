import { createHash, createHmac, hkdfSync } from 'node:crypto';

import {
  sha256DigestSchema,
  vaultIdSchema,
  type Sha256Digest,
  type VaultId,
} from '@kavrix/schemas';

import {
  constantTimeEqual,
  decodeBase64Url,
  encodeBase64Url,
  requireByteLength,
  zeroize,
} from './bytes.js';
import { AuthenticationError, CryptoInputError } from './errors.js';
import type { VaultRootKey } from './keys.js';

const CHECKPOINT_DOMAIN = Buffer.from('credvault/rotation-checkpoint/v1\0', 'ascii');
const RECORD_SET_DOMAIN = Buffer.from('credvault/rotation-record-set/v2\0', 'ascii');
const TRANSCRIPT_DOMAIN = Buffer.from(
  'credvault/rotation-processed-transcript/v1\0',
  'ascii',
);
const AUTH_INFO = Buffer.from('credvault/v1/rotation-checkpoint-auth', 'ascii');
const ZERO_SALT = Buffer.alloc(32);
const OPAQUE_ID = /^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$/;
const MAX_RECORDS = 1_000_000;

export type RotationKind = 'vault-root' | 'group' | 'item';
export type RotationState = 'pending' | 'running' | 'completed';

export interface RotationSourceRecord {
  readonly recordId: string;
  readonly sourceDigest: Sha256Digest;
}

export interface RotationReplacement {
  readonly recordId: string;
  readonly replacementDigest: Sha256Digest;
}

export interface RotationCheckpointPayload {
  readonly version: 1;
  readonly vaultId: VaultId;
  readonly rotationId: string;
  readonly recordSetDigest: Sha256Digest;
  readonly processedTranscriptDigest: Sha256Digest;
  readonly kind: RotationKind;
  readonly fromKeyVersion: number;
  readonly toKeyVersion: number;
  readonly totalRecords: number;
  readonly nextRecordIndex: number;
  readonly state: RotationState;
}

export interface AuthenticatedRotationCheckpoint {
  readonly payload: RotationCheckpointPayload;
  readonly authenticationTag: string;
}

export interface RotationCheckpointExpectation {
  readonly vaultId: VaultId;
  readonly rotationId: string;
  readonly orderedRecords: readonly RotationSourceRecord[];
}

export function createRotationCheckpoint(
  options: RotationCheckpointExpectation & {
    readonly kind: RotationKind;
    readonly fromKeyVersion: number;
    readonly toKeyVersion: number;
  },
  rootKey: VaultRootKey,
): AuthenticatedRotationCheckpoint {
  validateExpectation(options);
  if (
    !isRotationKind(options.kind) ||
    !isPositiveUint32(options.fromKeyVersion) ||
    !isPositiveUint32(options.toKeyVersion) ||
    options.toKeyVersion <= options.fromKeyVersion
  ) {
    throw new CryptoInputError('Invalid rotation checkpoint');
  }
  return authenticate(
    {
      version: 1,
      vaultId: options.vaultId,
      rotationId: options.rotationId,
      recordSetDigest: recordSetDigest(options.orderedRecords),
      processedTranscriptDigest: initialTranscriptDigest(),
      kind: options.kind,
      fromKeyVersion: options.fromKeyVersion,
      toKeyVersion: options.toKeyVersion,
      totalRecords: options.orderedRecords.length,
      nextRecordIndex: 0,
      state: options.orderedRecords.length === 0 ? 'completed' : 'pending',
    },
    rootKey,
  );
}

export function resumeRotationCheckpoint(
  checkpoint: AuthenticatedRotationCheckpoint,
  rootKey: VaultRootKey,
  expected: RotationCheckpointExpectation,
): AuthenticatedRotationCheckpoint {
  const payload = verifyRotationCheckpoint(checkpoint, rootKey, expected);
  return payload.state === 'pending'
    ? authenticate({ ...payload, state: 'running' }, rootKey)
    : checkpoint;
}

/**
 * Advances exactly the next expected source record. The caller must first
 * durably persist and read-back verify the replacement identified by
 * replacementDigest, then persist the returned checkpoint. The old envelope
 * and old key must remain available until an authenticated completed
 * checkpoint is durable. Cryptographic code cannot prove external durability.
 */
export function advanceRotationCheckpoint(
  checkpoint: AuthenticatedRotationCheckpoint,
  replacement: RotationReplacement,
  rootKey: VaultRootKey,
  expected: RotationCheckpointExpectation,
): AuthenticatedRotationCheckpoint {
  const payload = verifyRotationCheckpoint(checkpoint, rootKey, expected);
  if (payload.state !== 'running') {
    throw new CryptoInputError(
      payload.state === 'completed'
        ? 'Completed rotation cannot advance'
        : 'Rotation must be resumed before it can advance',
    );
  }
  validateReplacement(replacement);
  const source = expected.orderedRecords[payload.nextRecordIndex];
  if (source?.recordId !== replacement.recordId) {
    throw new CryptoInputError('Replacement is not the next expected record');
  }

  const nextRecordIndex = payload.nextRecordIndex + 1;
  return authenticate(
    {
      ...payload,
      processedTranscriptDigest: extendTranscriptDigest(
        payload.processedTranscriptDigest,
        payload.nextRecordIndex,
        source,
        replacement.replacementDigest,
      ),
      nextRecordIndex,
      state: nextRecordIndex === payload.totalRecords ? 'completed' : 'running',
    },
    rootKey,
  );
}

export function verifyRotationCheckpoint(
  checkpoint: unknown,
  rootKey: VaultRootKey,
  expected: RotationCheckpointExpectation,
): RotationCheckpointPayload {
  let suppliedTag: Uint8Array | undefined;
  let expectedTag: Uint8Array | undefined;
  try {
    requireByteLength(rootKey, 32, 'vault root key');
    validateExpectation(expected);
    if (
      typeof checkpoint !== 'object' ||
      checkpoint === null ||
      Object.keys(checkpoint).length !== 2 ||
      !('payload' in checkpoint) ||
      !('authenticationTag' in checkpoint) ||
      typeof checkpoint.authenticationTag !== 'string'
    ) {
      throw new AuthenticationError();
    }
    const payload = validatePayload(checkpoint.payload);
    if (
      payload.vaultId !== expected.vaultId ||
      payload.rotationId !== expected.rotationId ||
      payload.totalRecords !== expected.orderedRecords.length ||
      payload.recordSetDigest !== recordSetDigest(expected.orderedRecords) ||
      (payload.nextRecordIndex === 0 &&
        payload.processedTranscriptDigest !== initialTranscriptDigest())
    ) {
      throw new AuthenticationError();
    }
    suppliedTag = decodeBase64Url(checkpoint.authenticationTag, { exactBytes: 32 });
    expectedTag = checkpointTag(payload, rootKey);
    if (!constantTimeEqual(suppliedTag, expectedTag)) {
      throw new AuthenticationError();
    }
    return payload;
  } catch {
    throw new AuthenticationError();
  } finally {
    zeroize(suppliedTag);
    zeroize(expectedTag);
  }
}

function authenticate(
  payload: RotationCheckpointPayload,
  rootKey: VaultRootKey,
): AuthenticatedRotationCheckpoint {
  const tag = checkpointTag(payload, rootKey);
  try {
    return { payload, authenticationTag: encodeBase64Url(tag) };
  } finally {
    zeroize(tag);
  }
}

function checkpointTag(
  payload: RotationCheckpointPayload,
  rootKey: VaultRootKey,
): Uint8Array {
  requireByteLength(rootKey, 32, 'vault root key');
  const keyMaterial = hkdfSync('sha256', rootKey, ZERO_SALT, AUTH_INFO, 32);
  const key = new Uint8Array(keyMaterial);
  const encoded = encodePayload(payload);
  try {
    return Uint8Array.from(createHmac('sha256', key).update(encoded).digest());
  } finally {
    zeroize(key);
    zeroize(encoded);
  }
}

function recordSetDigest(records: readonly RotationSourceRecord[]): Sha256Digest {
  const hash = createHash('sha256').update(RECORD_SET_DOMAIN).update(uint32(1));
  for (const record of records) {
    hash
      .update(lengthPrefixedAscii(record.recordId))
      .update(lengthPrefixedAscii(record.sourceDigest));
  }
  return finishDigest(hash);
}

function initialTranscriptDigest(): Sha256Digest {
  return finishDigest(createHash('sha256').update(TRANSCRIPT_DOMAIN).update(uint32(1)));
}

function extendTranscriptDigest(
  previousDigest: Sha256Digest,
  recordIndex: number,
  source: RotationSourceRecord,
  replacementDigest: Sha256Digest,
): Sha256Digest {
  return finishDigest(
    createHash('sha256')
      .update(TRANSCRIPT_DOMAIN)
      .update(uint32(1))
      .update(lengthPrefixedAscii(previousDigest))
      .update(uint32(recordIndex))
      .update(lengthPrefixedAscii(source.recordId))
      .update(lengthPrefixedAscii(source.sourceDigest))
      .update(lengthPrefixedAscii(replacementDigest)),
  );
}

function finishDigest(hash: ReturnType<typeof createHash>): Sha256Digest {
  const digest = hash.digest();
  try {
    return sha256DigestSchema.parse(encodeBase64Url(digest));
  } finally {
    zeroize(digest);
  }
}

function encodePayload(payload: RotationCheckpointPayload): Uint8Array {
  return Buffer.concat([
    CHECKPOINT_DOMAIN,
    uint32(payload.version),
    lengthPrefixedAscii(payload.vaultId),
    lengthPrefixedAscii(payload.rotationId),
    lengthPrefixedAscii(payload.recordSetDigest),
    lengthPrefixedAscii(payload.processedTranscriptDigest),
    lengthPrefixedAscii(payload.kind),
    uint32(payload.fromKeyVersion),
    uint32(payload.toKeyVersion),
    uint32(payload.totalRecords),
    uint32(payload.nextRecordIndex),
    lengthPrefixedAscii(payload.state),
  ]);
}

function validatePayload(value: unknown): RotationCheckpointPayload {
  if (typeof value !== 'object' || value === null) {
    throw new AuthenticationError();
  }
  const payload = value as Record<string, unknown>;
  if (
    payload['version'] !== 1 ||
    typeof payload['vaultId'] !== 'string' ||
    !vaultIdSchema.safeParse(payload['vaultId']).success ||
    typeof payload['rotationId'] !== 'string' ||
    !OPAQUE_ID.test(payload['rotationId']) ||
    !isCanonicalDigest(payload['recordSetDigest']) ||
    !isCanonicalDigest(payload['processedTranscriptDigest']) ||
    !isRotationKind(payload['kind']) ||
    !isPositiveUint32(payload['fromKeyVersion']) ||
    !isPositiveUint32(payload['toKeyVersion']) ||
    payload['toKeyVersion'] <= payload['fromKeyVersion'] ||
    !isNonnegativeInteger(payload['totalRecords']) ||
    payload['totalRecords'] > MAX_RECORDS ||
    !isNonnegativeInteger(payload['nextRecordIndex']) ||
    payload['nextRecordIndex'] > payload['totalRecords'] ||
    (payload['state'] !== 'pending' &&
      payload['state'] !== 'running' &&
      payload['state'] !== 'completed') ||
    (payload['state'] === 'pending' &&
      (payload['nextRecordIndex'] !== 0 || payload['totalRecords'] === 0)) ||
    (payload['state'] === 'running' &&
      payload['nextRecordIndex'] >= payload['totalRecords']) ||
    (payload['state'] === 'completed' &&
      payload['nextRecordIndex'] !== payload['totalRecords']) ||
    Object.keys(payload).length !== 11
  ) {
    throw new AuthenticationError();
  }
  return payload as unknown as RotationCheckpointPayload;
}

function validateExpectation(
  value: unknown,
): asserts value is RotationCheckpointExpectation {
  if (
    typeof value !== 'object' ||
    value === null ||
    !('vaultId' in value) ||
    !vaultIdSchema.safeParse(value.vaultId).success ||
    !('rotationId' in value) ||
    typeof value.rotationId !== 'string' ||
    !OPAQUE_ID.test(value.rotationId) ||
    !('orderedRecords' in value) ||
    !Array.isArray(value.orderedRecords) ||
    value.orderedRecords.length > MAX_RECORDS
  ) {
    throw new CryptoInputError('Invalid rotation checkpoint context');
  }
  const seenIds = new Set<string>();
  const records = value.orderedRecords as readonly unknown[];
  for (const record of records) {
    if (
      typeof record !== 'object' ||
      record === null ||
      Object.keys(record).length !== 2 ||
      !('recordId' in record) ||
      typeof record.recordId !== 'string' ||
      !OPAQUE_ID.test(record.recordId) ||
      !('sourceDigest' in record) ||
      !isCanonicalDigest(record.sourceDigest) ||
      seenIds.has(record.recordId)
    ) {
      throw new CryptoInputError('Invalid rotation checkpoint context');
    }
    seenIds.add(record.recordId);
  }
}

function validateReplacement(
  replacement: unknown,
): asserts replacement is RotationReplacement {
  if (
    typeof replacement !== 'object' ||
    replacement === null ||
    Object.keys(replacement).length !== 2 ||
    !('recordId' in replacement) ||
    typeof replacement.recordId !== 'string' ||
    !OPAQUE_ID.test(replacement.recordId) ||
    !('replacementDigest' in replacement) ||
    !isCanonicalDigest(replacement.replacementDigest)
  ) {
    throw new CryptoInputError('Invalid durable rotation replacement');
  }
}

function isCanonicalDigest(value: unknown): value is Sha256Digest {
  if (typeof value !== 'string' || !sha256DigestSchema.safeParse(value).success) {
    return false;
  }
  let decoded: Uint8Array | undefined;
  try {
    decoded = decodeBase64Url(value, { exactBytes: 32 });
    return true;
  } catch {
    return false;
  } finally {
    zeroize(decoded);
  }
}

function lengthPrefixedAscii(value: string): Buffer {
  const bytes = Buffer.from(value, 'ascii');
  return Buffer.concat([uint32(bytes.byteLength), bytes]);
}

function uint32(value: number): Buffer {
  const output = Buffer.allocUnsafe(4);
  output.writeUInt32BE(value);
  return output;
}

function isRotationKind(value: unknown): value is RotationKind {
  return value === 'vault-root' || value === 'group' || value === 'item';
}

function isPositiveUint32(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 1 &&
    value <= 0xff_ff_ff_ff
  );
}

function isNonnegativeInteger(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 0 &&
    value <= 0xff_ff_ff_ff
  );
}
