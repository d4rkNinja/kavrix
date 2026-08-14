import { createHash, createHmac, hkdfSync } from 'node:crypto';

import {
  canonicalJson,
  keySlotIdSchema,
  keySlotSchema,
  portableKeyRotationCheckpointSchema,
  portableKeyRotationCheckpointPayloadSchema,
  sha256DigestSchema,
  vaultIdSchema,
  vaultRevisionSchema,
  type KeySlot,
  type KeySlotId,
  type PortableKeyRotationCheckpoint,
  type PortableKeyRotationCheckpointPayload,
  type PortableKeyRotationState,
  type Sha256Digest,
  type VaultId,
  type VaultRevision,
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

const CHECKPOINT_DOMAIN = Buffer.from(
  'credvault/portable-key-rotation-checkpoint/v1\0',
  'ascii',
);
const TRANSCRIPT_DOMAIN = Buffer.from(
  'credvault/portable-key-rotation-transcript/v1\0',
  'ascii',
);
const SLOT_DIGEST_DOMAIN = Buffer.from(
  'credvault/portable-key-rotation-slot/v1\0',
  'ascii',
);
const AUTH_INFO = Buffer.from(
  'credvault/v1/portable-key-rotation-checkpoint-auth',
  'ascii',
);
const ZERO_SALT = Buffer.alloc(32);
const OPERATION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._~-]{15,127}$/u;

export interface PortableKeyRotationCheckpointExpectation {
  readonly vaultId: VaultId;
  readonly operationId: string;
  readonly sourceSlotId: KeySlotId;
  readonly replacementSlotId: KeySlotId;
  readonly sourceRevision: VaultRevision;
  readonly sourceSlotDigest: Sha256Digest;
  readonly replacementSlotDigest: Sha256Digest;
}

export function portableKeyRotationSlotDigest(slot: KeySlot): Sha256Digest {
  const parsed = (() => {
    try {
      return portableKeyRotationCheckpointSlot(slot);
    } catch {
      throw new CryptoInputError('Invalid portable rotation slot');
    }
  })();
  const normalized = normalizeSlotForRotationDigest(parsed);
  const digest = createHash('sha256')
    .update(SLOT_DIGEST_DOMAIN)
    .update(canonicalJson(normalized), 'utf8')
    .digest();
  try {
    return sha256DigestSchema.parse(encodeBase64Url(digest));
  } finally {
    zeroize(digest);
  }
}

function normalizeSlotForRotationDigest(
  slot: Extract<KeySlot, { readonly type: 'portable-key' }>,
): Extract<KeySlot, { readonly type: 'portable-key' }> {
  const copy = { ...slot } as Record<string, unknown>;
  delete copy['revokedAt'];
  delete copy['supersededAt'];
  copy['state'] = 'active';
  return copy as Extract<KeySlot, { readonly type: 'portable-key' }>;
}

export function createPortableKeyRotationCheckpoint(
  expected: PortableKeyRotationCheckpointExpectation,
  rootKey: VaultRootKey,
): PortableKeyRotationCheckpoint {
  validateExpectation(expected);
  const payload = portableKeyRotationCheckpointPayloadSchema.parse({
    version: 1,
    vaultId: expected.vaultId,
    operationId: expected.operationId,
    sourceSlotId: expected.sourceSlotId,
    replacementSlotId: expected.replacementSlotId,
    sourceRevision: expected.sourceRevision,
    remoteRevision: expected.sourceRevision,
    sourceSlotDigest: expected.sourceSlotDigest,
    replacementSlotDigest: expected.replacementSlotDigest,
    transcriptDigest: initialTranscriptDigest(),
    state: 'prepared',
  });
  return authenticate(payload, rootKey);
}

export function advancePortableKeyRotationCheckpoint(
  checkpoint: unknown,
  rootKey: VaultRootKey,
  expected: PortableKeyRotationCheckpointExpectation,
  state: Exclude<PortableKeyRotationState, 'prepared'>,
  remoteRevision: VaultRevision,
): PortableKeyRotationCheckpoint {
  const payload = verifyPortableKeyRotationCheckpoint(checkpoint, rootKey, expected);
  const nextState = nextRotationState(payload.state);
  if (nextState !== state || remoteRevision !== payload.remoteRevision + 1) {
    throw new CryptoInputError('Invalid portable rotation checkpoint transition');
  }
  const nextPayload = portableKeyRotationCheckpointPayloadSchema.parse({
    ...payload,
    state,
    remoteRevision,
    transcriptDigest: extendTranscriptDigest(
      payload.transcriptDigest,
      state,
      remoteRevision,
    ),
  });
  return authenticate(nextPayload, rootKey);
}

export function verifyPortableKeyRotationCheckpoint(
  checkpoint: unknown,
  rootKey: VaultRootKey,
  expected: PortableKeyRotationCheckpointExpectation,
): PortableKeyRotationCheckpointPayload {
  let suppliedTag: Uint8Array | undefined;
  let expectedTag: Uint8Array | undefined;
  try {
    validateExpectation(expected);
    const parsed = portableKeyRotationCheckpointSchema.parse(checkpoint);
    const payload = parsed.payload;
    if (
      payload.vaultId !== expected.vaultId ||
      payload.operationId !== expected.operationId ||
      payload.sourceSlotId !== expected.sourceSlotId ||
      payload.replacementSlotId !== expected.replacementSlotId ||
      payload.sourceRevision !== expected.sourceRevision ||
      payload.sourceSlotDigest !== expected.sourceSlotDigest ||
      payload.replacementSlotDigest !== expected.replacementSlotDigest
    ) {
      throw new AuthenticationError();
    }
    suppliedTag = decodeBase64Url(parsed.authenticationTag, { exactBytes: 32 });
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
  payload: PortableKeyRotationCheckpointPayload,
  rootKey: VaultRootKey,
): PortableKeyRotationCheckpoint {
  const tag = checkpointTag(payload, rootKey);
  try {
    return portableKeyRotationCheckpointSchema.parse({
      payload,
      authenticationTag: encodeBase64Url(tag),
    });
  } finally {
    zeroize(tag);
  }
}

function checkpointTag(
  payload: PortableKeyRotationCheckpointPayload,
  rootKey: VaultRootKey,
): Uint8Array {
  requireByteLength(rootKey, 32, 'vault root key');
  const keyMaterial = hkdfSync('sha256', rootKey, ZERO_SALT, AUTH_INFO, 32);
  const key = new Uint8Array(keyMaterial);
  const encoded = Buffer.concat([
    CHECKPOINT_DOMAIN,
    Buffer.from(canonicalJson(payload), 'utf8'),
  ]);
  try {
    return Uint8Array.from(createHmac('sha256', key).update(encoded).digest());
  } finally {
    zeroize(key);
    zeroize(encoded);
  }
}

function initialTranscriptDigest(): Sha256Digest {
  const digest = createHash('sha256').update(TRANSCRIPT_DOMAIN).digest();
  try {
    return sha256DigestSchema.parse(encodeBase64Url(digest));
  } finally {
    zeroize(digest);
  }
}

function extendTranscriptDigest(
  previous: Sha256Digest,
  state: PortableKeyRotationState,
  remoteRevision: VaultRevision,
): Sha256Digest {
  const digest = createHash('sha256')
    .update(TRANSCRIPT_DOMAIN)
    .update(canonicalJson({ version: 1, previous, state, remoteRevision }), 'utf8')
    .digest();
  try {
    return sha256DigestSchema.parse(encodeBase64Url(digest));
  } finally {
    zeroize(digest);
  }
}

function validateExpectation(expected: PortableKeyRotationCheckpointExpectation): void {
  if (
    !vaultIdSchema.safeParse(expected.vaultId).success ||
    !OPERATION_ID_PATTERN.test(expected.operationId) ||
    !keySlotIdSchema.safeParse(expected.sourceSlotId).success ||
    !keySlotIdSchema.safeParse(expected.replacementSlotId).success ||
    expected.sourceSlotId === expected.replacementSlotId ||
    !vaultRevisionSchema.safeParse(expected.sourceRevision).success ||
    expected.sourceRevision > Number.MAX_SAFE_INTEGER - 3 ||
    !sha256DigestSchema.safeParse(expected.sourceSlotDigest).success ||
    !sha256DigestSchema.safeParse(expected.replacementSlotDigest).success
  ) {
    throw new CryptoInputError('Invalid portable rotation checkpoint context');
  }
}

function portableKeyRotationCheckpointSlot(
  slot: KeySlot,
): Extract<KeySlot, { readonly type: 'portable-key' }> {
  const parsed = keySlotSchema.parse(slot);
  if (parsed.type !== 'portable-key') {
    throw new CryptoInputError('Invalid slot type');
  }
  return parsed;
}

function nextRotationState(
  state: PortableKeyRotationState,
): Exclude<PortableKeyRotationState, 'prepared'> | null {
  switch (state) {
    case 'prepared':
      return 'pending-published';
    case 'pending-published':
      return 'active-published';
    case 'active-published':
      return 'completed';
    case 'completed':
      return null;
  }
}
