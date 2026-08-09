import type { AeadEnvelope, AssociatedData } from '@kavrix/schemas';

import { decryptAead, encryptAead } from './aead.js';
import { requireByteLength, zeroize } from './bytes.js';
import { CryptoInputError } from './errors.js';
import type { AttachmentKey, GroupKey, ItemKey, VaultRootKey } from './keys.js';

export async function wrapRootKey(
  rootKey: VaultRootKey,
  keyEncryptionKey: Uint8Array,
  context: AssociatedData,
): Promise<AeadEnvelope> {
  assertEntityType(context, 'wrapped-root-key');
  return encryptAead(rootKey, keyEncryptionKey, context);
}

export async function unwrapRootKey(
  envelope: AeadEnvelope,
  keyEncryptionKey: Uint8Array,
  expectedContext: AssociatedData,
): Promise<VaultRootKey> {
  assertEntityType(expectedContext, 'wrapped-root-key');
  const key = await decryptAead(envelope, keyEncryptionKey, expectedContext);
  requireByteLength(key, 32, 'vault root key');
  return key as VaultRootKey;
}

export async function wrapGroupKey(
  groupKey: GroupKey,
  rootKey: VaultRootKey,
  context: AssociatedData,
): Promise<AeadEnvelope> {
  assertEntityType(context, 'wrapped-group-key');
  return encryptAead(groupKey, rootKey, context);
}

export async function unwrapGroupKey(
  envelope: AeadEnvelope,
  rootKey: VaultRootKey,
  expectedContext: AssociatedData,
): Promise<GroupKey> {
  assertEntityType(expectedContext, 'wrapped-group-key');
  const key = await decryptAead(envelope, rootKey, expectedContext);
  requireByteLength(key, 32, 'group key');
  return key as GroupKey;
}

export async function wrapItemKey(
  itemKey: ItemKey,
  groupKey: GroupKey,
  context: AssociatedData,
): Promise<AeadEnvelope> {
  assertEntityType(context, 'wrapped-item-key');
  return encryptAead(itemKey, groupKey, context);
}

export async function unwrapItemKey(
  envelope: AeadEnvelope,
  groupKey: GroupKey,
  expectedContext: AssociatedData,
): Promise<ItemKey> {
  assertEntityType(expectedContext, 'wrapped-item-key');
  const key = await decryptAead(envelope, groupKey, expectedContext);
  requireByteLength(key, 32, 'item key');
  return key as ItemKey;
}

export async function wrapAttachmentKey(
  attachmentKey: AttachmentKey,
  itemKey: ItemKey,
  context: AssociatedData,
): Promise<AeadEnvelope> {
  assertEntityType(context, 'wrapped-attachment-key');
  return encryptAead(attachmentKey, itemKey, context);
}

export async function unwrapAttachmentKey(
  envelope: AeadEnvelope,
  itemKey: ItemKey,
  expectedContext: AssociatedData,
): Promise<AttachmentKey> {
  assertEntityType(expectedContext, 'wrapped-attachment-key');
  const key = await decryptAead(envelope, itemKey, expectedContext);
  requireByteLength(key, 32, 'attachment key');
  return key as AttachmentKey;
}

export async function encryptPayload(
  plaintext: Uint8Array,
  payloadKey: Uint8Array,
  context: AssociatedData,
): Promise<AeadEnvelope> {
  if (context.entityType.startsWith('wrapped-')) {
    throw new CryptoInputError('A wrapped-key context cannot encrypt a payload');
  }
  return encryptAead(plaintext, payloadKey, context);
}

export async function decryptPayload(
  envelope: AeadEnvelope,
  payloadKey: Uint8Array,
  expectedContext: AssociatedData,
): Promise<Uint8Array> {
  if (expectedContext.entityType.startsWith('wrapped-')) {
    throw new CryptoInputError('A wrapped-key context cannot decrypt a payload');
  }
  return decryptAead(envelope, payloadKey, expectedContext);
}

export async function rewrapKey(
  envelope: AeadEnvelope,
  oldWrappingKey: Uint8Array,
  newWrappingKey: Uint8Array,
  oldContext: AssociatedData,
  newContext: AssociatedData,
): Promise<AeadEnvelope> {
  if (!oldContext.entityType.startsWith('wrapped-')) {
    throw new CryptoInputError('Only wrapped keys may be rewrapped');
  }
  if (newContext.entityType !== oldContext.entityType) {
    throw new CryptoInputError('Rewrap cannot change the wrapped-key type');
  }
  const unwrapped = await decryptAead(envelope, oldWrappingKey, oldContext);
  try {
    requireByteLength(unwrapped, 32, 'wrapped key');
    return await encryptAead(unwrapped, newWrappingKey, newContext);
  } finally {
    zeroize(unwrapped);
  }
}

function assertEntityType(
  context: AssociatedData,
  expected: AssociatedData['entityType'],
): void {
  if (context.entityType !== expected) {
    throw new CryptoInputError(`Expected ${expected} associated data`);
  }
}
