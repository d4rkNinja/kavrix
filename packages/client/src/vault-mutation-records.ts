import { createHash } from 'node:crypto';

import {
  CryptoAuthenticationError,
  ValidationError,
  validateItemAgainstTemplate,
} from '@kavrix/core';
import {
  decryptPayload,
  encryptPayload,
  unwrapGroupKey,
  unwrapItemKey,
  wrapGroupKey,
  wrapItemKey,
  zeroize,
  type GroupKey,
  type ItemKey,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  associatedDataSchema,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  groupPayloadSchema,
  itemPayloadSchema,
  sha256DigestSchema,
  vaultPreferencesSchema,
  vaultRecordSchema,
  type AssociatedData,
  type EncryptedGroupRecord,
  type EncryptedItemRecord,
  type GroupPayload,
  type ItemPayload,
  type KeyVersion,
  type RecordRevision,
  type SchemaVersion,
  type Sha256Digest,
  type VaultId,
  type VaultRecord,
} from '@kavrix/schemas';

import { MAX_VAULT_PAYLOAD_BYTES } from './vault-read-session.js';

export type ActiveVault = Readonly<{
  schemaVersion: SchemaVersion;
  keyVersion: KeyVersion;
}>;

export type OpenGroup = Readonly<{
  record: EncryptedGroupRecord;
  payload: GroupPayload;
  key: GroupKey;
  expectedRecordRevision: RecordRevision;
  deleted: boolean;
}>;

export type OpenItem = Readonly<{
  record: EncryptedItemRecord;
  payload: ItemPayload;
  key: ItemKey;
  expectedRecordRevision: RecordRevision;
  deleted: boolean;
}>;

export async function authenticateVaultRecord(
  candidate: VaultRecord,
  vaultId: VaultId,
  rootKey: VaultRootKey,
): Promise<ActiveVault> {
  const parsed = vaultRecordSchema.safeParse(candidate);
  if (
    !parsed.success ||
    parsed.data.id !== vaultId ||
    parsed.data.encryptedPreferences.keyVersion !== parsed.data.currentKeyVersion
  ) {
    throw new CryptoAuthenticationError();
  }
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = await decryptPayload(
      parsed.data.encryptedPreferences,
      rootKey,
      associatedDataSchema.parse({
        version: 1,
        schemaVersion: parsed.data.schemaVersion,
        keyVersion: parsed.data.currentKeyVersion,
        vaultId: parsed.data.id,
        entityType: 'vault-preferences',
        entityId: parsed.data.id,
        purpose: 'vault-preferences',
      }),
    );
    parseCanonicalPayload(plaintext, vaultPreferencesSchema);
    return {
      schemaVersion: parsed.data.schemaVersion,
      keyVersion: parsed.data.currentKeyVersion,
    };
  } catch (error) {
    if (error instanceof CryptoAuthenticationError) throw error;
    throw new CryptoAuthenticationError({ cause: error });
  } finally {
    zeroize(plaintext);
  }
}

export async function openGroupRecord(
  candidate: EncryptedGroupRecord,
  vaultId: VaultId,
  vault: ActiveVault,
  rootKey: VaultRootKey,
): Promise<OpenGroup> {
  const parsed = encryptedGroupRecordSchema.safeParse(candidate);
  if (
    !parsed.success ||
    parsed.data.vaultId !== vaultId ||
    parsed.data.schemaVersion !== vault.schemaVersion ||
    parsed.data.wrappedGroupKey.keyVersion !== vault.keyVersion ||
    parsed.data.encryptedPayload.keyVersion !== vault.keyVersion ||
    parsed.data.tombstonedAt !== undefined
  ) {
    throw new CryptoAuthenticationError();
  }
  const record = parsed.data;
  let key: GroupKey | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    key = await unwrapGroupKey(
      record.wrappedGroupKey,
      rootKey,
      groupKeyContext(record, vault),
    );
    plaintext = await decryptPayload(
      record.encryptedPayload,
      key,
      groupPayloadContext(record, vault),
    );
    const payload = parseCanonicalPayload(plaintext, groupPayloadSchema);
    if (
      payload.id !== record.id ||
      payload.vaultId !== record.vaultId ||
      payload.revision !== record.recordRevision ||
      payload.template.version !== record.templateVersion ||
      payload.createdAt !== record.createdAt ||
      payload.updatedAt !== record.updatedAt ||
      payload.deletedAt !== undefined
    ) {
      throw new CryptoAuthenticationError();
    }
    return {
      key,
      payload,
      record,
      expectedRecordRevision: record.recordRevision,
      deleted: false,
    };
  } catch (error) {
    zeroize(key);
    if (error instanceof CryptoAuthenticationError) throw error;
    throw new CryptoAuthenticationError({ cause: error });
  } finally {
    zeroize(plaintext);
  }
}

export async function openItemRecord(
  candidate: EncryptedItemRecord,
  group: OpenGroup,
  vault: ActiveVault,
): Promise<OpenItem> {
  const parsed = encryptedItemRecordSchema.safeParse(candidate);
  if (
    !parsed.success ||
    parsed.data.vaultId !== group.payload.vaultId ||
    parsed.data.groupId !== group.payload.id ||
    parsed.data.schemaVersion !== vault.schemaVersion ||
    parsed.data.wrappedItemKey.keyVersion !== vault.keyVersion ||
    parsed.data.encryptedPayload.keyVersion !== vault.keyVersion ||
    parsed.data.ciphertextHash !==
      ciphertextDigest(parsed.data.encryptedPayload.ciphertext) ||
    parsed.data.tombstonedAt !== undefined
  ) {
    throw new CryptoAuthenticationError();
  }
  const record = parsed.data;
  let key: ItemKey | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    key = await unwrapItemKey(
      record.wrappedItemKey,
      group.key,
      itemKeyContext(record, vault),
    );
    plaintext = await decryptPayload(
      record.encryptedPayload,
      key,
      itemPayloadContext(record, vault),
    );
    const payload = parseCanonicalPayload(plaintext, itemPayloadSchema);
    if (
      payload.id !== record.id ||
      payload.vaultId !== record.vaultId ||
      payload.groupId !== record.groupId ||
      payload.revision !== record.recordRevision ||
      payload.createdAt !== record.createdAt ||
      payload.updatedAt !== record.updatedAt ||
      payload.deletedAt !== undefined ||
      payload.templateId !== group.payload.template.id ||
      payload.templateVersion !== group.payload.template.version
    ) {
      throw new CryptoAuthenticationError();
    }
    validateItemAgainstTemplate(payload, group.payload.template);
    return {
      key,
      payload,
      record,
      expectedRecordRevision: record.recordRevision,
      deleted: false,
    };
  } catch (error) {
    zeroize(key);
    if (error instanceof CryptoAuthenticationError) throw error;
    throw new CryptoAuthenticationError({ cause: error });
  } finally {
    zeroize(plaintext);
  }
}

export async function encryptGroupRecord(
  payload: GroupPayload,
  key: GroupKey,
  rootKey: VaultRootKey,
  vault: ActiveVault,
  wrappedGroupKey?: EncryptedGroupRecord['wrappedGroupKey'],
  tombstonedAt?: string,
): Promise<EncryptedGroupRecord> {
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = serializePayload(payload);
    const identity = { id: payload.id, vaultId: payload.vaultId };
    const encryptedPayload = await encryptPayload(
      plaintext,
      key,
      groupPayloadContext(identity, vault),
    );
    return encryptedGroupRecordSchema.parse({
      ...identity,
      schemaVersion: vault.schemaVersion,
      wrappedGroupKey:
        wrappedGroupKey ??
        (await wrapGroupKey(key, rootKey, groupKeyContext(identity, vault))),
      encryptedPayload,
      templateVersion: payload.template.version,
      recordRevision: payload.revision,
      createdAt: payload.createdAt,
      updatedAt: payload.updatedAt,
      ...(tombstonedAt === undefined ? {} : { tombstonedAt }),
    });
  } finally {
    zeroize(plaintext);
  }
}

export async function encryptItemRecord(
  payload: ItemPayload,
  key: ItemKey,
  groupKey: GroupKey,
  vault: ActiveVault,
  wrappedItemKey?: EncryptedItemRecord['wrappedItemKey'],
  tombstonedAt?: string,
): Promise<EncryptedItemRecord> {
  let plaintext: Uint8Array | undefined;
  try {
    plaintext = serializePayload(payload);
    const identity = {
      id: payload.id,
      vaultId: payload.vaultId,
      groupId: payload.groupId,
    };
    const encryptedPayload = await encryptPayload(
      plaintext,
      key,
      itemPayloadContext(identity, vault),
    );
    return encryptedItemRecordSchema.parse({
      ...identity,
      schemaVersion: vault.schemaVersion,
      wrappedItemKey:
        wrappedItemKey ??
        (await wrapItemKey(key, groupKey, itemKeyContext(identity, vault))),
      encryptedPayload,
      recordRevision: payload.revision,
      ciphertextHash: ciphertextDigest(encryptedPayload.ciphertext),
      createdAt: payload.createdAt,
      updatedAt: payload.updatedAt,
      ...(tombstonedAt === undefined ? {} : { tombstonedAt }),
    });
  } finally {
    zeroize(plaintext);
  }
}

export function parseCanonicalPayload<TOutput>(
  plaintext: Uint8Array,
  schema: {
    safeParse(
      value: unknown,
    ): Readonly<{ success: true; data: TOutput }> | Readonly<{ success: false }>;
  },
): TOutput {
  if (plaintext.byteLength === 0 || plaintext.byteLength > MAX_VAULT_PAYLOAD_BYTES) {
    throw new CryptoAuthenticationError();
  }
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    const decoded = JSON.parse(text) as unknown;
    const result = schema.safeParse(decoded);
    if (!result.success || JSON.stringify(result.data) !== text) {
      throw new CryptoAuthenticationError();
    }
    return result.data;
  } catch (error) {
    if (error instanceof CryptoAuthenticationError) throw error;
    throw new CryptoAuthenticationError({ cause: error });
  }
}

function groupKeyContext(
  record: Pick<EncryptedGroupRecord, 'id' | 'vaultId'>,
  vault: ActiveVault,
): AssociatedData {
  return associatedDataSchema.parse({
    version: 1,
    schemaVersion: vault.schemaVersion,
    keyVersion: vault.keyVersion,
    vaultId: record.vaultId,
    entityType: 'wrapped-group-key',
    entityId: record.id,
    purpose: 'group-key',
  });
}

function groupPayloadContext(
  record: Pick<EncryptedGroupRecord, 'id' | 'vaultId'>,
  vault: ActiveVault,
): AssociatedData {
  return associatedDataSchema.parse({
    version: 1,
    schemaVersion: vault.schemaVersion,
    keyVersion: vault.keyVersion,
    vaultId: record.vaultId,
    entityType: 'group',
    entityId: record.id,
    purpose: 'group-payload',
  });
}

function itemKeyContext(
  record: Pick<EncryptedItemRecord, 'id' | 'vaultId' | 'groupId'>,
  vault: ActiveVault,
): AssociatedData {
  return associatedDataSchema.parse({
    version: 1,
    schemaVersion: vault.schemaVersion,
    keyVersion: vault.keyVersion,
    vaultId: record.vaultId,
    entityType: 'wrapped-item-key',
    entityId: record.id,
    groupId: record.groupId,
    purpose: 'item-key',
  });
}

function itemPayloadContext(
  record: Pick<EncryptedItemRecord, 'id' | 'vaultId' | 'groupId'>,
  vault: ActiveVault,
): AssociatedData {
  return associatedDataSchema.parse({
    version: 1,
    schemaVersion: vault.schemaVersion,
    keyVersion: vault.keyVersion,
    vaultId: record.vaultId,
    entityType: 'item',
    entityId: record.id,
    groupId: record.groupId,
    purpose: 'item-payload',
  });
}

function serializePayload(payload: GroupPayload | ItemPayload): Uint8Array {
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  if (plaintext.byteLength === 0 || plaintext.byteLength > MAX_VAULT_PAYLOAD_BYTES) {
    zeroize(plaintext);
    throw new ValidationError('The encrypted payload exceeds the supported size.');
  }
  return plaintext;
}

function ciphertextDigest(ciphertext: string): Sha256Digest {
  return sha256DigestSchema.parse(
    createHash('sha256')
      .update(Buffer.from(ciphertext, 'base64url'))
      .digest('base64url'),
  );
}
