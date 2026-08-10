import {
  changeRecordSchema,
  contentHashForRecord,
  encryptedGroupRecordSchema,
  opaqueMutationSchema,
  syncCursorSchema,
  type EncryptedGroupRecord,
  type OpaqueMutation,
  type SyncPulledChange,
  type VaultId,
} from '@kavrix/schemas';
import type { ApplyPullPageInput } from '@kavrix/sync';

export const timestamp = '2026-08-10T00:00:00.000Z';
export const digest = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
export const vaultId = 'vault.1' as VaultId;
export const otherVaultId = 'vault.2' as VaultId;
export const plaintextCanary = 'plaintext-local-store-canary';

export function groupRecord(
  id = 'group.1',
  revision = 0,
  recordVaultId: VaultId = vaultId,
): EncryptedGroupRecord {
  return encryptedGroupRecordSchema.parse({
    id,
    vaultId: recordVaultId,
    schemaVersion: 1,
    wrappedGroupKey: envelope(
      'wrapped-group-key',
      'group-key',
      id,
      recordVaultId,
      'AQID',
    ),
    encryptedPayload: envelope(
      'group',
      'group-payload',
      id,
      recordVaultId,
      Buffer.from(plaintextCanary).toString('base64url'),
    ),
    templateVersion: 1,
    recordRevision: revision,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
}

export function mutation(
  key: string,
  record = groupRecord(),
  expectedRevision: number | null = null,
): OpaqueMutation {
  return opaqueMutationSchema.parse({
    entityType: 'group',
    expectedRecordRevision: expectedRevision,
    idempotencyKey: key,
    record,
  });
}

export function pullPage(
  records: readonly EncryptedGroupRecord[],
  highestSeenVaultRevision = records.length,
  pageVaultId: VaultId = vaultId,
): ApplyPullPageInput {
  const changes: SyncPulledChange[] = records.map((record, index) => ({
    change: changeRecordSchema.parse({
      id: `change.${String(index + 1)}`,
      vaultId: pageVaultId,
      serverSequence: index + 1,
      entityType: 'group',
      entityId: record.id,
      recordRevision: record.recordRevision,
      operation: 'upsert',
      ciphertextHash: contentHashForRecord(record),
      createdAt: timestamp,
    }),
    record,
  }));
  return {
    vaultId: pageVaultId,
    changes,
    cursor: syncCursorSchema.parse({
      vaultId: pageVaultId,
      serverSequence: records.length,
      highestSeenVaultRevision,
    }),
  };
}

function envelope(
  entityType: 'group' | 'wrapped-group-key',
  purpose: 'group-key' | 'group-payload',
  entityId: string,
  recordVaultId: VaultId,
  ciphertext: string,
): Record<string, unknown> {
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext,
    authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: recordVaultId,
      entityType,
      entityId,
      purpose,
    },
    keyVersion: 1,
  };
}
