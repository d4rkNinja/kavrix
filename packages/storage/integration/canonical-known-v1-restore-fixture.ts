import { createHash } from 'node:crypto';

import {
  createRestoreKnownRecordsVerificationSessionFactoryV1,
  type RestoreKnownRecordsCredentialV1,
  type RestoreKnownRecordsVerificationSessionFactoryV1,
} from '@kavrix/client';
import {
  createPassphraseKeySlot,
  createPortableKeySlot,
  createRecoveryKeySlot,
  encryptAttachmentStream,
  encryptPayload,
  formatPortableKey,
  formatRecoveryKey,
  generateAttachmentKey,
  generateGroupKey,
  generateItemKey,
  generatePortableKey,
  generateRecoveryKey,
  generateVaultRootKey,
  wrapAttachmentKey,
  wrapGroupKey,
  wrapItemKey,
  zeroize,
  type ItemKey,
  type SlotIdentity,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  createEncryptedBackup,
  verifyEncryptedBackup,
  type BackupLimits,
  type BackupVerification,
} from '@kavrix/import-export';
import {
  associatedDataSchema,
  aeadEnvelopeSchema,
  auditEventIdSchema,
  attachmentChunkCiphertextHash,
  attachmentHeaderContentHash,
  attachmentIdSchema,
  attachmentSecretStreamManifestSchema,
  canonicalJson,
  contentHashForRecord,
  createBackupStagedEntryCommitment,
  encryptedAttachmentRecordSchema,
  encryptedAuditRecordSchema,
  encryptedBackupEntrySchema,
  encryptedGroupRecordSchema,
  encryptedHistoryRecordSchema,
  encryptedItemRecordSchema,
  fieldIdSchema,
  groupIdSchema,
  groupPayloadSchema,
  historyIdSchema,
  itemIdSchema,
  itemPayloadSchema,
  keySlotAuditPayloadSchema,
  keySlotIdSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  recordRevisionSchema,
  sha256DigestSchema,
  templateIdSchema,
  timestampSchema,
  tombstoneRecordSchema,
  vaultIdSchema,
  vaultPreferencesSchema,
  vaultRecordSchema,
  vaultRevisionSchema,
  type AeadEnvelope,
  type AssociatedData,
  type AttachmentSecretStreamChunkRecord,
  type AttachmentSecretStreamHeaderRecord,
  type EncryptedAttachmentRecord,
  type EncryptedAuditRecord,
  type EncryptedBackupEntry,
  type EncryptedGroupRecord,
  type EncryptedHistoryRecord,
  type EncryptedItemRecord,
  type ItemPayload,
  type KeySlotId,
  type PersistedAttachmentChunkRecord,
  type PersistedAttachmentHeaderRecord,
  type Sha256Digest,
  type TombstoneRecord,
  type VaultId,
  type VaultRecord,
  type VaultRevision,
} from '@kavrix/schemas';

export const CANONICAL_RESTORE_CREATED_AT = timestampSchema.parse(
  '2026-08-12T00:00:00.000Z',
);
export const CANONICAL_RESTORE_DELETED_AT = timestampSchema.parse(
  '2026-08-12T00:01:00.000Z',
);
export const CANONICAL_RESTORE_RESTORED_AT = timestampSchema.parse(
  '2026-08-12T00:02:00.000Z',
);
export const CANONICAL_RESTORE_LIMITS = {
  maximumBytes: 8 * 1024 * 1024,
  maximumRecords: 100,
} as const satisfies BackupLimits;

const PASSPHRASE_CANARY = 'KAVRIX_TEST_ONLY_RESTORE_PASSPHRASE_CANARY';
const PREFERENCES_CANARY = 'KAVRIX_TEST_ONLY_RESTORE_PRODUCT_CANARY';
const GROUP_CANARY = 'KAVRIX_TEST_ONLY_RESTORE_GROUP_CANARY';
const FIELD_CANARY = 'KAVRIX_TEST_ONLY_RESTORE_FIELD_CANARY';
const ATTACHMENT_CANARY = 'KAVRIX_TEST_ONLY_RESTORE_ATTACHMENT_CANARY';

export const CANONICAL_RESTORE_PLAINTEXT_CANARIES = Object.freeze([
  PASSPHRASE_CANARY,
  PREFERENCES_CANARY,
  GROUP_CANARY,
  FIELD_CANARY,
  ATTACHMENT_CANARY,
]);

export const CANONICAL_RESTORE_EXPECTED_COUNTS = Object.freeze({
  vaults: 1 as const,
  groups: 1,
  items: 3,
  attachments: 1,
  attachmentHeaders: 1,
  attachmentChunks: 2,
  tombstonePredecessors: Object.freeze({ groups: 0, items: 1, attachments: 0 }),
  tombstones: 2,
  histories: 1,
  audits: 1,
});

export type CanonicalRestoreSlotType = 'portable-key' | 'passphrase' | 'recovery-key';
export type CanonicalInnerCorruption =
  | 'preferences'
  | 'wrapped-group-key'
  | 'group-payload'
  | 'wrapped-item-key'
  | 'item-payload'
  | 'wrapped-attachment-key'
  | 'attachment-manifest'
  | 'attachment-stream';

type NonVaultEntry = Exclude<EncryptedBackupEntry, { readonly kind: 'vault' }>;

export interface CanonicalKnownV1RestoreFixture {
  readonly vaultId: VaultId;
  readonly vaultRevision: VaultRevision;
  readonly vault: VaultRecord;
  readonly group: EncryptedGroupRecord;
  readonly activeItem: EncryptedItemRecord;
  readonly deletedItem: EncryptedItemRecord;
  readonly deletedPredecessor: EncryptedItemRecord;
  readonly deletedTombstone: TombstoneRecord;
  readonly restoredItem: EncryptedItemRecord;
  readonly restoredTombstone: TombstoneRecord;
  readonly attachment: EncryptedAttachmentRecord;
  readonly attachmentHeader: PersistedAttachmentHeaderRecord;
  readonly attachmentChunks: readonly PersistedAttachmentChunkRecord[];
  readonly records: readonly NonVaultEntry[];
  readonly entries: readonly EncryptedBackupEntry[];
  readonly archive: Uint8Array;
  readonly summary: BackupVerification;
  readonly slotIds: Readonly<Record<CanonicalRestoreSlotType, KeySlotId>>;
  cloneRecords(): readonly NonVaultEntry[];
  credentialCanaries(): readonly string[];
  unsupportedArchive(family: 'history' | 'audit'): Promise<Uint8Array>;
  innerCorruptionArchive(kind: CanonicalInnerCorruption): Promise<Uint8Array>;
  verificationFactory(
    type: CanonicalRestoreSlotType,
    highestSeenVaultRevision?: VaultRevision,
  ): RestoreKnownRecordsVerificationSessionFactoryV1;
  createArchive(records?: readonly NonVaultEntry[]): Promise<Uint8Array>;
  authenticate(archive: Uint8Array, limits?: BackupLimits): Promise<BackupVerification>;
  close(): void;
}

export async function createCanonicalKnownV1RestoreFixture(): Promise<CanonicalKnownV1RestoreFixture> {
  const vaultId = vaultIdSchema.parse('restore.acceptance.vault');
  const vaultRevision = vaultRevisionSchema.parse(9);
  const schemaVersion = 1;
  const keyVersion = 1;
  const groupId = groupIdSchema.parse('restore.acceptance.group');
  const activeItemId = itemIdSchema.parse('restore.acceptance.item.active');
  const deletedItemId = itemIdSchema.parse('restore.acceptance.item.deleted');
  const restoredItemId = itemIdSchema.parse('restore.acceptance.item.restored');
  const attachmentId = attachmentIdSchema.parse('restore.acceptance.attachment.active');
  const historyId = historyIdSchema.parse('restore.acceptance.history');
  const auditId = auditEventIdSchema.parse('restore.acceptance.audit');
  const templateId = templateIdSchema.parse('restore.acceptance.template');
  const fieldId = fieldIdSchema.parse('restore.acceptance.field');
  const slotIds = Object.freeze({
    'portable-key': keySlotIdSchema.parse('restore.acceptance.slot.portable'),
    passphrase: keySlotIdSchema.parse('restore.acceptance.slot.passphrase'),
    'recovery-key': keySlotIdSchema.parse('restore.acceptance.slot.recovery'),
  });
  const rootKey = generateVaultRootKey();
  const portableKey = generatePortableKey();
  const recoveryKey = generateRecoveryKey();
  const passphrase = new TextEncoder().encode(PASSPHRASE_CANARY);
  const groupKey = generateGroupKey();
  const activeItemKey = generateItemKey();
  const deletedItemKey = generateItemKey();
  const restoredItemKey = generateItemKey();
  const attachmentKey = generateAttachmentKey();
  let formattedPortable = '';
  let formattedRecovery = '';
  let closed = false;

  try {
    formattedPortable = formatPortableKey(portableKey);
    formattedRecovery = formatRecoveryKey(recoveryKey);
    const identity = (slotId: KeySlotId): SlotIdentity => ({
      vaultId,
      slotId,
      schemaVersion,
      keyVersion,
      createdAt: CANONICAL_RESTORE_CREATED_AT,
    });
    const slots = [
      await createPortableKeySlot(
        identity(slotIds['portable-key']),
        portableKey,
        rootKey,
      ),
      await createPassphraseKeySlot(identity(slotIds.passphrase), passphrase, rootKey),
      await createRecoveryKeySlot(
        identity(slotIds['recovery-key']),
        recoveryKey,
        rootKey,
      ),
    ];
    const preferences = vaultPreferencesSchema.parse({
      productLabel: PREFERENCES_CANARY,
      executableName: 'creds',
      clipboardClearSeconds: 30,
      revealHideSeconds: 15,
      historyRetentionDays: 90,
      telemetryEnabled: false,
    });
    const vault = vaultRecordSchema.parse({
      id: vaultId,
      schemaVersion,
      cryptographicVersion: 1,
      keySlots: slots,
      currentKeyVersion: keyVersion,
      revision: vaultRevision,
      encryptedPreferences: await encryptCanonicalPayload(
        preferences,
        rootKey,
        aad('vault-preferences', vaultId, vaultId),
      ),
      createdAt: CANONICAL_RESTORE_CREATED_AT,
      updatedAt: CANONICAL_RESTORE_RESTORED_AT,
    });
    const field = {
      id: fieldId,
      stableKey: 'restore_field',
      label: 'Acceptance value',
      type: 'text' as const,
      required: true,
      sensitive: false,
      repeatable: false,
      copyable: true,
      searchableLocally: true,
      showInPreview: true,
      copyPolicy: 'allowed' as const,
      revealPolicy: 'never' as const,
      reauthenticationPolicy: 'never' as const,
      exportPolicy: 'encrypted-only' as const,
      sortOrder: 0,
      createdAt: CANONICAL_RESTORE_CREATED_AT,
      updatedAt: CANONICAL_RESTORE_CREATED_AT,
    };
    const groupPayload = groupPayloadSchema.parse({
      id: groupId,
      vaultId,
      name: GROUP_CANARY,
      description: `${GROUP_CANARY}.description`,
      aliases: [],
      tags: [],
      notes: [],
      template: {
        id: templateId,
        name: 'Acceptance template',
        version: 1,
        fields: [field],
        createdAt: CANONICAL_RESTORE_CREATED_AT,
        updatedAt: CANONICAL_RESTORE_CREATED_AT,
      },
      sortOrder: 0,
      revision: recordRevisionSchema.parse(1),
      createdAt: CANONICAL_RESTORE_CREATED_AT,
      updatedAt: CANONICAL_RESTORE_CREATED_AT,
    });
    const group = encryptedGroupRecordSchema.parse({
      id: groupId,
      vaultId,
      schemaVersion,
      wrappedGroupKey: await wrapGroupKey(
        groupKey,
        rootKey,
        aad('wrapped-group-key', vaultId, groupId),
      ),
      encryptedPayload: await encryptCanonicalPayload(
        groupPayload,
        groupKey,
        aad('group', vaultId, groupId),
      ),
      templateVersion: groupPayload.template.version,
      recordRevision: groupPayload.revision,
      createdAt: groupPayload.createdAt,
      updatedAt: groupPayload.updatedAt,
    });

    const itemPayload = (
      id: typeof activeItemId,
      revision: number,
      updatedAt: string,
      options: {
        readonly attachmentIds?: readonly (typeof attachmentId)[];
        readonly deleted?: boolean;
      } = {},
    ): ItemPayload =>
      itemPayloadSchema.parse({
        version: 1,
        id,
        vaultId,
        groupId,
        templateId,
        title: `Acceptance ${id}`,
        aliases: [],
        templateVersion: 1,
        templateValues: [
          {
            fieldId,
            stableKey: field.stableKey,
            value: {
              version: 1,
              state: 'present',
              content: {
                cardinality: 'single',
                value: {
                  kind: 'text',
                  value: `${FIELD_CANARY}.${id}.${String(revision)}`,
                },
              },
            },
            updatedAt,
          },
        ],
        itemFields: [],
        itemValues: [],
        archivedFieldValues: [],
        notes: [],
        tags: [],
        favorite: false,
        productionSensitive: false,
        relatedItemIds: [],
        attachmentIds: options.attachmentIds ?? [],
        copySequences: [],
        revision: recordRevisionSchema.parse(revision),
        createdAt: CANONICAL_RESTORE_CREATED_AT,
        updatedAt,
        ...(options.deleted === true
          ? { deletedAt: CANONICAL_RESTORE_DELETED_AT }
          : {}),
      });
    const createItemRecord = async (
      payload: ReturnType<typeof itemPayload>,
      key: ItemKey,
      tombstonedAt?: string,
    ): Promise<EncryptedItemRecord> => {
      const encryptedPayload = await encryptCanonicalPayload(
        payload,
        key,
        aad('item', vaultId, payload.id, groupId),
      );
      return encryptedItemRecordSchema.parse({
        id: payload.id,
        vaultId,
        groupId,
        schemaVersion,
        wrappedItemKey: await wrapItemKey(
          key,
          groupKey,
          aad('wrapped-item-key', vaultId, payload.id, groupId),
        ),
        encryptedPayload,
        recordRevision: payload.revision,
        ciphertextHash: digestCiphertext(encryptedPayload),
        createdAt: payload.createdAt,
        updatedAt: payload.updatedAt,
        ...(tombstonedAt === undefined ? {} : { tombstonedAt }),
      });
    };

    const activeItem = await createItemRecord(
      itemPayload(activeItemId, 2, CANONICAL_RESTORE_CREATED_AT, {
        attachmentIds: [attachmentId],
      }),
      activeItemKey,
    );
    const deletedPredecessor = await createItemRecord(
      itemPayload(deletedItemId, 2, CANONICAL_RESTORE_CREATED_AT),
      deletedItemKey,
    );
    const deletedItem = await createItemRecord(
      itemPayload(deletedItemId, 3, CANONICAL_RESTORE_DELETED_AT, { deleted: true }),
      deletedItemKey,
      CANONICAL_RESTORE_DELETED_AT,
    );
    const deletedTombstone = tombstoneRecordSchema.parse({
      vaultId,
      entityType: 'item',
      entityId: deletedItemId,
      state: 'deleted',
      tombstoneRevision: deletedItem.recordRevision,
      lastRecordRevision: deletedPredecessor.recordRevision,
      lastCiphertextHash: contentHashForRecord(deletedPredecessor),
      deletedAt: CANONICAL_RESTORE_DELETED_AT,
    });
    const restoredItem = await createItemRecord(
      itemPayload(restoredItemId, 5, CANONICAL_RESTORE_RESTORED_AT),
      restoredItemKey,
    );
    const restoredActivePredecessor = await createItemRecord(
      itemPayload(restoredItemId, 3, CANONICAL_RESTORE_CREATED_AT),
      restoredItemKey,
    );
    const restoredTombstone = tombstoneRecordSchema.parse({
      vaultId,
      entityType: 'item',
      entityId: restoredItemId,
      state: 'restored',
      tombstoneRevision: restoredItem.recordRevision,
      lastRecordRevision: restoredActivePredecessor.recordRevision,
      lastCiphertextHash: contentHashForRecord(restoredActivePredecessor),
      deletedAt: CANONICAL_RESTORE_DELETED_AT,
      restoredAt: CANONICAL_RESTORE_RESTORED_AT,
    });

    const attachmentStream = await createAttachmentStream(
      attachmentKey,
      vaultId,
      groupId,
      activeItemId,
      attachmentId,
    );
    const attachment = encryptedAttachmentRecordSchema.parse({
      id: attachmentId,
      vaultId,
      groupId,
      itemId: activeItemId,
      schemaVersion,
      wrappedAttachmentKey: await wrapAttachmentKey(
        attachmentKey,
        activeItemKey,
        aad('wrapped-attachment-key', vaultId, attachmentId, groupId, activeItemId),
      ),
      encryptedManifest: await encryptCanonicalPayload(
        attachmentStream.manifest,
        attachmentKey,
        aad('attachment', vaultId, attachmentId, groupId, activeItemId),
      ),
      chunkCount: attachmentStream.manifest.chunkCount,
      recordRevision: recordRevisionSchema.parse(2),
      createdAt: CANONICAL_RESTORE_CREATED_AT,
      updatedAt: CANONICAL_RESTORE_CREATED_AT,
    });
    const headerBase = persistedAttachmentHeaderRecordSchema.parse({
      entityType: 'attachment-header',
      record: attachmentStream.header,
      recordRevision: attachment.recordRevision,
      contentHash: createHash('sha256').update('placeholder').digest('base64url'),
      createdAt: CANONICAL_RESTORE_CREATED_AT,
      updatedAt: CANONICAL_RESTORE_CREATED_AT,
    });
    const attachmentHeader = persistedAttachmentHeaderRecordSchema.parse({
      ...headerBase,
      contentHash: attachmentHeaderContentHash(headerBase),
    });
    const attachmentChunks = attachmentStream.chunks.map(({ record, bytes }) => {
      const base = persistedAttachmentChunkRecordSchema.parse({
        entityType: 'attachment-chunk',
        record,
        plaintextBytes: bytes,
        recordRevision: attachment.recordRevision,
        ciphertextHash: createHash('sha256').update('placeholder').digest('base64url'),
        createdAt: CANONICAL_RESTORE_CREATED_AT,
        updatedAt: CANONICAL_RESTORE_CREATED_AT,
      });
      return persistedAttachmentChunkRecordSchema.parse({
        ...base,
        ciphertextHash: attachmentChunkCiphertextHash(base),
      });
    });
    const historyPayload = itemPayload(activeItemId, 1, CANONICAL_RESTORE_CREATED_AT, {
      attachmentIds: [attachmentId],
    });
    const historyEncryptedPayload = await encryptCanonicalPayload(
      historyPayload,
      activeItemKey,
      aad('history', vaultId, historyId, groupId, activeItemId),
    );
    const history = encryptedHistoryRecordSchema.parse({
      id: historyId,
      vaultId,
      groupId,
      itemId: activeItemId,
      schemaVersion,
      encryptedPayload: historyEncryptedPayload,
      itemRecordRevision: historyPayload.revision,
      ciphertextHash: digestCiphertext(historyEncryptedPayload),
      createdAt: CANONICAL_RESTORE_CREATED_AT,
    });
    const auditPayload = keySlotAuditPayloadSchema.parse({
      version: 1,
      action: 'create',
      slotId: slotIds['portable-key'],
      slotType: 'portable-key',
      resultingState: 'active',
      keyVersion,
      actorDeviceId: 'restore.acceptance.device',
      occurredAt: CANONICAL_RESTORE_CREATED_AT,
    });
    const auditPlaintext = new TextEncoder().encode(canonicalJson(auditPayload));
    let auditEncryptedPayload: AeadEnvelope;
    try {
      auditEncryptedPayload = await encryptPayload(
        auditPlaintext,
        rootKey,
        aad('audit-event', vaultId, auditId),
      );
    } finally {
      zeroize(auditPlaintext);
    }
    const audit = encryptedAuditRecordSchema.parse({
      id: auditId,
      vaultId,
      schemaVersion,
      encryptedPayload: auditEncryptedPayload,
      recordRevision: recordRevisionSchema.parse(1),
      createdAt: CANONICAL_RESTORE_CREATED_AT,
    });
    const records = [
      encryptedBackupEntrySchema.parse({ kind: 'group', record: group }),
      encryptedBackupEntrySchema.parse({ kind: 'item', record: activeItem }),
      encryptedBackupEntrySchema.parse({ kind: 'history', record: history }),
      encryptedBackupEntrySchema.parse({ kind: 'attachment', record: attachment }),
      encryptedBackupEntrySchema.parse({
        kind: 'attachment-header',
        record: attachmentHeader,
      }),
      ...attachmentChunks.map((record) =>
        encryptedBackupEntrySchema.parse({ kind: 'attachment-chunk', record }),
      ),
      encryptedBackupEntrySchema.parse({ kind: 'item', record: deletedItem }),
      encryptedBackupEntrySchema.parse({
        kind: 'tombstone-predecessor',
        entityType: 'item',
        record: deletedPredecessor,
      }),
      encryptedBackupEntrySchema.parse({
        kind: 'tombstone',
        record: deletedTombstone,
      }),
      encryptedBackupEntrySchema.parse({ kind: 'item', record: restoredItem }),
      encryptedBackupEntrySchema.parse({
        kind: 'tombstone',
        record: restoredTombstone,
      }),
      encryptedBackupEntrySchema.parse({ kind: 'audit', record: audit }),
    ] as readonly NonVaultEntry[];
    const entries = [
      encryptedBackupEntrySchema.parse({ kind: 'vault', record: vault }),
      ...records,
    ];
    if (entries.length !== 14) throw new Error('Canonical restore fixture drifted.');
    if (
      restoredTombstone.lastCiphertextHash !==
        contentHashForRecord(restoredActivePredecessor) ||
      restoredItem.tombstonedAt !== undefined
    ) {
      throw new Error('Canonical restored-state relation drifted.');
    }
    const archive = await createArchive(vault, records, rootKey);
    const summary = await verifyEncryptedBackup(
      byteChunks(archive),
      rootKey,
      vaultId,
      CANONICAL_RESTORE_LIMITS,
    );
    const commitment = createBackupStagedEntryCommitment();
    for (const entry of entries) commitment.update(entry);
    if (
      summary.recordCount !== 14 ||
      summary.canonicalEntriesSha256 !== commitment.finalize()
    ) {
      throw new Error('Canonical restore fixture commitment drifted.');
    }

    const verificationFactory = (
      type: CanonicalRestoreSlotType,
      highestSeenVaultRevision?: VaultRevision,
    ): RestoreKnownRecordsVerificationSessionFactoryV1 => {
      if (closed) throw new Error('Canonical restore fixture is closed.');
      let credential: RestoreKnownRecordsCredentialV1;
      if (type === 'portable-key') {
        credential = {
          type,
          slotId: slotIds[type],
          formattedKey: formattedPortable,
        };
      } else if (type === 'recovery-key') {
        credential = {
          type,
          slotId: slotIds[type],
          formattedKey: formattedRecovery,
        };
      } else {
        const owned = Uint8Array.from(passphrase);
        try {
          credential = { type, slotId: slotIds[type], passphrase: owned };
          return createRestoreKnownRecordsVerificationSessionFactoryV1({
            credential,
            ...(highestSeenVaultRevision === undefined
              ? {}
              : { highestSeenVaultRevision }),
          });
        } finally {
          zeroize(owned);
        }
      }
      return createRestoreKnownRecordsVerificationSessionFactoryV1({
        credential,
        ...(highestSeenVaultRevision === undefined ? {} : { highestSeenVaultRevision }),
      });
    };
    return Object.freeze({
      vaultId,
      vaultRevision,
      vault,
      group,
      activeItem,
      deletedItem,
      deletedPredecessor,
      deletedTombstone,
      restoredItem,
      restoredTombstone,
      attachment,
      attachmentHeader,
      attachmentChunks: Object.freeze(attachmentChunks),
      records: Object.freeze(records),
      entries: Object.freeze(entries),
      archive,
      summary,
      slotIds,
      cloneRecords: () => cloneEntries(records),
      credentialCanaries: () =>
        closed
          ? []
          : [
              formattedPortable,
              formattedRecovery,
              new TextDecoder().decode(passphrase),
            ],
      unsupportedArchive: async (family: 'history' | 'audit') => {
        if (closed) throw new Error('Canonical restore fixture is closed.');
        const future = await futureVersionEntry(
          family,
          history,
          audit,
          activeItemKey,
          rootKey,
        );
        return createArchive(
          vault,
          cloneEntries(records).map((entry) =>
            entry.kind === family ? future : entry,
          ),
          rootKey,
        );
      },
      innerCorruptionArchive: (kind: CanonicalInnerCorruption) => {
        if (closed) throw new Error('Canonical restore fixture is closed.');
        const corrupted = corruptInnerGraph(vault, records, kind);
        return createArchive(corrupted.vault, corrupted.records, rootKey);
      },
      verificationFactory,
      createArchive: (candidate: readonly NonVaultEntry[] = records) => {
        if (closed) throw new Error('Canonical restore fixture is closed.');
        return createArchive(vault, candidate, rootKey);
      },
      authenticate: (
        candidate: Uint8Array,
        limits: BackupLimits = CANONICAL_RESTORE_LIMITS,
      ) => {
        if (closed) throw new Error('Canonical restore fixture is closed.');
        return verifyEncryptedBackup(byteChunks(candidate), rootKey, vaultId, limits);
      },
      close() {
        if (closed) return;
        closed = true;
        zeroize(rootKey);
        zeroize(passphrase);
        formattedPortable = '';
        formattedRecovery = '';
      },
    });
  } catch (error) {
    zeroize(rootKey);
    zeroize(passphrase);
    throw error;
  } finally {
    zeroize(portableKey);
    zeroize(recoveryKey);
    zeroize(groupKey);
    zeroize(activeItemKey);
    zeroize(deletedItemKey);
    zeroize(restoredItemKey);
    zeroize(attachmentKey);
  }
}

async function createArchive(
  vault: VaultRecord,
  records: readonly NonVaultEntry[],
  rootKey: VaultRootKey,
): Promise<Uint8Array> {
  const strictRecords = records.map((entry) => encryptedBackupEntrySchema.parse(entry));
  const chunks: Uint8Array[] = [];
  for await (const chunk of createEncryptedBackup(
    {
      vault: vaultRecordSchema.parse(vault),
      records: asyncValues(strictRecords),
      createdAt: CANONICAL_RESTORE_CREATED_AT,
      limits: CANONICAL_RESTORE_LIMITS,
    },
    rootKey,
  )) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function encryptCanonicalPayload(
  parsed: unknown,
  key: Uint8Array,
  associatedData: ReturnType<typeof associatedDataSchema.parse>,
): Promise<AeadEnvelope> {
  const plaintext = new TextEncoder().encode(JSON.stringify(parsed));
  try {
    return await encryptPayload(plaintext, key, associatedData);
  } finally {
    zeroize(plaintext);
  }
}

async function createAttachmentStream(
  key: Uint8Array,
  vaultId: VaultId,
  groupId: string,
  itemId: string,
  attachmentId: string,
): Promise<
  Readonly<{
    header: AttachmentSecretStreamHeaderRecord;
    chunks: readonly Readonly<{
      record: AttachmentSecretStreamChunkRecord;
      bytes: number;
    }>[];
    manifest: ReturnType<typeof attachmentSecretStreamManifestSchema.parse>;
  }>
> {
  const plaintext = [
    new TextEncoder().encode(`${ATTACHMENT_CANARY}.first`),
    new TextEncoder().encode(`${ATTACHMENT_CANARY}.final`),
  ];
  const stream = encryptAttachmentStream(
    plaintext,
    key,
    aad('attachment-chunk', vaultId, attachmentId, groupId, itemId),
  );
  let header: AttachmentSecretStreamHeaderRecord | undefined;
  const chunks: {
    record: AttachmentSecretStreamChunkRecord;
    bytes: number;
  }[] = [];
  try {
    for (;;) {
      const next = await stream.next();
      if (next.done) {
        if (header?.recordType !== 'header') throw new Error('Missing stream header.');
        return {
          header,
          chunks,
          manifest: attachmentSecretStreamManifestSchema.parse(next.value),
        };
      }
      if (next.value.recordType === 'header') {
        header = next.value;
      } else {
        chunks.push({
          record: next.value,
          bytes: plaintext[next.value.index]?.byteLength ?? -1,
        });
      }
    }
  } finally {
    for (const value of plaintext) zeroize(value);
  }
}

function aad(
  entityType:
    | 'vault-preferences'
    | 'wrapped-group-key'
    | 'group'
    | 'wrapped-item-key'
    | 'item'
    | 'wrapped-attachment-key'
    | 'history'
    | 'audit-event'
    | 'attachment'
    | 'attachment-chunk',
  vaultId: VaultId,
  entityId: string,
  groupId?: string,
  parentId?: string,
): AssociatedData {
  const purpose = {
    'vault-preferences': 'vault-preferences',
    'wrapped-group-key': 'group-key',
    group: 'group-payload',
    'wrapped-item-key': 'item-key',
    item: 'item-payload',
    'wrapped-attachment-key': 'attachment-key',
    attachment: 'attachment-metadata',
    'attachment-chunk': 'attachment-chunk',
    history: 'history-event',
    'audit-event': 'audit-event',
  } as const;
  return associatedDataSchema.parse({
    version: 1,
    schemaVersion: 1,
    keyVersion: 1,
    vaultId,
    entityType,
    entityId,
    ...(groupId === undefined ? {} : { groupId }),
    ...(parentId === undefined ? {} : { parentId }),
    purpose: purpose[entityType],
  });
}

async function futureVersionEntry(
  family: 'history' | 'audit',
  history: EncryptedHistoryRecord,
  audit: EncryptedAuditRecord,
  itemKey: ItemKey,
  rootKey: VaultRootKey,
): Promise<NonVaultEntry> {
  const record = family === 'history' ? history : audit;
  const plaintext = new TextEncoder().encode(JSON.stringify({ version: 2 }));
  try {
    const encryptedPayload = await encryptPayload(
      plaintext,
      family === 'history' ? itemKey : rootKey,
      record.encryptedPayload.aad,
    );
    if (family === 'history') {
      return strictNonVault({
        kind: family,
        record: encryptedHistoryRecordSchema.parse({
          ...history,
          encryptedPayload,
          ciphertextHash: digestCiphertext(encryptedPayload),
        }),
      });
    }
    return strictNonVault({
      kind: family,
      record: encryptedAuditRecordSchema.parse({
        ...audit,
        encryptedPayload,
      }),
    });
  } finally {
    zeroize(plaintext);
  }
}

function cloneEntries(entries: readonly NonVaultEntry[]): readonly NonVaultEntry[] {
  return entries.map((entry) =>
    strictNonVault(JSON.parse(JSON.stringify(entry)) as unknown),
  );
}

function corruptInnerGraph(
  vault: VaultRecord,
  records: readonly NonVaultEntry[],
  kind: CanonicalInnerCorruption,
): Readonly<{ vault: VaultRecord; records: readonly NonVaultEntry[] }> {
  let corruptedVault = vaultRecordSchema.parse(
    JSON.parse(JSON.stringify(vault)) as unknown,
  );
  let mutations = 0;
  const corruptedRecords = cloneEntries(records).map((entry) => {
    if (kind === 'wrapped-group-key' && entry.kind === 'group') {
      mutations += 1;
      return strictNonVault({
        ...entry,
        record: {
          ...entry.record,
          wrappedGroupKey: flipEnvelope(entry.record.wrappedGroupKey, 'tag'),
        },
      });
    }
    if (kind === 'group-payload' && entry.kind === 'group') {
      mutations += 1;
      return strictNonVault({
        ...entry,
        record: {
          ...entry.record,
          encryptedPayload: flipEnvelope(entry.record.encryptedPayload, 'ciphertext'),
        },
      });
    }
    if (kind === 'wrapped-item-key' && entry.kind === 'item' && mutations === 0) {
      mutations += 1;
      return strictNonVault({
        ...entry,
        record: {
          ...entry.record,
          wrappedItemKey: flipEnvelope(entry.record.wrappedItemKey, 'tag'),
        },
      });
    }
    if (kind === 'item-payload' && entry.kind === 'item' && mutations === 0) {
      mutations += 1;
      const encryptedPayload = flipEnvelope(
        entry.record.encryptedPayload,
        'ciphertext',
      );
      return strictNonVault({
        ...entry,
        record: {
          ...entry.record,
          encryptedPayload,
          ciphertextHash: digestCiphertext(encryptedPayload),
        },
      });
    }
    if (kind === 'wrapped-attachment-key' && entry.kind === 'attachment') {
      mutations += 1;
      return strictNonVault({
        ...entry,
        record: {
          ...entry.record,
          wrappedAttachmentKey: flipEnvelope(entry.record.wrappedAttachmentKey, 'tag'),
        },
      });
    }
    if (kind === 'attachment-manifest' && entry.kind === 'attachment') {
      mutations += 1;
      return strictNonVault({
        ...entry,
        record: {
          ...entry.record,
          encryptedManifest: flipEnvelope(entry.record.encryptedManifest, 'ciphertext'),
        },
      });
    }
    if (
      kind === 'attachment-stream' &&
      entry.kind === 'attachment-chunk' &&
      entry.record.record.index === 0
    ) {
      mutations += 1;
      const bytes = flipBase64Url(entry.record.record.ciphertext);
      const base = persistedAttachmentChunkRecordSchema.parse({
        ...entry.record,
        record: { ...entry.record.record, ciphertext: bytes },
      });
      return strictNonVault({
        ...entry,
        record: {
          ...base,
          ciphertextHash: attachmentChunkCiphertextHash(base),
        },
      });
    }
    return entry;
  });
  if (kind === 'preferences') {
    mutations += 1;
    corruptedVault = vaultRecordSchema.parse({
      ...corruptedVault,
      encryptedPreferences: flipEnvelope(
        corruptedVault.encryptedPreferences,
        'ciphertext',
      ),
    });
  }
  if (mutations !== 1) throw new Error('Canonical corruption target drifted.');
  return { vault: corruptedVault, records: corruptedRecords };
}

function flipEnvelope(
  envelope: AeadEnvelope,
  part: 'ciphertext' | 'tag',
): AeadEnvelope {
  return aeadEnvelopeSchema.parse({
    ...envelope,
    ...(part === 'ciphertext'
      ? { ciphertext: flipBase64Url(envelope.ciphertext) }
      : { authenticationTag: flipBase64Url(envelope.authenticationTag) }),
  });
}

function flipBase64Url(value: string): string {
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.byteLength === 0) throw new Error('Cannot mutate empty fixture bytes.');
  bytes[0] = (bytes[0] ?? 0) ^ 1;
  return bytes.toString('base64url');
}

function strictNonVault(candidate: unknown): NonVaultEntry {
  const entry = encryptedBackupEntrySchema.parse(candidate);
  if (entry.kind === 'vault') throw new Error('Expected a non-vault backup entry.');
  return entry;
}

function digestCiphertext(envelope: AeadEnvelope): Sha256Digest {
  return sha256DigestSchema.parse(
    createHash('sha256')
      .update(Buffer.from(envelope.ciphertext, 'base64url'))
      .digest('base64url'),
  );
}

function byteChunks(value: Uint8Array): AsyncIterable<Uint8Array> {
  return asyncValues([value]);
}

function asyncValues<T>(values: readonly T[]): AsyncIterable<T> {
  return {
    [Symbol.asyncIterator]() {
      let index = 0;
      return {
        next(): Promise<IteratorResult<T>> {
          const value = values[index++];
          return Promise.resolve(
            value === undefined
              ? { done: true, value: undefined }
              : { done: false, value },
          );
        },
      };
    },
  };
}
