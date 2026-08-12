import { CryptoAuthenticationError } from '@kavrix/core';
import {
  constantTimeEqual,
  decryptAttachmentStreamToStager,
  decryptPayload,
  unwrapAttachmentKey,
  zeroize,
  type AttachmentKey,
  type VaultRootKey,
} from '@kavrix/crypto';
import {
  associatedDataSchema,
  attachmentRecordHashMatchesCanonicalContent,
  attachmentSecretStreamManifestSchema,
  backupVerificationSchema,
  canonicalJson,
  contentHashForRecord,
  createBackupStagedEntryCommitment,
  encryptedAttachmentRecordSchema,
  encryptedBackupEntrySchema,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  restoreKnownRecordsVerificationV1Schema,
  vaultRevisionSchema,
  vaultRecordSchema,
  type AttachmentSecretStreamManifest,
  type BackupVerification,
  type EncryptedAttachmentRecord,
  type EncryptedBackupEntry,
  type RestoreKnownRecordsVerificationV1,
  type TombstoneRecord,
  type VaultRecord,
  type VaultRevision,
} from '@kavrix/schemas';

import {
  assertGroupTombstoneRelation,
  assertItemTombstoneRelation,
} from './vault-mutation-deleted-state.js';
import {
  authenticateVaultRecord,
  openGroupRecordForState,
  openItemRecordForState,
  parseCanonicalPayload,
  type ActiveVault,
  type OpenGroup,
  type OpenItem,
} from './vault-mutation-records.js';
import {
  unwrapRestoreVaultRootKey,
  type RestoreSlotCredential,
} from './restore-slot-selection.js';

const SAFE_MESSAGE = 'Encrypted backup decryptability verification failed.';

export class RestoreKnownRecordsVerificationError extends Error {
  readonly safe = true;
  readonly kind: 'invalid' | 'unsupported';

  constructor(kind: 'invalid' | 'unsupported' = 'invalid') {
    super(SAFE_MESSAGE);
    this.name = 'RestoreKnownRecordsVerificationError';
    this.kind = kind;
  }
}

export type RestoreKnownRecordsCredentialV1 = RestoreSlotCredential;

export type RestoreKnownRecordsVerifierOptionsV1 = Readonly<{
  credential: RestoreKnownRecordsCredentialV1;
  highestSeenVaultRevision?: VaultRevision;
}>;

export type RestoreKnownRecordsVerificationSessionV1 = Readonly<{
  readonly vaultRootKey: VaultRootKey;
  readonly selectedSlot: RestoreKnownRecordsVerificationV1['selectedSlot'];
  verify(
    entries: AsyncIterable<EncryptedBackupEntry>,
    summary: BackupVerification,
  ): Promise<RestoreKnownRecordsVerificationV1>;
  close(): void;
}>;

export type RestoreKnownRecordsVerificationSessionFactoryV1 = (
  vault: VaultRecord,
) => Promise<RestoreKnownRecordsVerificationSessionV1>;

type OpenAttachment = Readonly<{
  record: EncryptedAttachmentRecord;
  manifest: AttachmentSecretStreamManifest;
  key: AttachmentKey;
  deleted: boolean;
}>;

interface Counts {
  vaults: 0 | 1;
  groups: number;
  items: number;
  attachments: number;
  attachmentHeaders: number;
  attachmentChunks: number;
  tombstonePredecessors: { groups: number; items: number; attachments: number };
  tombstones: number;
  histories: 0;
  audits: 0;
}

export function createRestoreKnownRecordsVerificationSessionFactoryV1(
  options: RestoreKnownRecordsVerifierOptionsV1,
): RestoreKnownRecordsVerificationSessionFactoryV1 {
  let retainedCredential: RestoreKnownRecordsCredentialV1 | undefined;
  let anchor: VaultRevision | undefined;
  try {
    const candidate = options.credential;
    retainedCredential =
      candidate.type === 'passphrase'
        ? { ...candidate, passphrase: Uint8Array.from(candidate.passphrase) }
        : { ...candidate };
    anchor =
      options.highestSeenVaultRevision === undefined
        ? undefined
        : vaultRevisionSchema.parse(options.highestSeenVaultRevision);
  } catch {
    if (retainedCredential?.type === 'passphrase') {
      zeroize(retainedCredential.passphrase);
    }
    throw invalid();
  }
  return async (vaultCandidate) => {
    const credential = retainedCredential;
    retainedCredential = undefined;
    try {
      if (credential === undefined) throw invalid();
      const archivedVault = vaultRecordSchema.parse(vaultCandidate);
      const opened = await unwrapRestoreVaultRootKey(archivedVault, credential);
      let closed = false;
      const selectedSlot = Object.freeze({ ...opened.selectedSlot });
      const session: RestoreKnownRecordsVerificationSessionV1 = {
        vaultRootKey: opened.vaultRootKey,
        selectedSlot,
        async verify(entries, summary) {
          if (closed) throw invalid();
          return verifyKnownRecords(
            entries,
            summary,
            archivedVault,
            opened.vaultRootKey,
            selectedSlot,
            anchor,
            () => closed,
          );
        },
        close() {
          if (!closed) {
            closed = true;
            zeroize(opened.vaultRootKey);
          }
        },
      };
      return Object.freeze(session);
    } catch {
      throw invalid();
    } finally {
      if (credential?.type === 'passphrase') zeroize(credential.passphrase);
    }
  };
}

async function verifyKnownRecords(
  entries: AsyncIterable<EncryptedBackupEntry>,
  summaryCandidate: BackupVerification,
  archivedVault: VaultRecord,
  rootKey: VaultRootKey,
  selectedSlot: RestoreKnownRecordsVerificationV1['selectedSlot'],
  anchor: VaultRevision | undefined,
  isClosed: () => boolean,
): Promise<RestoreKnownRecordsVerificationV1> {
  const commitment = createBackupStagedEntryCommitment();
  const groups = new Map<string, OpenGroup>();
  const items = new Map<string, OpenItem>();
  const attachments = new Map<string, OpenAttachment>();
  const predecessors = new Map<string, OpenGroup | OpenItem | OpenAttachment>();
  const tombstones = new Map<string, TombstoneRecord>();
  const counts: Counts = {
    vaults: 0,
    groups: 0,
    items: 0,
    attachments: 0,
    attachmentHeaders: 0,
    attachmentChunks: 0,
    tombstonePredecessors: { groups: 0, items: 0, attachments: 0 },
    tombstones: 0,
    histories: 0,
    audits: 0,
  };
  let summary: BackupVerification;
  let vault: VaultRecord | undefined;
  let activeVault: ActiveVault | undefined;
  let eof = false;
  let iterator: AsyncIterator<EncryptedBackupEntry> | undefined;
  const budget = { consumed: 0, maximum: 0 };
  try {
    summary = backupVerificationSchema.parse(summaryCandidate);
    budget.maximum = summary.recordCount;
    iterator = entries[Symbol.asyncIterator]();
    for (;;) {
      if (isClosed()) throw invalid();
      const next = await iterator.next();
      if (next.done) {
        eof = true;
        break;
      }
      budget.consumed = add(budget.consumed, 1);
      if (budget.consumed > budget.maximum) throw invalid();
      const entry = encryptedBackupEntrySchema.parse(next.value);
      commitment.update(entry);
      if (counts.vaults === 0 && entry.kind !== 'vault') throw invalid();
      switch (entry.kind) {
        case 'vault': {
          if (
            counts.vaults !== 0 ||
            canonicalJson(entry.record) !== canonicalJson(archivedVault)
          ) {
            throw invalid();
          }
          if (
            entry.record.id !== summary.header.vaultId ||
            entry.record.schemaVersion !== summary.header.schemaVersion
          ) {
            throw invalid();
          }
          activeVault = await authenticateVaultRecord(
            entry.record,
            entry.record.id,
            rootKey,
          );
          if (anchor !== undefined && entry.record.revision < anchor) throw invalid();
          vault = entry.record;
          counts.vaults = 1;
          break;
        }
        case 'group': {
          const [currentActiveVault, currentVault] = requireVault(activeVault, vault);
          if (groups.has(entry.record.id)) throw invalid();
          const opened = await openGroupRecordForState(
            entry.record,
            currentVault.id,
            currentActiveVault,
            rootKey,
            entry.record.tombstonedAt === undefined ? 'active' : 'deleted',
          );
          groups.set(entry.record.id, opened);
          counts.groups = add(counts.groups, 1);
          break;
        }
        case 'item': {
          const [currentActiveVault] = requireVault(activeVault, vault);
          if (items.has(entry.record.id)) throw invalid();
          const group = groups.get(entry.record.groupId);
          if (group === undefined) throw invalid();
          const opened = await openItemRecordForState(
            entry.record,
            group,
            currentActiveVault,
            entry.record.tombstonedAt === undefined ? 'active' : 'deleted',
          );
          items.set(entry.record.id, opened);
          counts.items = add(counts.items, 1);
          break;
        }
        case 'attachment': {
          requireVault(activeVault, vault);
          if (attachments.has(entry.record.id)) throw invalid();
          const item = items.get(entry.record.itemId);
          if (item?.record.groupId !== entry.record.groupId) {
            throw invalid();
          }
          const opened = await openAttachment(entry.record, item);
          attachments.set(entry.record.id, opened);
          counts.attachments = add(counts.attachments, 1);
          await verifyAttachmentStream(
            iterator,
            commitment,
            opened,
            counts,
            budget,
            isClosed,
          );
          break;
        }
        case 'tombstone-predecessor': {
          const [currentActiveVault, currentVault] = requireVault(activeVault, vault);
          const key = relationKey(entry.entityType, entry.record.id);
          if (predecessors.has(key)) throw invalid();
          if (entry.entityType === 'group') {
            const record = encryptedGroupRecordSchema.parse(entry.record);
            const current = groups.get(record.id);
            if (!current?.deleted) throw invalid();
            const opened = await openGroupRecordForState(
              record,
              currentVault.id,
              currentActiveVault,
              rootKey,
              'active',
            );
            predecessors.set(key, opened);
            counts.tombstonePredecessors.groups = add(
              counts.tombstonePredecessors.groups,
              1,
            );
          } else if (entry.entityType === 'item') {
            const record = encryptedItemRecordSchema.parse(entry.record);
            const current = items.get(record.id);
            if (!current?.deleted) throw invalid();
            const group = groups.get(record.groupId);
            if (group === undefined) throw invalid();
            const opened = await openItemRecordForState(
              record,
              group,
              currentActiveVault,
              'active',
            );
            predecessors.set(key, opened);
            counts.tombstonePredecessors.items = add(
              counts.tombstonePredecessors.items,
              1,
            );
          } else {
            const record = encryptedAttachmentRecordSchema.parse(entry.record);
            const current = attachments.get(record.id);
            if (!current?.deleted) throw invalid();
            const item = items.get(record.itemId);
            if (item?.record.groupId !== record.groupId) {
              throw invalid();
            }
            const opened = await openAttachment(record, item, 'active');
            predecessors.set(key, opened);
            counts.tombstonePredecessors.attachments = add(
              counts.tombstonePredecessors.attachments,
              1,
            );
          }
          break;
        }
        case 'tombstone': {
          if (entry.record.entityType === 'vault') throw invalid();
          const key = relationKey(entry.record.entityType, entry.record.entityId);
          if (tombstones.has(key)) throw invalid();
          const current =
            entry.record.entityType === 'group'
              ? groups.get(entry.record.entityId)
              : entry.record.entityType === 'item'
                ? items.get(entry.record.entityId)
                : attachments.get(entry.record.entityId);
          if (
            current === undefined ||
            (entry.record.state === 'deleted'
              ? !current.deleted || !predecessors.has(key)
              : current.deleted || predecessors.has(key))
          ) {
            throw invalid();
          }
          tombstones.set(key, entry.record);
          counts.tombstones = add(counts.tombstones, 1);
          break;
        }
        case 'history':
        case 'audit':
          throw unsupported();
        case 'attachment-header':
        case 'attachment-chunk':
          throw invalid();
      }
    }

    if (isClosed()) throw invalid();
    const [, openedVault] = requireVault(activeVault, vault);
    assertRelations(groups, items, attachments, predecessors, tombstones);
    const canonicalEntriesSha256 = commitment.finalize();
    if (
      canonicalEntriesSha256 !== summary.canonicalEntriesSha256 ||
      observedCount(counts) !== summary.recordCount ||
      openedVault.revision !== archivedVault.revision ||
      selectedSlot.keyVersion !== openedVault.currentKeyVersion ||
      !openedVault.keySlots.some(
        (slot) =>
          slot.id === selectedSlot.id &&
          slot.type === selectedSlot.type &&
          slot.state === 'active' &&
          slot.keyVersion === selectedSlot.keyVersion,
      )
    ) {
      throw invalid();
    }
    return restoreKnownRecordsVerificationV1Schema.parse({
      version: 1,
      scope: 'known-v1-records',
      vaultId: openedVault.id,
      vaultRevision: openedVault.revision,
      restoreSessionId: summary.restoreSessionId,
      transcriptSha256: summary.transcriptSha256,
      canonicalEntriesSha256: summary.canonicalEntriesSha256,
      recordCount: summary.recordCount,
      selectedSlot,
      verified: counts,
    });
  } catch (error) {
    if (error instanceof RestoreKnownRecordsVerificationError) throw error;
    throw invalid();
  } finally {
    if (!eof) {
      try {
        await iterator?.return?.();
      } catch {
        // Cleanup errors are deliberately hidden by the safe outer error.
      }
    }
    wipeOpened(groups.values());
    wipeOpened(items.values());
    wipeOpened(attachments.values());
    wipeOpened(predecessors.values());
  }
}

async function openAttachment(
  candidate: EncryptedAttachmentRecord,
  item: OpenItem,
  expectedState: 'active' | 'deleted' = candidate.tombstonedAt === undefined
    ? 'active'
    : 'deleted',
): Promise<OpenAttachment> {
  const parsed = encryptedAttachmentRecordSchema.parse(candidate);
  if (
    parsed.vaultId !== item.record.vaultId ||
    parsed.groupId !== item.record.groupId ||
    parsed.itemId !== item.record.id ||
    parsed.schemaVersion !== item.record.schemaVersion ||
    (expectedState === 'active'
      ? parsed.tombstonedAt !== undefined
      : parsed.tombstonedAt === undefined)
  ) {
    throw new CryptoAuthenticationError();
  }
  const keyVersion = parsed.wrappedAttachmentKey.keyVersion;
  const keyContext = associatedDataSchema.parse({
    version: 1,
    schemaVersion: parsed.schemaVersion,
    keyVersion,
    vaultId: parsed.vaultId,
    entityType: 'wrapped-attachment-key',
    entityId: parsed.id,
    groupId: parsed.groupId,
    parentId: parsed.itemId,
    purpose: 'attachment-key',
  });
  let key: AttachmentKey | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    key = await unwrapAttachmentKey(parsed.wrappedAttachmentKey, item.key, keyContext);
    plaintext = await decryptPayload(
      parsed.encryptedManifest,
      key,
      associatedDataSchema.parse({
        ...keyContext,
        entityType: 'attachment',
        purpose: 'attachment-metadata',
      }),
    );
    const manifest = parseCanonicalPayload(
      plaintext,
      attachmentSecretStreamManifestSchema,
    );
    if (
      manifest.schemaVersion !== parsed.schemaVersion ||
      manifest.keyVersion !== keyVersion ||
      manifest.vaultId !== parsed.vaultId ||
      manifest.groupId !== parsed.groupId ||
      manifest.itemId !== parsed.itemId ||
      manifest.attachmentId !== parsed.id ||
      manifest.chunkCount !== parsed.chunkCount
    ) {
      throw new CryptoAuthenticationError();
    }
    return { record: parsed, manifest, key, deleted: expectedState === 'deleted' };
  } catch {
    zeroize(key);
    throw new CryptoAuthenticationError();
  } finally {
    zeroize(plaintext);
  }
}

async function verifyAttachmentStream(
  iterator: AsyncIterator<EncryptedBackupEntry>,
  commitment: ReturnType<typeof createBackupStagedEntryCommitment>,
  attachment: OpenAttachment,
  counts: Counts,
  budget: { consumed: number; maximum: number },
  isClosed: () => boolean,
): Promise<void> {
  const sizes: number[] = [];
  let committed = false;
  let writeIndex = 0;
  const records = (async function* () {
    const needed = attachment.record.chunkCount + 1;
    for (let index = 0; index < needed; index += 1) {
      if (isClosed()) throw invalid();
      const next = await iterator.next();
      if (next.done) throw invalid();
      budget.consumed = add(budget.consumed, 1);
      if (budget.consumed > budget.maximum) throw invalid();
      const entry = encryptedBackupEntrySchema.parse(next.value);
      commitment.update(entry);
      if (!attachmentRecordHashEntry(entry)) throw invalid();
      const wrapper = entry.record;
      const nested = wrapper.record;
      if (
        wrapper.recordRevision !== attachment.record.recordRevision ||
        nested.schemaVersion !== attachment.record.schemaVersion ||
        nested.keyVersion !== attachment.record.wrappedAttachmentKey.keyVersion ||
        nested.vaultId !== attachment.record.vaultId ||
        nested.groupId !== attachment.record.groupId ||
        nested.itemId !== attachment.record.itemId ||
        nested.attachmentId !== attachment.record.id
      ) {
        throw invalid();
      }
      if (index === 0) {
        if (entry.kind !== 'attachment-header' || nested.recordType !== 'header') {
          throw invalid();
        }
        if (nested.header !== attachment.manifest.header) throw invalid();
        counts.attachmentHeaders = add(counts.attachmentHeaders, 1);
      } else {
        if (entry.kind !== 'attachment-chunk' || nested.recordType !== 'chunk') {
          throw invalid();
        }
        if (
          nested.index !== index - 1 ||
          nested.tag !== (index === needed - 1 ? 'final' : 'message')
        ) {
          throw invalid();
        }
        sizes.push(entry.record.plaintextBytes);
        counts.attachmentChunks = add(counts.attachmentChunks, 1);
      }
      yield nested;
    }
  })();
  await decryptAttachmentStreamToStager(
    records,
    attachment.key,
    associatedDataSchema.parse({
      version: 1,
      schemaVersion: attachment.record.schemaVersion,
      keyVersion: attachment.record.wrappedAttachmentKey.keyVersion,
      vaultId: attachment.record.vaultId,
      entityType: 'attachment-chunk',
      entityId: attachment.record.id,
      groupId: attachment.record.groupId,
      parentId: attachment.record.itemId,
      purpose: 'attachment-chunk',
    }),
    attachment.manifest,
    {
      write(chunk) {
        if (chunk.byteLength !== sizes[writeIndex]) throw invalid();
        writeIndex += 1;
      },
      commit() {
        if (writeIndex !== sizes.length) throw invalid();
        committed = true;
      },
      abort() {
        committed = false;
      },
    },
  );
  void committed;
}

function attachmentRecordHashEntry(
  entry: EncryptedBackupEntry,
): entry is Extract<
  EncryptedBackupEntry,
  { readonly kind: 'attachment-header' | 'attachment-chunk' }
> {
  return (
    (entry.kind === 'attachment-header' || entry.kind === 'attachment-chunk') &&
    attachmentRecordHashMatchesCanonicalContent(entry.record)
  );
}

function assertRelations(
  groups: ReadonlyMap<string, OpenGroup>,
  items: ReadonlyMap<string, OpenItem>,
  attachments: ReadonlyMap<string, OpenAttachment>,
  predecessors: ReadonlyMap<string, OpenGroup | OpenItem | OpenAttachment>,
  tombstones: ReadonlyMap<string, TombstoneRecord>,
): void {
  for (const [key, tombstone] of tombstones) {
    const predecessor = predecessors.get(key);
    if (tombstone.entityType === 'group') {
      const current = groups.get(tombstone.entityId);
      if (
        current === undefined ||
        (predecessor !== undefined && !isGroup(predecessor))
      ) {
        throw invalid();
      }
      assertGroupTombstoneRelation(current, tombstone, predecessor);
    } else if (tombstone.entityType === 'item') {
      const current = items.get(tombstone.entityId);
      if (
        current === undefined ||
        (predecessor !== undefined && !isItem(predecessor))
      ) {
        throw invalid();
      }
      assertItemTombstoneRelation(current, tombstone, predecessor);
    } else if (tombstone.entityType === 'attachment') {
      const current = attachments.get(tombstone.entityId);
      if (
        current === undefined ||
        (predecessor !== undefined && !isAttachment(predecessor))
      ) {
        throw invalid();
      }
      assertAttachmentRelation(current, tombstone, predecessor);
    } else {
      throw invalid();
    }
  }
  for (const [key, predecessor] of predecessors) {
    if (!tombstones.has(key)) throw invalid();
    void predecessor;
  }
  for (const group of groups.values()) {
    if (group.deleted !== tombstones.has(relationKey('group', group.record.id))) {
      const tombstone = tombstones.get(relationKey('group', group.record.id));
      if (group.deleted || tombstone?.state !== 'restored') throw invalid();
    }
  }
  for (const item of items.values()) {
    if (item.deleted !== tombstones.has(relationKey('item', item.record.id))) {
      const tombstone = tombstones.get(relationKey('item', item.record.id));
      if (item.deleted || tombstone?.state !== 'restored') throw invalid();
    }
  }
  for (const attachment of attachments.values()) {
    if (
      attachment.deleted !==
      tombstones.has(relationKey('attachment', attachment.record.id))
    ) {
      const tombstone = tombstones.get(relationKey('attachment', attachment.record.id));
      if (attachment.deleted || tombstone?.state !== 'restored') throw invalid();
    }
  }
}

function assertAttachmentRelation(
  current: OpenAttachment,
  tombstone: Extract<TombstoneRecord, { readonly entityType: 'attachment' }>,
  predecessor?: OpenAttachment,
): void {
  if (
    current.record.id !== tombstone.entityId ||
    current.record.vaultId !== tombstone.vaultId ||
    current.record.recordRevision !== tombstone.tombstoneRevision
  ) {
    throw invalid();
  }
  if (tombstone.state === 'deleted') {
    if (
      !current.deleted ||
      current.record.tombstonedAt !== tombstone.deletedAt ||
      predecessor === undefined ||
      predecessor.deleted ||
      predecessor.record.id !== current.record.id ||
      predecessor.record.vaultId !== current.record.vaultId ||
      predecessor.record.groupId !== current.record.groupId ||
      predecessor.record.itemId !== current.record.itemId ||
      predecessor.record.schemaVersion !== current.record.schemaVersion ||
      predecessor.record.recordRevision !== tombstone.lastRecordRevision ||
      contentHashForRecord(predecessor.record) !== tombstone.lastCiphertextHash
    ) {
      throw invalid();
    }
    if (
      canonicalJson(current.manifest) !== canonicalJson(predecessor.manifest) ||
      !constantTimeEqual(current.key, predecessor.key)
    ) {
      throw unsupported();
    }
  } else if (
    current.deleted ||
    current.record.tombstonedAt !== undefined ||
    predecessor !== undefined ||
    current.record.recordRevision !== tombstone.tombstoneRevision ||
    tombstone.restoredAt === undefined ||
    current.record.updatedAt !== tombstone.restoredAt
  ) {
    throw invalid();
  }
}

function observedCount(counts: Counts): number {
  return [
    counts.vaults,
    counts.groups,
    counts.items,
    counts.attachments,
    counts.attachmentHeaders,
    counts.attachmentChunks,
    counts.tombstonePredecessors.groups,
    counts.tombstonePredecessors.items,
    counts.tombstonePredecessors.attachments,
    counts.tombstones,
  ].reduce(add, 0);
}

function add(left: number, right: number): number {
  const result = left + right;
  if (!Number.isSafeInteger(result)) throw invalid();
  return result;
}

function relationKey(type: string, id: string): string {
  return `${type}:${id}`;
}

function requireVault(
  active: ActiveVault | undefined,
  vault: VaultRecord | undefined,
): readonly [ActiveVault, VaultRecord] {
  if (active === undefined || vault === undefined) throw invalid();
  return [active, vault];
}

function wipeOpened(values: Iterable<OpenGroup | OpenItem | OpenAttachment>): void {
  for (const value of values) zeroize(value.key);
}

function isGroup(value: OpenGroup | OpenItem | OpenAttachment): value is OpenGroup {
  return 'templateVersion' in value.record && !('groupId' in value.record);
}

function isItem(value: OpenGroup | OpenItem | OpenAttachment): value is OpenItem {
  return 'groupId' in value.record && !('itemId' in value.record);
}

function isAttachment(
  value: OpenGroup | OpenItem | OpenAttachment,
): value is OpenAttachment {
  return 'itemId' in value.record;
}

function invalid(): RestoreKnownRecordsVerificationError {
  return new RestoreKnownRecordsVerificationError('invalid');
}

function unsupported(): RestoreKnownRecordsVerificationError {
  return new RestoreKnownRecordsVerificationError('unsupported');
}
