import { createHash } from 'node:crypto';

import {
  createPassphraseKeySlot,
  createRecoveryKeySlot,
  encryptAttachmentStream,
  encryptPayload,
  formatPortableKey,
  formatRecoveryKey,
  generateAttachmentKey,
  generatePortableKey,
  generateRecoveryKey,
  unwrapGroupKey,
  unwrapItemKey,
  wrapAttachmentKey,
  zeroize,
} from '@kavrix/crypto';
import {
  associatedDataSchema,
  attachmentChunkCiphertextHash,
  attachmentHeaderContentHash,
  attachmentIdSchema,
  attachmentSecretStreamManifestSchema,
  auditEventIdSchema,
  backupVerificationSchema,
  contentHashForRecord,
  createBackupStagedEntryCommitment,
  encryptedAttachmentRecordSchema,
  encryptedAuditRecordSchema,
  encryptedBackupEntrySchema,
  encryptedHistoryRecordSchema,
  historyIdSchema,
  keySlotIdSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  sha256DigestSchema,
  timestampSchema,
  vaultPreferencesSchema,
  vaultRecordSchema,
  vaultRevisionSchema,
  type BackupVerification,
  type EncryptedBackupEntry,
  type VaultRecord,
} from '@kavrix/schemas';
import { describe, expect, it, vi } from 'vitest';

import {
  RestoreKnownRecordsVerificationError,
  createRestoreKnownRecordsVerificationSessionFactoryV1,
  type RestoreKnownRecordsCredentialV1,
  type RestoreKnownRecordsVerificationSessionFactoryV1,
} from '../src/backup-restore-verifier.js';
import {
  encryptGroupRecord,
  encryptItemRecord,
} from '../src/vault-mutation-records.js';
import { encryptedFixture, type EncryptedFixture } from './fixtures.js';

const timestamp = timestampSchema.parse('2026-08-12T00:00:00.000Z');
const slotId = keySlotIdSchema.parse('slot.client');

describe('known-record restore verifier', () => {
  it('authenticates an exact vault/group/item graph and returns a bound receipt only at EOF', async () => {
    const material = await fixture();
    try {
      const source = tracked(material.entries);
      const session = await material.factory(material.vault);
      const receipt = await session.verify(source, material.summary);

      expect(receipt).toMatchObject({
        version: 1,
        scope: 'known-v1-records',
        vaultId: material.vault.id,
        vaultRevision: material.vault.revision,
        selectedSlot: {
          id: slotId,
          type: 'portable-key',
          keyVersion: material.vault.currentKeyVersion,
        },
        verified: {
          vaults: 1,
          groups: 1,
          items: 1,
          attachments: 0,
          attachmentHeaders: 0,
          attachmentChunks: 0,
          tombstonePredecessors: { groups: 0, items: 0, attachments: 0 },
          tombstones: 0,
          histories: 0,
          audits: 0,
        },
      });
      expect(source.nextCalls).toBe(material.entries.length + 1);
      expect(source.returnCalls).toBe(0);
      expect(Object.isFrozen(session.selectedSlot)).toBe(true);
      session.close();
      session.close();
      await expect(session.verify(source, material.summary)).rejects.toEqual(
        safe('invalid'),
      );
    } finally {
      material.dispose();
    }
  });

  it('accepts an equal rollback anchor and rejects a lower archived revision', async () => {
    const material = await fixture();
    try {
      const equal = await createRestoreKnownRecordsVerificationSessionFactoryV1({
        credential: material.credential,
        highestSeenVaultRevision: vaultRevisionSchema.parse(material.vault.revision),
      })(material.vault);
      await expect(
        equal.verify(tracked(material.entries), material.summary),
      ).resolves.toBeDefined();
      equal.close();

      const ahead = await createRestoreKnownRecordsVerificationSessionFactoryV1({
        credential: material.credential,
        highestSeenVaultRevision: vaultRevisionSchema.parse(
          material.vault.revision + 1,
        ),
      })(material.vault);
      await expect(
        ahead.verify(tracked(material.entries), material.summary),
      ).rejects.toEqual(safe('invalid'));
      ahead.close();
    } finally {
      material.dispose();
    }
  });

  it('rejects substitution, wrong ordering, extra records, and iterator failures generically', async () => {
    const material = await fixture();
    try {
      const cases: readonly AsyncIterable<EncryptedBackupEntry>[] = [
        tracked(material.entries.slice(1)),
        tracked([...material.entries, material.entries[1]]),
        throwingIterable('record-id-canary'),
      ];
      for (const entries of cases) {
        const session = await material.makeFactory()(material.vault);
        await expect(session.verify(entries, material.summary)).rejects.toEqual(
          safe('invalid'),
        );
        session.close();
        if ('returnCalls' in entries) expect(entries.returnCalls).toBe(1);
      }

      const session = await material.makeFactory()(material.vault);
      await expect(
        session.verify(tracked(material.entries), {
          ...material.summary,
          canonicalEntriesSha256: digest('substituted'),
        }),
      ).rejects.toEqual(safe('invalid'));
      session.close();
    } finally {
      material.dispose();
    }
  });

  it('normalizes invalid factory inputs without leaking nested validation detail', async () => {
    const material = await fixture();
    try {
      await expect(
        material.factory({ id: 'plaintext-id-canary' } as never),
      ).rejects.toEqual(safe('invalid'));
      expect(() =>
        createRestoreKnownRecordsVerificationSessionFactoryV1(undefined as never),
      ).toThrow(safe('invalid'));
    } finally {
      material.dispose();
    }
  });

  it('closes a verification in flight, wipes the session key, and normalizes return/log canaries', async () => {
    const material = await fixture();
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      const session = await material.makeFactory()(material.vault);
      const controlled = controlledEntries(material.entries);
      const pending = session.verify(controlled.iterable, material.summary);
      await controlled.waiting;
      session.close();
      controlled.release();
      await expect(pending).rejects.toEqual(safe('invalid'));
      expect(controlled.returnCalls()).toBe(1);
      expect(session.vaultRootKey.every((byte) => byte === 0)).toBe(true);

      const returnThrows = tracked(material.entries.slice(1), true);
      const second = await material.makeFactory()(material.vault);
      const caught = await second
        .verify(returnThrows, material.summary)
        .catch((error: unknown) => error);
      expect(caught).toEqual(safe('invalid'));
      expect(String(caught)).not.toContain('iterator-return-canary');
      expect(consoleSpy).not.toHaveBeenCalled();
      second.close();
    } finally {
      consoleSpy.mockRestore();
      material.dispose();
    }
  });

  it('allows each credential factory exactly one unwrap attempt', async () => {
    const material = await fixture();
    try {
      const factory = material.makeFactory();
      const session = await factory(material.vault);
      await expect(factory(material.vault)).rejects.toEqual(safe('invalid'));
      session.close();
    } finally {
      material.dispose();
    }
  });

  it('selects passphrase and recovery slots and wipes only owned credential bytes', async () => {
    const material = await fixture();
    const passphrase = new TextEncoder().encode('restore verifier passphrase');
    const recoveryKey = generateRecoveryKey();
    try {
      const passphraseId = keySlotIdSchema.parse('slot.verifier.passphrase');
      const recoveryId = keySlotIdSchema.parse('slot.verifier.recovery');
      const identity = (
        slotId: typeof passphraseId,
      ): Parameters<typeof createPassphraseKeySlot>[0] => ({
        vaultId: material.vault.id,
        slotId,
        schemaVersion: material.vault.schemaVersion,
        keyVersion: material.vault.currentKeyVersion,
        createdAt: timestamp,
      });
      const vault = vaultRecordSchema.parse({
        ...material.vault,
        keySlots: [
          ...material.vault.keySlots,
          await createPassphraseKeySlot(
            identity(passphraseId),
            passphrase,
            material.rootKey,
          ),
          await createRecoveryKeySlot(
            identity(recoveryId),
            recoveryKey,
            material.rootKey,
          ),
        ],
      });
      const entries = replaceVault(material.entries, vault);
      const summary = summaryFor(entries, vault);
      const credentials = [
        { type: 'passphrase' as const, slotId: passphraseId, passphrase },
        {
          type: 'recovery-key' as const,
          slotId: recoveryId,
          formattedKey: formatRecoveryKey(recoveryKey),
        },
      ];
      for (const credential of credentials) {
        const session = await createRestoreKnownRecordsVerificationSessionFactoryV1({
          credential,
        })(vault);
        await expect(session.verify(tracked(entries), summary)).resolves.toMatchObject({
          selectedSlot: { id: credential.slotId, type: credential.type },
        });
        session.close();
      }
      expect(passphrase).toEqual(
        new TextEncoder().encode('restore verifier passphrase'),
      );
    } finally {
      zeroize(passphrase);
      zeroize(recoveryKey);
      material.dispose();
    }
  });

  it.each([
    ['one-message', [new TextEncoder().encode('one')]],
    [
      'multi-message',
      [new TextEncoder().encode('one'), new TextEncoder().encode('two')],
    ],
    ['zero-byte', []],
  ] as const)('authenticates %s attachment streams', async (_name, chunks) => {
    const material = await fixture();
    try {
      const attachment = await attachmentEntries(material, chunks);
      const entries = [...material.entries, ...attachment.entries];
      const summary = summaryFor(entries, material.vault);
      const session = await material.makeFactory()(material.vault);
      await expect(session.verify(tracked(entries), summary)).resolves.toMatchObject({
        verified: {
          attachments: 1,
          attachmentHeaders: 1,
          attachmentChunks: Math.max(1, chunks.length),
        },
      });
      session.close();
    } finally {
      for (const chunk of chunks) zeroize(chunk);
      material.dispose();
    }
  });

  it('rejects attachment wrapper hash, plaintext-size, order, and manifest bindings generically', async () => {
    const material = await fixture();
    try {
      const attachment = await attachmentEntries(material, [
        new TextEncoder().encode('attachment-canary'),
      ]);
      const good = [...material.entries, ...attachment.entries];
      const mutations = [
        (entries: EncryptedBackupEntry[]) => {
          const chunk = entries.at(-1) as Extract<
            EncryptedBackupEntry,
            { kind: 'attachment-chunk' }
          >;
          entries[entries.length - 1] = encryptedBackupEntrySchema.parse({
            ...chunk,
            record: { ...chunk.record, ciphertextHash: digest('wrong-hash') },
          });
        },
        (entries: EncryptedBackupEntry[]) => {
          const chunk = entries.at(-1) as Extract<
            EncryptedBackupEntry,
            { kind: 'attachment-chunk' }
          >;
          entries[entries.length - 1] = {
            ...chunk,
            record: {
              ...chunk.record,
              plaintextBytes: chunk.record.plaintextBytes + 1,
            },
          };
        },
        (entries: EncryptedBackupEntry[]) => {
          const headerIndex = material.entries.length + 1;
          const header = required(entries[headerIndex]);
          const chunk = required(entries[headerIndex + 1]);
          [entries[headerIndex], entries[headerIndex + 1]] = [chunk, header];
        },
      ];
      for (const mutate of mutations) {
        const entries = structuredClone(good);
        mutate(entries);
        const session = await material.makeFactory()(material.vault);
        await expect(
          session.verify(tracked(entries), summaryFor(good, material.vault)),
        ).rejects.toEqual(safe('invalid'));
        session.close();
      }
    } finally {
      material.dispose();
    }
  });

  it('rejects authenticated-graph attachment parent, manifest, ciphertext, FINAL, and truncation failures', async () => {
    const material = await fixture();
    try {
      const attachment = await attachmentEntries(material, [
        new TextEncoder().encode('crypto-canary'),
      ]);
      const good = [...material.entries, ...attachment.entries];
      const cases: EncryptedBackupEntry[][] = [];

      const corruptManifest = structuredClone(good);
      const attachmentIndex = material.entries.length;
      const attachmentEntry = corruptManifest[attachmentIndex] as Extract<
        EncryptedBackupEntry,
        { kind: 'attachment' }
      >;
      const manifestBytes = Buffer.from(
        attachmentEntry.record.encryptedManifest.ciphertext,
        'base64url',
      );
      manifestBytes[0] = (manifestBytes[0] ?? 0) ^ 1;
      corruptManifest[attachmentIndex] = encryptedBackupEntrySchema.parse({
        ...attachmentEntry,
        record: {
          ...attachmentEntry.record,
          encryptedManifest: {
            ...attachmentEntry.record.encryptedManifest,
            ciphertext: manifestBytes.toString('base64url'),
          },
        },
      });
      cases.push(corruptManifest);

      const corruptChunk = structuredClone(good);
      const last = corruptChunk.at(-1) as Extract<
        EncryptedBackupEntry,
        { kind: 'attachment-chunk' }
      >;
      const cipher = Buffer.from(last.record.record.ciphertext, 'base64url');
      cipher[0] = (cipher[0] ?? 0) ^ 1;
      const changedChunk = persistedAttachmentChunkRecordSchema.parse({
        ...last.record,
        record: { ...last.record.record, ciphertext: cipher.toString('base64url') },
        ciphertextHash: digest('placeholder'),
      });
      corruptChunk[corruptChunk.length - 1] = encryptedBackupEntrySchema.parse({
        kind: 'attachment-chunk',
        record: {
          ...changedChunk,
          ciphertextHash: attachmentChunkCiphertextHash(changedChunk),
        },
      });
      cases.push(corruptChunk);

      const wrongFinal = structuredClone(good);
      const finalEntry = wrongFinal.at(-1) as Extract<
        EncryptedBackupEntry,
        { kind: 'attachment-chunk' }
      >;
      wrongFinal[wrongFinal.length - 1] = encryptedBackupEntrySchema.parse({
        ...finalEntry,
        record: {
          ...finalEntry.record,
          record: { ...finalEntry.record.record, tag: 'message' },
        },
      });
      cases.push(wrongFinal);
      cases.push(good.slice(0, -1));

      const wrongParent = structuredClone(good);
      const wrongRecord = wrongParent[attachmentIndex] as Extract<
        EncryptedBackupEntry,
        { kind: 'attachment' }
      >;
      wrongParent[attachmentIndex] = encryptedBackupEntrySchema.parse({
        ...wrongRecord,
        record: {
          ...wrongRecord.record,
          itemId: 'item.missing',
          wrappedAttachmentKey: {
            ...wrongRecord.record.wrappedAttachmentKey,
            aad: {
              ...wrongRecord.record.wrappedAttachmentKey.aad,
              parentId: 'item.missing',
            },
          },
          encryptedManifest: {
            ...wrongRecord.record.encryptedManifest,
            aad: {
              ...wrongRecord.record.encryptedManifest.aad,
              parentId: 'item.missing',
            },
          },
        },
      });
      cases.push(wrongParent);

      for (const entries of cases) {
        const session = await material.makeFactory()(material.vault);
        await expect(
          session.verify(tracked(entries), summaryFor(entries, material.vault)),
        ).rejects.toEqual(safe('invalid'));
        session.close();
      }
    } finally {
      material.dispose();
    }
  });

  it('rejects schema-valid opaque history and audit records as unsupported before crypto semantics', async () => {
    const material = await fixture();
    try {
      const group = material.groups[0];
      const item = group === undefined ? undefined : material.items.get(group.id)?.[0];
      if (group === undefined || item === undefined) throw new Error('fixture');
      const historyId = historyIdSchema.parse('history.restore.verifier');
      const history = encryptedHistoryRecordSchema.parse({
        id: historyId,
        vaultId: material.vault.id,
        groupId: group.id,
        itemId: item.id,
        schemaVersion: material.vault.schemaVersion,
        encryptedPayload: {
          ...item.encryptedPayload,
          aad: associatedDataSchema.parse({
            version: 1,
            schemaVersion: material.vault.schemaVersion,
            keyVersion: material.vault.currentKeyVersion,
            vaultId: material.vault.id,
            entityType: 'history',
            entityId: historyId,
            groupId: group.id,
            parentId: item.id,
            purpose: 'history-event',
          }),
        },
        itemRecordRevision: item.recordRevision,
        ciphertextHash: digest('history-ciphertext'),
        createdAt: timestamp,
      });
      const auditId = auditEventIdSchema.parse('audit.restore.verifier');
      const audit = encryptedAuditRecordSchema.parse({
        id: auditId,
        vaultId: material.vault.id,
        schemaVersion: material.vault.schemaVersion,
        encryptedPayload: {
          ...item.encryptedPayload,
          aad: associatedDataSchema.parse({
            version: 1,
            schemaVersion: material.vault.schemaVersion,
            keyVersion: material.vault.currentKeyVersion,
            vaultId: material.vault.id,
            entityType: 'audit-event',
            entityId: auditId,
            purpose: 'audit-event',
          }),
        },
        recordRevision: 1,
        createdAt: timestamp,
      });
      for (const unsupportedEntry of [
        encryptedBackupEntrySchema.parse({ kind: 'history', record: history }),
        encryptedBackupEntrySchema.parse({ kind: 'audit', record: audit }),
      ]) {
        const entries = [material.entries[0], unsupportedEntry];
        const source = tracked(entries);
        const session = await material.makeFactory()(material.vault);
        await expect(
          session.verify(source, summaryFor(entries, material.vault)),
        ).rejects.toEqual(safe('unsupported'));
        expect(source.returnCalls).toBe(1);
        session.close();
      }
    } finally {
      material.dispose();
    }
  });

  it('verifies deleted and restored group tombstone closure and rejects reordered closure', async () => {
    const material = await fixture();
    const predecessor = material.groups[0];
    if (predecessor === undefined) throw new Error('fixture');
    const groupKey = await unwrapGroupKey(
      predecessor.wrappedGroupKey,
      material.rootKey,
      predecessor.wrappedGroupKey.aad,
    );
    try {
      const deletedAt = timestampSchema.parse('2026-08-12T01:00:00.000Z');
      const payload = {
        ...material.groupPayloads[0],
        revision: 2,
        updatedAt: deletedAt,
        deletedAt,
      } as never;
      const current = await encryptGroupRecord(
        payload,
        groupKey,
        material.rootKey,
        {
          schemaVersion: material.vault.schemaVersion,
          keyVersion: material.vault.currentKeyVersion,
        },
        predecessor.wrappedGroupKey,
        deletedAt,
      );
      const tombstone = {
        vaultId: material.vault.id,
        entityType: 'group' as const,
        entityId: current.id,
        state: 'deleted' as const,
        tombstoneRevision: current.recordRevision,
        lastRecordRevision: predecessor.recordRevision,
        lastCiphertextHash: contentHashForRecord(predecessor),
        deletedAt,
      };
      const entries = [
        material.entries[0],
        encryptedBackupEntrySchema.parse({ kind: 'group', record: current }),
        encryptedBackupEntrySchema.parse({
          kind: 'tombstone-predecessor',
          entityType: 'group',
          record: predecessor,
        }),
        encryptedBackupEntrySchema.parse({ kind: 'tombstone', record: tombstone }),
      ];
      const session = await material.makeFactory()(material.vault);
      await expect(
        session.verify(tracked(entries), summaryFor(entries, material.vault)),
      ).resolves.toMatchObject({
        verified: {
          groups: 1,
          tombstonePredecessors: { groups: 1 },
          tombstones: 1,
        },
      });
      session.close();

      const reordered = [
        entries[0],
        entries[1],
        entries[3],
        entries[2],
      ] as EncryptedBackupEntry[];
      const rejected = await material.makeFactory()(material.vault);
      await expect(
        rejected.verify(tracked(reordered), summaryFor(reordered, material.vault)),
      ).rejects.toEqual(safe('invalid'));
      rejected.close();

      const restoredAt = timestampSchema.parse('2026-08-12T02:00:00.000Z');
      const restoredPayload = {
        ...material.groupPayloads[0],
        revision: 3,
        updatedAt: restoredAt,
      } as never;
      const restored = await encryptGroupRecord(
        restoredPayload,
        groupKey,
        material.rootKey,
        {
          schemaVersion: material.vault.schemaVersion,
          keyVersion: material.vault.currentKeyVersion,
        },
        predecessor.wrappedGroupKey,
      );
      const restoredEntries = [
        material.entries[0],
        encryptedBackupEntrySchema.parse({ kind: 'group', record: restored }),
        encryptedBackupEntrySchema.parse({
          kind: 'tombstone',
          record: {
            vaultId: material.vault.id,
            entityType: 'group',
            entityId: restored.id,
            state: 'restored',
            tombstoneRevision: restored.recordRevision,
            lastRecordRevision: 2,
            lastCiphertextHash: digest('deleted-group'),
            deletedAt,
            restoredAt,
          },
        }),
      ];
      const restoredSession = await material.makeFactory()(material.vault);
      await expect(
        restoredSession.verify(
          tracked(restoredEntries),
          summaryFor(restoredEntries, material.vault),
        ),
      ).resolves.toMatchObject({ verified: { groups: 1, tombstones: 1 } });
      restoredSession.close();
    } finally {
      zeroize(groupKey);
      material.dispose();
    }
  });

  it('verifies deleted item predecessor/tombstone closure and rejects missing predecessors', async () => {
    const material = await fixture();
    const group = material.groups[0];
    const predecessor =
      group === undefined ? undefined : material.items.get(group.id)?.[0];
    if (group === undefined || predecessor === undefined) throw new Error('fixture');
    const groupKey = await unwrapGroupKey(
      group.wrappedGroupKey,
      material.rootKey,
      group.wrappedGroupKey.aad,
    );
    const itemKey = await unwrapItemKey(
      predecessor.wrappedItemKey,
      groupKey,
      predecessor.wrappedItemKey.aad,
    );
    try {
      const deletedAt = timestampSchema.parse('2026-08-12T03:00:00.000Z');
      const payload = {
        ...material.itemPayloads[0],
        revision: 2,
        updatedAt: deletedAt,
        deletedAt,
      } as never;
      const current = await encryptItemRecord(
        payload,
        itemKey,
        groupKey,
        {
          schemaVersion: material.vault.schemaVersion,
          keyVersion: material.vault.currentKeyVersion,
        },
        predecessor.wrappedItemKey,
        deletedAt,
      );
      const tombstone = encryptedBackupEntrySchema.parse({
        kind: 'tombstone',
        record: {
          vaultId: material.vault.id,
          entityType: 'item',
          entityId: current.id,
          state: 'deleted',
          tombstoneRevision: current.recordRevision,
          lastRecordRevision: predecessor.recordRevision,
          lastCiphertextHash: contentHashForRecord(predecessor),
          deletedAt,
        },
      });
      const base = [
        material.entries[0],
        material.entries[1],
        encryptedBackupEntrySchema.parse({ kind: 'item', record: current }),
      ];
      const predecessorEntry = encryptedBackupEntrySchema.parse({
        kind: 'tombstone-predecessor',
        entityType: 'item',
        record: predecessor,
      });
      const good = [...base, predecessorEntry, tombstone];
      const session = await material.makeFactory()(material.vault);
      await expect(
        session.verify(tracked(good), summaryFor(good, material.vault)),
      ).resolves.toMatchObject({
        verified: { items: 1, tombstonePredecessors: { items: 1 }, tombstones: 1 },
      });
      session.close();
      const missing = [...base, tombstone];
      const rejected = await material.makeFactory()(material.vault);
      await expect(
        rejected.verify(tracked(missing), summaryFor(missing, material.vault)),
      ).rejects.toEqual(safe('invalid'));
      rejected.close();
    } finally {
      zeroize(groupKey);
      zeroize(itemKey);
      material.dispose();
    }
  });

  it('verifies deleted/restored attachments and rejects unequal deleted predecessor semantics', async () => {
    const material = await fixture();
    try {
      const first = await attachmentEntries(material, [
        new TextEncoder().encode('same'),
      ]);
      const deletedAt = timestampSchema.parse('2026-08-12T04:00:00.000Z');
      const current = encryptedAttachmentRecordSchema.parse({
        ...first.record,
        recordRevision: 2,
        updatedAt: deletedAt,
        tombstonedAt: deletedAt,
      });
      const wrappers = first.entries.slice(1).map((entry) =>
        encryptedBackupEntrySchema.parse({
          ...entry,
          record: { ...entry.record, recordRevision: current.recordRevision },
        }),
      );
      const predecessor = encryptedBackupEntrySchema.parse({
        kind: 'tombstone-predecessor',
        entityType: 'attachment',
        record: first.record,
      });
      const tombstone = encryptedBackupEntrySchema.parse({
        kind: 'tombstone',
        record: {
          vaultId: material.vault.id,
          entityType: 'attachment',
          entityId: current.id,
          state: 'deleted',
          tombstoneRevision: current.recordRevision,
          lastRecordRevision: first.record.recordRevision,
          lastCiphertextHash: contentHashForRecord(first.record),
          deletedAt,
        },
      });
      const prefix = material.entries;
      const good = [
        ...prefix,
        encryptedBackupEntrySchema.parse({ kind: 'attachment', record: current }),
        ...wrappers,
        predecessor,
        tombstone,
      ];
      const session = await material.makeFactory()(material.vault);
      await expect(
        session.verify(tracked(good), summaryFor(good, material.vault)),
      ).resolves.toMatchObject({
        verified: {
          attachments: 1,
          tombstonePredecessors: { attachments: 1 },
          tombstones: 1,
        },
      });
      session.close();

      const unequal = await attachmentEntries(material, [
        new TextEncoder().encode('different'),
      ]);
      const unequalPredecessor = encryptedBackupEntrySchema.parse({
        kind: 'tombstone-predecessor',
        entityType: 'attachment',
        record: unequal.record,
      });
      const unequalTombstone = encryptedBackupEntrySchema.parse({
        ...tombstone,
        record: {
          ...tombstone.record,
          lastCiphertextHash: contentHashForRecord(unequal.record),
        },
      });
      const bad = [
        ...prefix,
        encryptedBackupEntrySchema.parse({ kind: 'attachment', record: current }),
        ...wrappers,
        unequalPredecessor,
        unequalTombstone,
      ];
      const rejected = await material.makeFactory()(material.vault);
      await expect(
        rejected.verify(tracked(bad), summaryFor(bad, material.vault)),
      ).rejects.toEqual(safe('unsupported'));
      rejected.close();

      const restoredAt = timestampSchema.parse('2026-08-12T05:00:00.000Z');
      const restored = encryptedAttachmentRecordSchema.parse({
        ...first.record,
        recordRevision: 3,
        updatedAt: restoredAt,
      });
      const restoredWrappers = first.entries.slice(1).map((entry) =>
        encryptedBackupEntrySchema.parse({
          ...entry,
          record: { ...entry.record, recordRevision: restored.recordRevision },
        }),
      );
      const restoredEntries = [
        ...prefix,
        encryptedBackupEntrySchema.parse({ kind: 'attachment', record: restored }),
        ...restoredWrappers,
        encryptedBackupEntrySchema.parse({
          kind: 'tombstone',
          record: {
            vaultId: material.vault.id,
            entityType: 'attachment',
            entityId: restored.id,
            state: 'restored',
            tombstoneRevision: restored.recordRevision,
            lastRecordRevision: 2,
            lastCiphertextHash: digest('deleted-attachment'),
            deletedAt,
            restoredAt,
          },
        }),
      ];
      const restoredSession = await material.makeFactory()(material.vault);
      await expect(
        restoredSession.verify(
          tracked(restoredEntries),
          summaryFor(restoredEntries, material.vault),
        ),
      ).resolves.toMatchObject({ verified: { attachments: 1, tombstones: 1 } });
      restoredSession.close();
    } finally {
      material.dispose();
    }
  });
});

async function fixture(): Promise<
  EncryptedFixture &
    Readonly<{
      vault: VaultRecord;
      entries: readonly EncryptedBackupEntry[];
      summary: BackupVerification;
      credential: RestoreKnownRecordsCredentialV1;
      factory: RestoreKnownRecordsVerificationSessionFactoryV1;
      makeFactory: () => RestoreKnownRecordsVerificationSessionFactoryV1;
      dispose: () => void;
    }>
> {
  const portableKey = generatePortableKey();
  const formattedKey = formatPortableKey(portableKey);
  const source = await encryptedFixture({ portableKey });
  const preferences = vaultPreferencesSchema.parse({
    productLabel: 'CredVault',
    executableName: 'creds',
    clipboardClearSeconds: 30,
    revealHideSeconds: 15,
    historyRetentionDays: 90,
    telemetryEnabled: false,
  });
  const vault = vaultRecordSchema.parse({
    ...source.vault,
    encryptedPreferences: await encryptPayload(
      new TextEncoder().encode(JSON.stringify(preferences)),
      source.rootKey,
      associatedDataSchema.parse({
        version: 1,
        schemaVersion: source.vault.schemaVersion,
        keyVersion: source.vault.currentKeyVersion,
        vaultId: source.vault.id,
        entityType: 'vault-preferences',
        entityId: source.vault.id,
        purpose: 'vault-preferences',
      }),
    ),
  });
  const entries = [
    encryptedBackupEntrySchema.parse({ kind: 'vault', record: vault }),
    encryptedBackupEntrySchema.parse({ kind: 'group', record: source.groups[0] }),
    encryptedBackupEntrySchema.parse({
      kind: 'item',
      record: source.items.get(source.groups[0]?.id ?? '')?.[0],
    }),
  ] as const;
  const commitment = createBackupStagedEntryCommitment();
  for (const entry of entries) commitment.update(entry);
  const summary: BackupVerification = backupVerificationSchema.parse({
    header: {
      type: 'header',
      format: 'kavrix-encrypted-backup',
      version: 1,
      vaultId: vault.id,
      schemaVersion: vault.schemaVersion,
      createdAt: timestamp,
      authentication: {
        algorithm: 'hkdf-sha256+hmac-sha256',
        salt: Buffer.alloc(32, 11).toString('base64url'),
      },
    },
    restoreSessionId: digest('restore-session'),
    recordCount: entries.length,
    transcriptSha256: digest('transcript'),
    canonicalEntriesSha256: commitment.finalize(),
  });
  const credential = { type: 'portable-key' as const, slotId, formattedKey };
  const factory = createRestoreKnownRecordsVerificationSessionFactoryV1({
    credential,
  });
  return {
    ...source,
    vault,
    entries,
    summary,
    credential,
    factory,
    makeFactory: () =>
      createRestoreKnownRecordsVerificationSessionFactoryV1({ credential }),
    dispose() {
      zeroize(portableKey);
      zeroize(source.rootKey);
    },
  };
}

function tracked(
  entries: readonly EncryptedBackupEntry[],
  throwOnReturn = false,
): AsyncIterable<EncryptedBackupEntry> & { nextCalls: number; returnCalls: number } {
  let index = 0;
  return {
    nextCalls: 0,
    returnCalls: 0,
    [Symbol.asyncIterator]() {
      return {
        next: () => {
          this.nextCalls += 1;
          return Promise.resolve(
            index < entries.length
              ? { done: false as const, value: required(entries[index++]) }
              : { done: true as const, value: undefined },
          );
        },
        return: () => {
          this.returnCalls += 1;
          return throwOnReturn
            ? Promise.reject(new Error('iterator-return-canary'))
            : Promise.resolve({ done: true as const, value: undefined });
        },
      };
    },
  };
}

function controlledEntries(entries: readonly EncryptedBackupEntry[]): Readonly<{
  waiting: Promise<void>;
  release: () => void;
  returnCalls: () => number;
  iterable: AsyncIterable<EncryptedBackupEntry>;
}> {
  let index = 0;
  let returnCalls = 0;
  let signalWaiting: (() => void) | undefined;
  let release: (() => void) | undefined;
  const waiting = new Promise<void>((resolve) => {
    signalWaiting = resolve;
  });
  const barrier = new Promise<void>((resolve) => {
    release = resolve;
  });
  return {
    waiting,
    release: () => release?.(),
    returnCalls: () => returnCalls,
    iterable: {
      [Symbol.asyncIterator]() {
        return {
          next: async () => {
            if (index === 1) {
              signalWaiting?.();
              await barrier;
            }
            return index < entries.length
              ? {
                  done: false as const,
                  value: required(entries[index++]),
                }
              : { done: true as const, value: undefined };
          },
          return: () => {
            returnCalls += 1;
            return Promise.resolve({ done: true as const, value: undefined });
          },
        };
      },
    },
  };
}

function throwingIterable(canary: string): AsyncIterable<EncryptedBackupEntry> {
  return {
    [Symbol.asyncIterator]() {
      return {
        next: () => Promise.reject(new Error(canary)),
        return: () => Promise.resolve({ done: true, value: undefined }),
      };
    },
  };
}

function digest(value: string): ReturnType<typeof sha256DigestSchema.parse> {
  return sha256DigestSchema.parse(
    createHash('sha256').update(value).digest('base64url'),
  );
}

function replaceVault(
  entries: readonly EncryptedBackupEntry[],
  vault: VaultRecord,
): EncryptedBackupEntry[] {
  return [
    encryptedBackupEntrySchema.parse({ kind: 'vault', record: vault }),
    ...entries.slice(1),
  ];
}

function summaryFor(
  entries: readonly EncryptedBackupEntry[],
  vault: VaultRecord,
): BackupVerification {
  const commitment = createBackupStagedEntryCommitment();
  for (const entry of entries)
    commitment.update(encryptedBackupEntrySchema.parse(entry));
  return backupVerificationSchema.parse({
    header: {
      type: 'header',
      format: 'kavrix-encrypted-backup',
      version: 1,
      vaultId: vault.id,
      schemaVersion: vault.schemaVersion,
      createdAt: timestamp,
      authentication: {
        algorithm: 'hkdf-sha256+hmac-sha256',
        salt: Buffer.alloc(32, 11).toString('base64url'),
      },
    },
    restoreSessionId: digest('restore-session'),
    recordCount: entries.length,
    transcriptSha256: digest('transcript'),
    canonicalEntriesSha256: commitment.finalize(),
  });
}

async function attachmentEntries(
  material: Awaited<ReturnType<typeof fixture>>,
  chunks: readonly Uint8Array[],
): Promise<
  Readonly<{
    record: ReturnType<typeof encryptedAttachmentRecordSchema.parse>;
    entries: readonly EncryptedBackupEntry[];
  }>
> {
  const group = material.groups[0];
  const item = group === undefined ? undefined : material.items.get(group.id)?.[0];
  if (group === undefined || item === undefined) throw new Error('fixture');
  const groupKey = await unwrapGroupKey(
    group.wrappedGroupKey,
    material.rootKey,
    group.wrappedGroupKey.aad,
  );
  const itemKey = await unwrapItemKey(
    item.wrappedItemKey,
    groupKey,
    item.wrappedItemKey.aad,
  );
  const attachmentKey = generateAttachmentKey();
  const attachmentId = attachmentIdSchema.parse('attachment.restore.verifier');
  const keyVersion = material.vault.currentKeyVersion;
  const streamContext = associatedDataSchema.parse({
    version: 1,
    schemaVersion: material.vault.schemaVersion,
    keyVersion,
    vaultId: material.vault.id,
    entityType: 'attachment-chunk',
    entityId: attachmentId,
    groupId: group.id,
    parentId: item.id,
    purpose: 'attachment-chunk',
  });
  try {
    const stream = encryptAttachmentStream(chunks, attachmentKey, streamContext);
    const streamRecords = [];
    let manifest;
    for (;;) {
      const next = await stream.next();
      if (next.done) {
        manifest = attachmentSecretStreamManifestSchema.parse(next.value);
        break;
      }
      streamRecords.push(next.value);
    }
    const record = encryptedAttachmentRecordSchema.parse({
      id: attachmentId,
      vaultId: material.vault.id,
      groupId: group.id,
      itemId: item.id,
      schemaVersion: material.vault.schemaVersion,
      wrappedAttachmentKey: await wrapAttachmentKey(
        attachmentKey,
        itemKey,
        associatedDataSchema.parse({
          ...streamContext,
          entityType: 'wrapped-attachment-key',
          purpose: 'attachment-key',
        }),
      ),
      encryptedManifest: await encryptPayload(
        new TextEncoder().encode(JSON.stringify(manifest)),
        attachmentKey,
        associatedDataSchema.parse({
          ...streamContext,
          entityType: 'attachment',
          purpose: 'attachment-metadata',
        }),
      ),
      chunkCount: manifest.chunkCount,
      recordRevision: 1,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    const headerRecord = streamRecords[0];
    if (headerRecord?.recordType !== 'header') throw new Error('fixture');
    const initialHeader = persistedAttachmentHeaderRecordSchema.parse({
      entityType: 'attachment-header',
      record: headerRecord,
      recordRevision: record.recordRevision,
      contentHash: digest('placeholder'),
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    const wrappers: EncryptedBackupEntry[] = [
      encryptedBackupEntrySchema.parse({ kind: 'attachment', record }),
      encryptedBackupEntrySchema.parse({
        kind: 'attachment-header',
        record: {
          ...initialHeader,
          contentHash: attachmentHeaderContentHash(initialHeader),
        },
      }),
    ];
    for (const streamRecord of streamRecords.slice(1)) {
      if (streamRecord.recordType !== 'chunk') throw new Error('fixture');
      const initialChunk = persistedAttachmentChunkRecordSchema.parse({
        entityType: 'attachment-chunk',
        record: streamRecord,
        plaintextBytes:
          Buffer.from(streamRecord.ciphertext, 'base64url').byteLength - 17,
        recordRevision: record.recordRevision,
        ciphertextHash: digest('placeholder'),
        createdAt: timestamp,
        updatedAt: timestamp,
      });
      wrappers.push(
        encryptedBackupEntrySchema.parse({
          kind: 'attachment-chunk',
          record: {
            ...initialChunk,
            ciphertextHash: attachmentChunkCiphertextHash(initialChunk),
          },
        }),
      );
    }
    return { record, entries: wrappers };
  } finally {
    zeroize(groupKey);
    zeroize(itemKey);
    zeroize(attachmentKey);
  }
}

function safe(kind: 'invalid' | 'unsupported'): RestoreKnownRecordsVerificationError {
  return new RestoreKnownRecordsVerificationError(kind);
}

function required<T>(value: T | undefined): T {
  if (value === undefined) throw new Error('Missing test fixture value');
  return value;
}
