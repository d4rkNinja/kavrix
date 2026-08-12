import { createHash, createHmac, hkdfSync } from 'node:crypto';

import {
  createPortableKeySlot,
  cloneSecretKey,
  encryptPayload,
  generateGroupKey,
  generatePortableKey,
  generateVaultRootKey,
  wrapGroupKey,
  zeroize,
} from '@kavrix/crypto';
import {
  associatedDataSchema,
  attachmentChunkCiphertextHash,
  attachmentHeaderContentHash,
  backupRestoreStatusSchema,
  canonicalJson,
  contentHashForRecord,
  createBackupStagedEntryCommitment,
  encryptedAttachmentRecordSchema,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  groupIdSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  keySlotIdSchema,
  recordRevisionSchema,
  restoreKnownRecordsVerificationV1Schema,
  sha256DigestSchema,
  timestampSchema,
  tombstoneRecordSchema,
  vaultIdSchema,
  vaultRecordSchema,
  type EncryptedGroupRecord,
  type EncryptedAttachmentRecord,
  type EncryptedItemRecord,
  type PersistedAttachmentChunkRecord,
  type PersistedAttachmentHeaderRecord,
  type VaultRecord,
  type BackupRestoreStatus,
  type BackupVerification,
  type ResolvedBackupLimits,
  type RestoreKnownRecordsVerificationV1,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import {
  BackupError,
  createEncryptedBackup,
  restoreEncryptedBackup,
  verifyEncryptedBackup,
  type BackupRestoreStager,
  type BackupRestoreStore,
  type EncryptedBackupEntry,
  type RestoreVerificationSessionFactory,
} from '../src/index.js';

const CREATED_AT = timestampSchema.parse('2026-08-10T00:00:00.000Z');
const VAULT_ID = vaultIdSchema.parse('vault-1');
const OTHER_VAULT_ID = vaultIdSchema.parse('vault-2');
const GROUP_ID = groupIdSchema.parse('group-1');
const ITEM_ID = 'item-1';
const ATTACHMENT_ID = 'attachment-1';
const DIGEST = sha256DigestSchema.parse('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
const PLAINTEXT_CANARY = 'KAVRIX-BACKUP-PLAINTEXT-CANARY';

describe('encrypted backup streaming format', () => {
  it('round-trips authenticated ciphertext records without exposing plaintext', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          {
            vault: fixture.vault,
            records: entries({ kind: 'group', record: fixture.group }),
            createdAt: CREATED_AT,
          },
          fixture.rootKey,
        ),
      );

      expect(bytes.toString('utf8')).not.toContain(PLAINTEXT_CANARY);
      await expect(
        verifyEncryptedBackup(chunks(bytes, 7), fixture.rootKey, VAULT_ID),
      ).resolves.toMatchObject({ recordCount: 2 });
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('rejects the wrong root key and a modified authentication footer', async () => {
    const fixture = await createFixture();
    const wrongKey = generateVaultRootKey();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          {
            vault: fixture.vault,
            records: entries({ kind: 'group', record: fixture.group }),
            createdAt: CREATED_AT,
          },
          fixture.rootKey,
        ),
      );

      await expect(
        verifyEncryptedBackup(chunks(bytes), wrongKey, VAULT_ID),
      ).rejects.toMatchObject({ code: 'BACKUP_AUTHENTICATION_FAILED' });

      const lines = bytes.toString('utf8').trimEnd().split('\n');
      const footer = JSON.parse(lines.at(-1) ?? '') as Record<string, unknown>;
      footer['authenticationTag'] = sha256DigestSchema.parse(
        Buffer.alloc(32).toString('base64url'),
      );
      lines[lines.length - 1] = JSON.stringify(footer);
      const modified = Buffer.from(`${lines.join('\n')}\n`, 'utf8');
      await expect(
        verifyEncryptedBackup(chunks(modified), fixture.rootKey, VAULT_ID),
      ).rejects.toMatchObject({ code: 'BACKUP_AUTHENTICATION_FAILED' });
    } finally {
      zeroize(fixture.rootKey);
      zeroize(wrongKey);
    }
  });

  it('keeps restore staging hidden and aborts it when authentication fails', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          {
            vault: fixture.vault,
            records: entries({ kind: 'group', record: fixture.group }),
            createdAt: CREATED_AT,
          },
          fixture.rootKey,
        ),
      );
      const tampered = replaceFooterTag(bytes);
      const restore = createRestoreHarness(fixture);

      await expect(
        restoreEncryptedBackup(
          chunks(tampered),
          VAULT_ID,
          restore.store,
          restore.factory,
        ),
      ).rejects.toBeInstanceOf(BackupError);
      expect(restore.state()).toBe('aborted');
      expect(restore.staged).toEqual([]);
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('commits only after a complete footer and accepts one-byte fragmentation', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          {
            vault: fixture.vault,
            records: entries({ kind: 'group', record: fixture.group }),
            createdAt: CREATED_AT,
          },
          fixture.rootKey,
        ),
      );
      const restore = createRestoreHarness(fixture);
      const result = await restoreEncryptedBackup(
        chunks(bytes, 1),
        VAULT_ID,
        restore.store,
        restore.factory,
      );

      expect(result).toMatchObject({ disposition: 'verified-and-committed' });
      expect(restore.staged.map((entry) => entry.kind)).toEqual(['vault', 'group']);
      expect(restore.events).toEqual([
        'write:vault',
        'write:group',
        'seal:2',
        'readSealed',
        'readSealed:eof',
        'verify',
        'publish',
        'finalize',
      ]);
      expect(restore.publishedReceipt()).toEqual(
        result.disposition === 'verified-and-committed'
          ? result.verification
          : undefined,
      );
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('rejects cross-vault restore and incomplete or noncanonical framing', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          {
            vault: fixture.vault,
            records: entries({ kind: 'group', record: fixture.group }),
            createdAt: CREATED_AT,
          },
          fixture.rootKey,
        ),
      );
      await expect(
        verifyEncryptedBackup(chunks(bytes), fixture.rootKey, OTHER_VAULT_ID),
      ).rejects.toMatchObject({ code: 'BACKUP_WRONG_VAULT' });
      await expect(
        verifyEncryptedBackup(chunks(bytes.subarray(0, -1)), fixture.rootKey, VAULT_ID),
      ).rejects.toMatchObject({ code: 'BACKUP_INCOMPLETE' });
      await expect(
        verifyEncryptedBackup(
          chunks(Buffer.from(bytes.toString('utf8').replaceAll('\n', '\r\n'))),
          fixture.rootKey,
          VAULT_ID,
        ),
      ).rejects.toMatchObject({ code: 'BACKUP_INVALID' });
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('rejects duplicate identities and incomplete attachment graphs', async () => {
    const fixture = await createFixture();
    try {
      await expect(
        collect(
          createEncryptedBackup(
            {
              vault: fixture.vault,
              records: entries(
                { kind: 'group', record: fixture.group },
                { kind: 'group', record: fixture.group },
              ),
              createdAt: CREATED_AT,
            },
            fixture.rootKey,
          ),
        ),
      ).rejects.toMatchObject({ code: 'BACKUP_INVALID' });

      const graph = createAttachmentGraph();
      await expect(
        collect(
          createEncryptedBackup(
            {
              vault: fixture.vault,
              records: entries(
                { kind: 'group', record: fixture.group },
                { kind: 'item', record: graph.item },
                { kind: 'attachment', record: graph.attachment },
              ),
              createdAt: CREATED_AT,
            },
            fixture.rootKey,
          ),
        ),
      ).rejects.toMatchObject({ code: 'BACKUP_INCOMPLETE' });

      await expect(
        collect(
          createEncryptedBackup(
            {
              vault: fixture.vault,
              records: entries(
                { kind: 'group', record: fixture.group },
                { kind: 'item', record: graph.item },
                { kind: 'attachment', record: graph.attachment },
                { kind: 'attachment-header', record: graph.header },
                { kind: 'attachment-chunk', record: graph.chunk },
              ),
              createdAt: CREATED_AT,
            },
            fixture.rootKey,
          ),
        ),
      ).resolves.toBeInstanceOf(Buffer);

      for (const [records, expectedError] of [
        [
          [
            { kind: 'group', record: fixture.group },
            { kind: 'item', record: graph.item },
            { kind: 'attachment', record: graph.attachment },
            {
              kind: 'attachment-header',
              record: withCanonicalHeaderHash({
                ...graph.header,
                record: { ...graph.header.record, keyVersion: 2 },
              }),
            },
            { kind: 'attachment-chunk', record: graph.chunk },
          ],
          { code: 'BACKUP_INCOMPLETE' },
        ],
        [
          [
            { kind: 'group', record: fixture.group },
            { kind: 'item', record: graph.item },
            { kind: 'attachment', record: graph.attachment },
            { kind: 'attachment-header', record: graph.header },
            {
              kind: 'attachment-chunk',
              record: {
                ...graph.chunk,
                record: { ...graph.chunk.record, schemaVersion: 2 },
              } as unknown as PersistedAttachmentChunkRecord,
            },
          ],
          {
            code: 'BACKUP_INVALID',
            message: 'The encrypted backup is malformed.',
          },
        ],
      ] as const) {
        await expect(
          collect(
            createEncryptedBackup(
              {
                vault: fixture.vault,
                records: entries(...records),
                createdAt: CREATED_AT,
              },
              fixture.rootKey,
            ),
          ),
        ).rejects.toMatchObject(expectedError);
      }
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('rejects split attachment key versions during creation and verification', async () => {
    const fixture = await createFixture();
    try {
      const graph = createAttachmentGraph();
      const splitAttachment = {
        ...graph.attachment,
        wrappedAttachmentKey: {
          ...graph.attachment.wrappedAttachmentKey,
          aad: { ...graph.attachment.wrappedAttachmentKey.aad, keyVersion: 2 },
          keyVersion: 2,
        },
      } as EncryptedAttachmentRecord;
      const graphEntries = [
        { kind: 'group', record: fixture.group },
        { kind: 'item', record: graph.item },
        { kind: 'attachment', record: splitAttachment },
        { kind: 'attachment-header', record: graph.header },
        { kind: 'attachment-chunk', record: graph.chunk },
      ] as const;

      await expect(
        collect(
          createEncryptedBackup(
            {
              vault: fixture.vault,
              records: entries(...graphEntries),
              createdAt: CREATED_AT,
            },
            fixture.rootKey,
          ),
        ),
      ).rejects.toMatchObject({ code: 'BACKUP_INVALID' });

      const validBytes = await collect(
        createEncryptedBackup(
          {
            vault: fixture.vault,
            records: entries(
              { kind: 'group', record: fixture.group },
              { kind: 'item', record: graph.item },
              { kind: 'attachment', record: graph.attachment },
              { kind: 'attachment-header', record: graph.header },
              { kind: 'attachment-chunk', record: graph.chunk },
            ),
            createdAt: CREATED_AT,
          },
          fixture.rootKey,
        ),
      );
      const lines = validBytes.toString('utf8').trimEnd().split('\n');
      const attachmentLineIndex = lines.findIndex((line) => {
        const value = JSON.parse(line) as { kind?: string };
        return value.kind === 'attachment';
      });
      const attachmentEntry = JSON.parse(lines[attachmentLineIndex] ?? '') as {
        record: EncryptedAttachmentRecord;
      };
      attachmentEntry.record = splitAttachment;
      lines[attachmentLineIndex] = JSON.stringify(attachmentEntry);

      await expect(
        verifyEncryptedBackup(
          chunks(Buffer.from(`${lines.join('\n')}\n`, 'utf8')),
          fixture.rootKey,
          VAULT_ID,
        ),
      ).rejects.toMatchObject({ code: 'BACKUP_INVALID' });
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it.each(['header', 'chunk'] as const)(
    'rejects a noncanonical attachment %s hash during creation before emitting a footer',
    async (kind) => {
      const fixture = await createFixture();
      try {
        const graph = createAttachmentGraph();
        const invalidRecord =
          kind === 'header'
            ? {
                kind: 'attachment-header' as const,
                record: { ...graph.header, contentHash: DIGEST },
              }
            : {
                kind: 'attachment-chunk' as const,
                record: { ...graph.chunk, ciphertextHash: DIGEST },
              };
        const emitted: Uint8Array[] = [];
        const archive = createEncryptedBackup(
          {
            vault: fixture.vault,
            records: entries(
              { kind: 'group', record: fixture.group },
              { kind: 'item', record: graph.item },
              { kind: 'attachment', record: graph.attachment },
              ...(kind === 'header'
                ? [
                    invalidRecord,
                    { kind: 'attachment-chunk' as const, record: graph.chunk },
                  ]
                : [
                    { kind: 'attachment-header' as const, record: graph.header },
                    invalidRecord,
                  ]),
            ),
            createdAt: CREATED_AT,
          },
          fixture.rootKey,
        );

        const caught = await (async (): Promise<unknown> => {
          try {
            for await (const bytes of archive) emitted.push(bytes);
            return undefined;
          } catch (error) {
            return error;
          }
        })();

        expect(caught).toEqual(expect.objectContaining({ code: 'BACKUP_INVALID' }));
        expect(Buffer.concat(emitted).toString('utf8')).not.toContain(
          '"type":"footer"',
        );
      } finally {
        zeroize(fixture.rootKey);
      }
    },
  );

  it.each(['header', 'chunk'] as const)(
    'rejects an authenticated noncanonical attachment %s hash and aborts hidden staging',
    async (kind) => {
      const fixture = await createFixture();
      try {
        const graph = createAttachmentGraph();
        const validBytes = await collect(
          createEncryptedBackup(
            {
              vault: fixture.vault,
              records: entries(
                { kind: 'group', record: fixture.group },
                { kind: 'item', record: graph.item },
                { kind: 'attachment', record: graph.attachment },
                { kind: 'attachment-header', record: graph.header },
                { kind: 'attachment-chunk', record: graph.chunk },
              ),
              createdAt: CREATED_AT,
            },
            fixture.rootKey,
          ),
        );
        const invalidBytes = authenticateMutatedArchive(
          validBytes,
          fixture.rootKey,
          kind === 'header' ? 'attachment-header' : 'attachment-chunk',
          (entry) => {
            if (entry.kind === 'attachment-header') {
              return { ...entry, record: { ...entry.record, contentHash: DIGEST } };
            }
            if (entry.kind === 'attachment-chunk') {
              return { ...entry, record: { ...entry.record, ciphertextHash: DIGEST } };
            }
            return entry;
          },
        );

        await expect(
          verifyEncryptedBackup(chunks(invalidBytes), fixture.rootKey, VAULT_ID),
        ).rejects.toMatchObject({ code: 'BACKUP_INVALID' });

        const restore = createRestoreHarness(fixture);
        await expect(
          restoreEncryptedBackup(
            chunks(invalidBytes),
            VAULT_ID,
            restore.store,
            restore.factory,
          ),
        ).rejects.toMatchObject({ code: 'BACKUP_INVALID' });
        expect({ state: restore.state(), staged: restore.staged }).toEqual({
          state: 'aborted',
          staged: [],
        });
      } finally {
        zeroize(fixture.rootKey);
      }
    },
  );

  it('requires the exact active predecessor before a deleted tombstone', async () => {
    const fixture = await createFixture();
    try {
      const current = encryptedGroupRecordSchema.parse({
        ...fixture.group,
        recordRevision: 2,
        tombstonedAt: CREATED_AT,
      });
      const tombstone = tombstoneRecordSchema.parse({
        vaultId: VAULT_ID,
        entityType: 'group',
        entityId: GROUP_ID,
        state: 'deleted',
        tombstoneRevision: 2,
        lastRecordRevision: fixture.group.recordRevision,
        lastCiphertextHash: contentHashForRecord(fixture.group),
        deletedAt: CREATED_AT,
      });
      const create = (...records: readonly EncryptedBackupEntry[]): Promise<Buffer> =>
        collect(
          createEncryptedBackup(
            {
              vault: fixture.vault,
              records: entries(...records),
              createdAt: CREATED_AT,
            },
            fixture.rootKey,
          ),
        );

      await expect(
        create(
          { kind: 'group', record: current },
          { kind: 'tombstone', record: tombstone },
        ),
      ).rejects.toMatchObject({ code: 'BACKUP_INCOMPLETE' });
      await expect(
        create(
          { kind: 'group', record: current },
          {
            kind: 'tombstone-predecessor',
            entityType: 'group',
            record: {
              ...fixture.group,
              recordRevision: recordRevisionSchema.parse(0),
            },
          },
          { kind: 'tombstone', record: tombstone },
        ),
      ).rejects.toMatchObject({ code: 'BACKUP_INVALID' });
      await expect(
        create(
          { kind: 'group', record: current },
          {
            kind: 'tombstone-predecessor',
            entityType: 'group',
            record: fixture.group,
          },
          { kind: 'tombstone', record: tombstone },
        ),
      ).resolves.toBeInstanceOf(Buffer);
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('enforces record and aggregate-byte quotas before publishing staged data', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          {
            vault: fixture.vault,
            records: entries({ kind: 'group', record: fixture.group }),
            createdAt: CREATED_AT,
          },
          fixture.rootKey,
        ),
      );
      const restore = createRestoreHarness(fixture);

      await expect(
        restoreEncryptedBackup(
          chunks(bytes),
          VAULT_ID,
          restore.store,
          restore.factory,
          { maximumRecords: 1 },
        ),
      ).rejects.toMatchObject({ code: 'BACKUP_TOO_LARGE' });
      expect({ state: restore.state(), staged: restore.staged }).toEqual({
        state: 'aborted',
        staged: [],
      });

      await expect(
        verifyEncryptedBackup(chunks(bytes), fixture.rootKey, VAULT_ID, {
          maximumBytes: bytes.byteLength - 1,
        }),
      ).rejects.toMatchObject({ code: 'BACKUP_TOO_LARGE' });
      await expect(
        verifyEncryptedBackup(chunks(bytes), fixture.rootKey, VAULT_ID, {
          maximumBytes: 64 * 1024 * 1024 * 1024 + 1,
        }),
      ).rejects.toBeInstanceOf(RangeError);
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('authenticates exact committed replay without fabricating a receipt', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          {
            vault: fixture.vault,
            records: entries({ kind: 'group', record: fixture.group }),
            createdAt: CREATED_AT,
          },
          fixture.rootKey,
        ),
      );
      const summary = await verifyEncryptedBackup(
        chunks(bytes),
        fixture.rootKey,
        VAULT_ID,
      );
      const restore = createRestoreHarness(fixture, {
        initialState: 'committed',
        summary,
      });

      await expect(
        restoreEncryptedBackup(chunks(bytes), VAULT_ID, restore.store, restore.factory),
      ).resolves.toEqual({ disposition: 'previously-committed', backup: summary });
      expect(restore.events).toEqual([]);
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('preserves staging failures and aborts hidden state before commit starts', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          {
            vault: fixture.vault,
            records: entries({ kind: 'group', record: fixture.group }),
            createdAt: CREATED_AT,
          },
          fixture.rootKey,
        ),
      );
      const restore = createRestoreHarness(fixture, { failWrite: true });
      await expect(
        restoreEncryptedBackup(chunks(bytes), VAULT_ID, restore.store, restore.factory),
      ).rejects.toMatchObject({ code: 'BACKUP_AUTHENTICATION_FAILED' });
      expect(restore.state()).toBe('aborted');
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('uses exact-prefix replay and then verifies sealed and published resumes', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          {
            vault: fixture.vault,
            records: entries({ kind: 'group', record: fixture.group }),
            createdAt: CREATED_AT,
          },
          fixture.rootKey,
        ),
      );
      const summary = await verifyEncryptedBackup(
        chunks(bytes),
        fixture.rootKey,
        VAULT_ID,
      );
      const allEntries = [
        { kind: 'vault' as const, record: fixture.vault },
        { kind: 'group' as const, record: fixture.group },
      ];

      for (const prefixLength of [1, 2]) {
        const resumed = createRestoreHarness(fixture, {
          initialEntries: allEntries.slice(0, prefixLength),
        });
        await expect(
          restoreEncryptedBackup(
            chunks(bytes, 1),
            VAULT_ID,
            resumed.store,
            resumed.factory,
          ),
        ).resolves.toMatchObject({ disposition: 'verified-and-committed' });
        expect(resumed.staged).toEqual(allEntries);
        expect(
          resumed.events.filter((event) => event.startsWith('write:')),
        ).toHaveLength(2);
      }

      for (const initialState of ['sealed', 'published'] as const) {
        const resumed = createRestoreHarness(fixture, {
          initialState,
          initialEntries: allEntries,
          summary,
        });
        await expect(
          restoreEncryptedBackup(
            chunks(bytes),
            VAULT_ID,
            resumed.store,
            resumed.factory,
          ),
        ).resolves.toMatchObject({ disposition: 'verified-and-committed' });
        expect(resumed.events.some((event) => event.startsWith('write:'))).toBe(false);
        expect(resumed.events).toContain('readSealed:eof');
        expect(resumed.events).toContain('verify');
        expect(resumed.events).toContain('finalize');
        expect(resumed.events.includes('publish')).toBe(initialState === 'sealed');
      }
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('rejects aborted reuse and validates the strict leading vault before factory/store', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
          fixture.rootKey,
        ),
      );
      const summary = await verifyEncryptedBackup(
        chunks(bytes),
        fixture.rootKey,
        VAULT_ID,
      );
      const aborted = createRestoreHarness(fixture, {
        initialState: 'aborted',
        summary,
      });
      await expect(
        restoreEncryptedBackup(chunks(bytes), VAULT_ID, aborted.store, aborted.factory),
      ).rejects.toMatchObject({ code: 'BACKUP_AUTHENTICATION_FAILED' });

      let factoryCalls = 0;
      let storeCalls = 0;
      const factory: RestoreVerificationSessionFactory = async (vault) => {
        factoryCalls += 1;
        return createRestoreHarness({ rootKey: fixture.rootKey, vault }).factory(vault);
      };
      const store: BackupRestoreStore = {
        open(): Promise<never> {
          storeCalls += 1;
          return Promise.reject(new Error('must not open'));
        },
      };
      for (const invalid of [
        Buffer.from('{"type":"bad"}\n', 'utf8'),
        Buffer.from(bytes.toString('utf8').split('\n').slice(0, 1).join('\n') + '\n'),
      ]) {
        await expect(
          restoreEncryptedBackup(chunks(invalid), VAULT_ID, store, factory),
        ).rejects.toBeInstanceOf(BackupError);
      }
      await expect(
        restoreEncryptedBackup(chunks(bytes), OTHER_VAULT_ID, store, factory),
      ).rejects.toMatchObject({ code: 'BACKUP_WRONG_VAULT' });
      expect({ factoryCalls, storeCalls }).toEqual({ factoryCalls: 0, storeCalls: 0 });
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('rejects every wrong second-line leading-vault variant before factory/store', async () => {
    const fixture = await createFixture();
    let factoryCalls = 0;
    let storeCalls = 0;
    try {
      const bytes = await collect(
        createEncryptedBackup(
          {
            vault: fixture.vault,
            records: entries({ kind: 'group', record: fixture.group }),
            createdAt: CREATED_AT,
          },
          fixture.rootKey,
        ),
      );
      const lines = bytes.toString('utf8').trimEnd().split('\n');
      const header = JSON.parse(lines[0] ?? '') as Record<string, unknown>;
      const mismatchedHeader = JSON.stringify({ ...header, schemaVersion: 2 });
      const variants = [
        [lines[0], lines.at(-1)],
        [lines[0], lines[2]],
        [mismatchedHeader, lines[1]],
      ].map((variant) =>
        Buffer.from(`${variant.filter((line) => line !== undefined).join('\n')}\n`),
      );
      const factory: RestoreVerificationSessionFactory = () => {
        factoryCalls += 1;
        return Promise.reject(new Error('must not open verifier'));
      };
      const store: BackupRestoreStore = {
        open(): Promise<never> {
          storeCalls += 1;
          return Promise.reject(new Error('must not open store'));
        },
      };
      for (const variant of variants) {
        await expect(
          restoreEncryptedBackup(chunks(variant), VAULT_ID, store, factory),
        ).rejects.toMatchObject({ code: 'BACKUP_INVALID' });
      }
      expect({ factoryCalls, storeCalls }).toEqual({ factoryCalls: 0, storeCalls: 0 });
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it.each([
    ['invalid', 'BACKUP_AUTHENTICATION_FAILED'],
    ['unsupported', 'BACKUP_DECRYPTABILITY_UNSUPPORTED'],
    ['unknown', 'BACKUP_AUTHENTICATION_FAILED'],
  ] as const)(
    'maps %s verifier failure generically and never publishes',
    async (verifierFailure, code) => {
      const fixture = await createFixture();
      try {
        const bytes = await collect(
          createEncryptedBackup(
            { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
            fixture.rootKey,
          ),
        );
        const restore = createRestoreHarness(fixture, { verifierFailure });
        const caught = await captureError(
          restoreEncryptedBackup(
            chunks(bytes),
            VAULT_ID,
            restore.store,
            restore.factory,
          ),
        );
        expect(caught).toMatchObject({ code });
        expect(restore.events).not.toContain('publish');
        expect(restore.state()).toBe('aborted');
        expect(JSON.stringify(caught)).not.toContain('KAVRIX_');
      } finally {
        zeroize(fixture.rootKey);
      }
    },
  );

  it('preserves unsupported classification when cursor cleanup also fails', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
          fixture.rootKey,
        ),
      );
      const restore = createRestoreHarness(fixture, {
        verifierFailure: 'unsupported',
        failReturn: true,
      });
      const caught = await captureError(
        restoreEncryptedBackup(chunks(bytes), VAULT_ID, restore.store, restore.factory),
      );
      expect(caught).toMatchObject({
        code: 'BACKUP_DECRYPTABILITY_UNSUPPORTED',
      });
      expect(errorText(caught)).not.toContain('KAVRIX_RETURN_CANARY');
      expect(restore.events).not.toContain('publish');
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it.each([false, true])(
    'requires verifier-observed EOF and treats cursor cleanup failure=%s as authentication failure',
    async (failReturn) => {
      const fixture = await createFixture();
      try {
        const bytes = await collect(
          createEncryptedBackup(
            {
              vault: fixture.vault,
              records: entries({ kind: 'group', record: fixture.group }),
              createdAt: CREATED_AT,
            },
            fixture.rootKey,
          ),
        );
        const restore = createRestoreHarness(fixture, {
          verifierReturnsEarly: true,
          failReturn,
        });
        const caught = await captureError(
          restoreEncryptedBackup(
            chunks(bytes),
            VAULT_ID,
            restore.store,
            restore.factory,
          ),
        );
        expect(caught).toMatchObject({ code: 'BACKUP_AUTHENTICATION_FAILED' });
        expect(restore.events).toContain('readSealed:return');
        expect(restore.events).not.toContain('publish');
        expect(errorText(caught)).not.toContain('KAVRIX_RETURN_CANARY');
      } finally {
        zeroize(fixture.rootKey);
      }
    },
  );

  it('reverifies and succeeds after one transient publish failure leaves exact sealed state', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
          fixture.rootKey,
        ),
      );
      const restore = createRestoreHarness(fixture, {
        failPublish: true,
        failPublishCount: 1,
        publishFailureState: 'sealed',
      });
      await expect(
        restoreEncryptedBackup(chunks(bytes), VAULT_ID, restore.store, restore.factory),
      ).resolves.toMatchObject({ disposition: 'verified-and-committed' });
      expect(restore.events.filter((event) => event === 'publish')).toHaveLength(2);
      expect(restore.events.filter((event) => event === 'verify')).toHaveLength(2);
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it.each(['published', 'committed'] as const)(
    'never claims abort when publication wins the abort race as %s',
    async (abortRaceState) => {
      const fixture = await createFixture();
      try {
        const bytes = await collect(
          createEncryptedBackup(
            { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
            fixture.rootKey,
          ),
        );
        const restore = createRestoreHarness(fixture, {
          verifierFailure: 'invalid',
          abortRaceState,
        });
        await expect(
          restoreEncryptedBackup(
            chunks(bytes),
            VAULT_ID,
            restore.store,
            restore.factory,
          ),
        ).rejects.toMatchObject({ code: 'BACKUP_COMMIT_UNCERTAIN' });
        expect(restore.events.filter((event) => event === 'abort')).toHaveLength(1);
        expect(restore.state()).toBe(abortRaceState);
      } finally {
        zeroize(fixture.rootKey);
      }
    },
  );

  it.each([
    ['initial', 0, {}],
    ['seal', 1, { failSeal: true, sealFailureState: 'sealed' as const }],
    ['publish', 2, { failPublish: true, publishFailureState: 'published' as const }],
    ['finalize', 3, { failFinalize: true, finalizeFailureState: 'committed' as const }],
  ] as const)(
    'reports uncertainty without leaking unreadable %s status details',
    async (_phase, failStatusAfter, phaseOptions) => {
      const fixture = await createFixture();
      try {
        const bytes = await collect(
          createEncryptedBackup(
            { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
            fixture.rootKey,
          ),
        );
        const restore = createRestoreHarness(fixture, {
          ...phaseOptions,
          failStatus: true,
          failStatusAfter,
        });
        const caught = await captureError(
          restoreEncryptedBackup(
            chunks(bytes),
            VAULT_ID,
            restore.store,
            restore.factory,
          ),
        );
        expect(caught).toMatchObject({ code: 'BACKUP_COMMIT_UNCERTAIN' });
        expect(errorText(caught)).not.toContain('KAVRIX_STATUS_CANARY');
        if (_phase === 'publish' || _phase === 'finalize') {
          expect(restore.events).not.toContain('abort');
        }
      } finally {
        zeroize(fixture.rootKey);
      }
    },
  );

  it.each([
    ['seal', { failSeal: true, sealFailureState: 'sealed' as const }],
    ['publish', { failPublish: true, publishFailureState: 'published' as const }],
    ['finalize', { failFinalize: true, finalizeFailureState: 'committed' as const }],
  ] as const)(
    'retains state and reports uncertainty for a divergent %s reconciliation status',
    async (_operation, failureOptions) => {
      const fixture = await createFixture();
      try {
        const bytes = await collect(
          createEncryptedBackup(
            { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
            fixture.rootKey,
          ),
        );
        const restore = createRestoreHarness(fixture, {
          ...failureOptions,
          divergentFrozenStatus: true,
        });
        await expect(
          restoreEncryptedBackup(
            chunks(bytes),
            VAULT_ID,
            restore.store,
            restore.factory,
          ),
        ).rejects.toMatchObject({ code: 'BACKUP_COMMIT_UNCERTAIN' });
        expect(restore.events).not.toContain('abort');
      } finally {
        zeroize(fixture.rootKey);
      }
    },
  );

  it.each([
    [
      'recordCount',
      (receipt: RestoreKnownRecordsVerificationV1) => ({
        ...receipt,
        recordCount: receipt.recordCount + 1,
      }),
    ],
    [
      'slot',
      (receipt: RestoreKnownRecordsVerificationV1) => ({
        ...receipt,
        selectedSlot: {
          ...receipt.selectedSlot,
          id: keySlotIdSchema.parse('other-slot'),
        },
      }),
    ],
    [
      'vault',
      (receipt: RestoreKnownRecordsVerificationV1) => ({
        ...receipt,
        vaultId: OTHER_VAULT_ID,
      }),
    ],
    [
      'session',
      (receipt: RestoreKnownRecordsVerificationV1) => ({
        ...receipt,
        restoreSessionId: DIGEST,
      }),
    ],
    [
      'transcript',
      (receipt: RestoreKnownRecordsVerificationV1) => ({
        ...receipt,
        transcriptSha256: DIGEST,
      }),
    ],
    [
      'commitment',
      (receipt: RestoreKnownRecordsVerificationV1) => ({
        ...receipt,
        canonicalEntriesSha256: DIGEST,
      }),
    ],
    [
      'slot-type',
      (receipt: RestoreKnownRecordsVerificationV1) => ({
        ...receipt,
        selectedSlot: { ...receipt.selectedSlot, type: 'recovery-key' as const },
      }),
    ],
    [
      'slot-version',
      (receipt: RestoreKnownRecordsVerificationV1) => ({
        ...receipt,
        selectedSlot: {
          ...receipt.selectedSlot,
          keyVersion: receipt.selectedSlot.keyVersion + 1,
        },
      }),
    ],
    [
      'excess',
      (receipt: RestoreKnownRecordsVerificationV1) => ({
        ...receipt,
        unexpected: true,
      }),
    ],
  ] as const)(
    'rejects a forged %s receipt before publication',
    async (_name, mutateReceipt) => {
      const fixture = await createFixture();
      try {
        const bytes = await collect(
          createEncryptedBackup(
            { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
            fixture.rootKey,
          ),
        );
        const restore = createRestoreHarness(fixture, { mutateReceipt });
        await expect(
          restoreEncryptedBackup(
            chunks(bytes),
            VAULT_ID,
            restore.store,
            restore.factory,
          ),
        ).rejects.toMatchObject({ code: 'BACKUP_AUTHENTICATION_FAILED' });
        expect(restore.events).not.toContain('publish');
      } finally {
        zeroize(fixture.rootKey);
      }
    },
  );

  it('sanitizes collaborator causes, closes the session, and still zeroizes its VRK', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
          fixture.rootKey,
        ),
      );
      const restore = createRestoreHarness(fixture, {
        failWrite: true,
        closeFailure: true,
      });
      const caught = await captureError(
        restoreEncryptedBackup(chunks(bytes), VAULT_ID, restore.store, restore.factory),
      );
      expect(caught).toMatchObject({ code: 'BACKUP_AUTHENTICATION_FAILED' });
      expect(errorText(caught)).not.toContain('KAVRIX_');
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('reports a sanitized aggregate when abort leaves exact hidden state', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
          fixture.rootKey,
        ),
      );
      const restore = createRestoreHarness(fixture, {
        verifierFailure: 'invalid',
        failAbort: true,
      });
      const caught = await captureError(
        restoreEncryptedBackup(chunks(bytes), VAULT_ID, restore.store, restore.factory),
      );
      expect(caught).toBeInstanceOf(AggregateError);
      expect(errorText(caught)).not.toContain('KAVRIX_ABORT_CANARY');
      expect(restore.state()).toBe('sealed');
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it.each([
    ['sealed', 'verified-and-committed'],
    ['staging', 'BACKUP_COMMIT_UNCERTAIN'],
  ] as const)(
    'bounds an ambiguous seal reconciled as %s',
    async (sealFailureState, expected) => {
      const fixture = await createFixture();
      try {
        const bytes = await collect(
          createEncryptedBackup(
            { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
            fixture.rootKey,
          ),
        );
        const restore = createRestoreHarness(fixture, {
          failSeal: true,
          sealFailureState,
        });
        const operation = restoreEncryptedBackup(
          chunks(bytes),
          VAULT_ID,
          restore.store,
          restore.factory,
        );
        if (expected === 'verified-and-committed') {
          await expect(operation).resolves.toMatchObject({ disposition: expected });
        } else {
          await expect(operation).rejects.toMatchObject({ code: expected });
        }
        expect(
          restore.events.filter((event) => event.startsWith('seal:')),
        ).toHaveLength(1);
      } finally {
        zeroize(fixture.rootKey);
      }
    },
  );

  it.each([
    ['published', 1, 'verified-and-committed'],
    ['sealed', 2, 'BACKUP_COMMIT_UNCERTAIN'],
  ] as const)(
    'bounds ambiguous publish at %s with %s attempt(s)',
    async (publishFailureState, attempts, expected) => {
      const fixture = await createFixture();
      try {
        const bytes = await collect(
          createEncryptedBackup(
            { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
            fixture.rootKey,
          ),
        );
        const restore = createRestoreHarness(fixture, {
          failPublish: true,
          publishFailureState,
        });
        const operation = restoreEncryptedBackup(
          chunks(bytes),
          VAULT_ID,
          restore.store,
          restore.factory,
        );
        if (expected === 'verified-and-committed') {
          await expect(operation).resolves.toMatchObject({ disposition: expected });
        } else {
          await expect(operation).rejects.toMatchObject({ code: expected });
        }
        expect(restore.events.filter((event) => event === 'publish')).toHaveLength(
          attempts,
        );
        expect(restore.events.filter((event) => event === 'verify')).toHaveLength(
          attempts,
        );
      } finally {
        zeroize(fixture.rootKey);
      }
    },
  );

  it.each([
    ['committed', 'verified-and-committed'],
    ['published', 'BACKUP_COMMIT_UNCERTAIN'],
  ] as const)(
    'reconciles an ambiguous finalize as %s without aborting publication',
    async (finalizeFailureState, expected) => {
      const fixture = await createFixture();
      try {
        const bytes = await collect(
          createEncryptedBackup(
            { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
            fixture.rootKey,
          ),
        );
        const restore = createRestoreHarness(fixture, {
          failFinalize: true,
          finalizeFailureState,
        });
        const operation = restoreEncryptedBackup(
          chunks(bytes),
          VAULT_ID,
          restore.store,
          restore.factory,
        );
        if (expected === 'verified-and-committed') {
          await expect(operation).resolves.toMatchObject({ disposition: expected });
        } else {
          await expect(operation).rejects.toMatchObject({ code: expected });
        }
        expect(restore.events).not.toContain('abort');
        expect(restore.events.filter((event) => event === 'finalize')).toHaveLength(1);
      } finally {
        zeroize(fixture.rootKey);
      }
    },
  );

  it.each(['published', 'committed'] as const)(
    'preserves replay error semantics from initial %s without aborting',
    async (initialState) => {
      const fixture = await createFixture();
      try {
        const bytes = await collect(
          createEncryptedBackup(
            { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
            fixture.rootKey,
          ),
        );
        const summary = await verifyEncryptedBackup(
          chunks(bytes),
          fixture.rootKey,
          VAULT_ID,
        );
        const restore = createRestoreHarness(fixture, {
          initialState,
          initialEntries: [{ kind: 'vault', record: fixture.vault }],
          summary,
          ...(initialState === 'published'
            ? { verifierFailure: 'unsupported' as const }
            : {}),
        });
        const input = initialState === 'committed' ? replaceFooterTag(bytes) : bytes;
        const caught = await captureError(
          restoreEncryptedBackup(
            chunks(input),
            VAULT_ID,
            restore.store,
            restore.factory,
          ),
        );
        expect(caught).toMatchObject({
          code:
            initialState === 'published'
              ? 'BACKUP_DECRYPTABILITY_UNSUPPORTED'
              : 'BACKUP_AUTHENTICATION_FAILED',
        });
        expect(restore.events).not.toContain('abort');
      } finally {
        zeroize(fixture.rootKey);
      }
    },
  );

  it('aborts an exact initial sealed session when the authenticated archive summary differs', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          {
            vault: fixture.vault,
            records: entries({ kind: 'group', record: fixture.group }),
            createdAt: CREATED_AT,
          },
          fixture.rootKey,
        ),
      );
      const summary = await verifyEncryptedBackup(
        chunks(bytes),
        fixture.rootKey,
        VAULT_ID,
      );
      const changed = authenticateMutatedArchive(
        bytes,
        fixture.rootKey,
        'group',
        (entry) =>
          entry.kind === 'group'
            ? {
                ...entry,
                record: {
                  ...entry.record,
                  updatedAt: timestampSchema.parse('2026-08-10T00:00:01.000Z'),
                },
              }
            : entry,
      );
      const restore = createRestoreHarness(fixture, {
        initialState: 'sealed',
        initialEntries: [
          { kind: 'vault', record: fixture.vault },
          { kind: 'group', record: fixture.group },
        ],
        summary,
      });
      await expect(
        restoreEncryptedBackup(
          chunks(changed),
          VAULT_ID,
          restore.store,
          restore.factory,
        ),
      ).rejects.toMatchObject({ code: 'BACKUP_AUTHENTICATION_FAILED' });
      expect(restore.events).toContain('abort');
      expect(restore.state()).toBe('aborted');
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it.each(['staging', 'sealed', 'published'] as const)(
    'rejects different persisted bounds for %s and aborts only exact hidden state',
    async (initialState) => {
      const fixture = await createFixture();
      try {
        const bytes = await collect(
          createEncryptedBackup(
            { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
            fixture.rootKey,
          ),
        );
        const summary = await verifyEncryptedBackup(
          chunks(bytes),
          fixture.rootKey,
          VAULT_ID,
        );
        const restore = createRestoreHarness(fixture, {
          initialState,
          summary,
          initialEntries:
            initialState === 'staging'
              ? []
              : [{ kind: 'vault', record: fixture.vault }],
          persistedLimits: { maximumBytes: 8 * 1024 * 1024, maximumRecords: 100 },
        });
        await expect(
          restoreEncryptedBackup(
            chunks(bytes),
            VAULT_ID,
            restore.store,
            restore.factory,
            { maximumBytes: 4 * 1024 * 1024, maximumRecords: 50 },
          ),
        ).rejects.toMatchObject({
          code: 'BACKUP_AUTHENTICATION_FAILED',
        });
        expect(restore.events.includes('abort')).toBe(initialState !== 'published');
        expect(restore.state()).toBe(
          initialState === 'published' ? 'published' : 'aborted',
        );
      } finally {
        zeroize(fixture.rootKey);
      }
    },
  );

  it.each([
    ['string', 'staging'],
    ['versionless', { state: 'staging', restoreSessionId: DIGEST }],
    [
      'excess',
      {
        state: 'aborted',
        protocolVersion: 2,
        restoreSessionId: DIGEST,
        abortedAt: CREATED_AT,
        extra: true,
      },
    ],
  ] as const)('rejects an invalid initial %s status', async (_name, rawStatus) => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
          fixture.rootKey,
        ),
      );
      const restore = createRestoreHarness(fixture, { rawStatus });
      await expect(
        restoreEncryptedBackup(chunks(bytes), VAULT_ID, restore.store, restore.factory),
      ).rejects.toMatchObject({ code: 'BACKUP_AUTHENTICATION_FAILED' });
      expect(restore.events).not.toContain('publish');
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('maps factory failure and wrong-length VRK generically', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
          fixture.rootKey,
        ),
      );
      const restore = createRestoreHarness(fixture);
      const factories: readonly RestoreVerificationSessionFactory[] = [
        () =>
          Promise.reject(new BackupError('BACKUP_INCOMPLETE', 'KAVRIX_FACTORY_CANARY')),
        async (vault) => {
          const session = await restore.factory(vault);
          return { ...session, vaultRootKey: new Uint8Array(31) as never };
        },
      ];
      for (const factory of factories) {
        const caught = await captureError(
          restoreEncryptedBackup(chunks(bytes), VAULT_ID, restore.store, factory),
        );
        expect(caught).toMatchObject({ code: 'BACKUP_AUTHENTICATION_FAILED' });
        expect(errorText(caught)).not.toContain('KAVRIX_FACTORY_CANARY');
      }
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('zeroizes the captured VRK even when session close throws', async () => {
    const fixture = await createFixture();
    let captured: Uint8Array | undefined;
    try {
      const bytes = await collect(
        createEncryptedBackup(
          { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
          fixture.rootKey,
        ),
      );
      const restore = createRestoreHarness(fixture, {
        closeFailure: true,
        exposeRootKey: (value) => {
          captured = value;
        },
      });
      await expect(
        restoreEncryptedBackup(chunks(bytes), VAULT_ID, restore.store, restore.factory),
      ).rejects.toMatchObject({ code: 'BACKUP_AUTHENTICATION_FAILED' });
      expect(captured).toEqual(new Uint8Array(32));
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('sanitizes readSealed next failures and publishes nothing', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
          fixture.rootKey,
        ),
      );
      const restore = createRestoreHarness(fixture, { failNext: true });
      const caught = await captureError(
        restoreEncryptedBackup(chunks(bytes), VAULT_ID, restore.store, restore.factory),
      );
      expect(caught).toMatchObject({ code: 'BACKUP_AUTHENTICATION_FAILED' });
      expect(errorText(caught)).not.toContain('KAVRIX_NEXT_CANARY');
      expect(restore.events).not.toContain('publish');
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('allows a published replay to use a different permitted slot without persisting the old slot', async () => {
    const fixture = await createFixture();
    try {
      const bytes = await collect(
        createEncryptedBackup(
          { vault: fixture.vault, records: entries(), createdAt: CREATED_AT },
          fixture.rootKey,
        ),
      );
      const summary = await verifyEncryptedBackup(
        chunks(bytes),
        fixture.rootKey,
        VAULT_ID,
      );
      const alternate = {
        id: keySlotIdSchema.parse('slot-alternate'),
        type: 'recovery-key' as const,
        keyVersion: fixture.vault.currentKeyVersion,
      };
      const restore = createRestoreHarness(fixture, {
        initialState: 'published',
        initialEntries: [{ kind: 'vault', record: fixture.vault }],
        summary,
        selectedSlotOverride: alternate,
      });
      await expect(
        restoreEncryptedBackup(chunks(bytes), VAULT_ID, restore.store, restore.factory),
      ).resolves.toMatchObject({
        disposition: 'verified-and-committed',
        verification: { selectedSlot: alternate },
      });
      expect(restore.publishedReceipt()?.selectedSlot).toEqual(alternate);
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('returns the frozen canonical-entry commitment from authentication-only verification', async () => {
    const fixture = await createFixture();
    try {
      const entry = { kind: 'group' as const, record: fixture.group };
      const bytes = await collect(
        createEncryptedBackup(
          { vault: fixture.vault, records: entries(entry), createdAt: CREATED_AT },
          fixture.rootKey,
        ),
      );
      const commitment = createBackupStagedEntryCommitment();
      commitment.update({ kind: 'vault', record: fixture.vault });
      commitment.update(entry);
      await expect(
        verifyEncryptedBackup(chunks(bytes, 1), fixture.rootKey, VAULT_ID),
      ).resolves.toMatchObject({ canonicalEntriesSha256: commitment.finalize() });
    } finally {
      zeroize(fixture.rootKey);
    }
  });
});

async function createFixture(): Promise<{
  rootKey: ReturnType<typeof generateVaultRootKey>;
  vault: VaultRecord;
  group: EncryptedGroupRecord;
}> {
  const rootKey = generateVaultRootKey();
  const portableKey = generatePortableKey();
  const slot = await createPortableKeySlot(
    {
      vaultId: VAULT_ID,
      slotId: keySlotIdSchema.parse('slot-1'),
      schemaVersion: 1,
      keyVersion: 1,
      createdAt: CREATED_AT,
    },
    portableKey,
    rootKey,
  );
  zeroize(portableKey);

  const preferencesAad = associatedDataSchema.parse({
    version: 1,
    schemaVersion: 1,
    keyVersion: 1,
    vaultId: VAULT_ID,
    entityType: 'vault-preferences',
    entityId: VAULT_ID,
    purpose: 'vault-preferences',
  });
  const encryptedPreferences = await encryptPayload(
    Buffer.from('{"locked":true}', 'utf8'),
    rootKey,
    preferencesAad,
  );
  const vault = vaultRecordSchema.parse({
    id: VAULT_ID,
    schemaVersion: 1,
    cryptographicVersion: 1,
    keySlots: [slot],
    currentKeyVersion: 1,
    revision: 0,
    encryptedPreferences,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });

  const groupKey = generateGroupKey();
  const wrappedGroupKey = await wrapGroupKey(
    groupKey,
    rootKey,
    associatedDataSchema.parse({
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: VAULT_ID,
      entityType: 'wrapped-group-key',
      entityId: GROUP_ID,
      purpose: 'group-key',
    }),
  );
  const encryptedPayload = await encryptPayload(
    Buffer.from(PLAINTEXT_CANARY, 'utf8'),
    groupKey,
    associatedDataSchema.parse({
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: VAULT_ID,
      entityType: 'group',
      entityId: GROUP_ID,
      purpose: 'group-payload',
    }),
  );
  zeroize(groupKey);
  const group = encryptedGroupRecordSchema.parse({
    id: GROUP_ID,
    vaultId: VAULT_ID,
    schemaVersion: 1,
    wrappedGroupKey,
    encryptedPayload,
    templateVersion: 1,
    recordRevision: 1,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });
  return { rootKey, vault, group };
}

function entries(
  ...values: readonly EncryptedBackupEntry[]
): AsyncIterable<EncryptedBackupEntry> {
  return asyncIterable(values);
}

type RestoreHarnessState = BackupRestoreStatus['state'];

function createRestoreHarness(
  fixture: Pick<Awaited<ReturnType<typeof createFixture>>, 'rootKey' | 'vault'>,
  options: Readonly<{
    initialState?: RestoreHarnessState;
    summary?: BackupVerification;
    persistedLimits?: ResolvedBackupLimits;
    initialEntries?: readonly EncryptedBackupEntry[];
    rawStatus?: unknown;
    failWrite?: boolean;
    failSeal?: boolean;
    sealFailureState?: RestoreHarnessState;
    failPublish?: boolean;
    failPublishCount?: number;
    publishFailureState?: RestoreHarnessState;
    failFinalize?: boolean;
    finalizeFailureState?: RestoreHarnessState;
    failStatus?: boolean;
    failStatusAfter?: number;
    statusCalls?: number;
    failReturn?: boolean;
    failNext?: boolean;
    failAbort?: boolean;
    abortRaceState?: 'published' | 'committed';
    closeFailure?: boolean;
    divergentFrozenStatus?: boolean;
    verifierFailure?: 'invalid' | 'unsupported' | 'unknown';
    verifierReturnsEarly?: boolean;
    mutateReceipt?: (receipt: RestoreKnownRecordsVerificationV1) => unknown;
    selectedSlotOverride?: RestoreKnownRecordsVerificationV1['selectedSlot'];
    exposeRootKey?: (rootKey: Uint8Array) => void;
  }> = {},
): Readonly<{
  store: BackupRestoreStore;
  factory: RestoreVerificationSessionFactory;
  staged: EncryptedBackupEntry[];
  events: string[];
  publishedReceipt(): RestoreKnownRecordsVerificationV1 | undefined;
  state(): RestoreHarnessState;
}> {
  const events: string[] = [];
  const staged: EncryptedBackupEntry[] = [...(options.initialEntries ?? [])];
  let writeOrdinal = 0;
  let publishedReceipt: RestoreKnownRecordsVerificationV1 | undefined;
  const selected = fixture.vault.keySlots[0];
  if (selected === undefined || selected.type === 'device-key') {
    throw new Error('Restore fixture requires a portable selected slot.');
  }
  const selectedSlot = {
    id: selected.id,
    type: selected.type,
    keyVersion: selected.keyVersion,
  } as const;
  const effectiveSelectedSlot = options.selectedSlotOverride ?? selectedSlot;
  let state: RestoreHarnessState = options.initialState ?? 'staging';
  let statusCalls = 0;
  let publishFailures = 0;
  let summary = options.summary;
  let restoreSessionId = summary?.restoreSessionId ?? DIGEST;
  let limits: ResolvedBackupLimits = options.persistedLimits ?? {
    maximumBytes: 16 * 1024 * 1024 * 1024,
    maximumRecords: 2_000_000,
  };
  const rootKey = cloneSecretKey(fixture.rootKey);
  options.exposeRootKey?.(rootKey);

  const frozenStatusSummary = (): BackupVerification | undefined =>
    options.divergentFrozenStatus === true && summary !== undefined
      ? {
          ...summary,
          canonicalEntriesSha256: sha256DigestSchema.parse(
            Buffer.alloc(32, 9).toString('base64url'),
          ),
        }
      : summary;

  const status = (): BackupRestoreStatus => {
    if (state === 'committed') {
      return backupRestoreStatusSchema.parse({
        state,
        protocolVersion: 2,
        restoreSessionId,
        summary: frozenStatusSummary(),
        committedAt: CREATED_AT,
      });
    }
    if (state === 'aborted') {
      return backupRestoreStatusSchema.parse({
        state,
        protocolVersion: 2,
        restoreSessionId,
        abortedAt: CREATED_AT,
      });
    }
    const common = {
      state,
      protocolVersion: 2,
      restoreSessionId,
      maximumBytes: limits.maximumBytes,
      maximumRecords: limits.maximumRecords,
      stagedBytes: staged.length === 0 ? 0 : 1,
      stagedRecords: staged.length,
      createdAt: CREATED_AT,
      updatedAt: CREATED_AT,
      ...(staged.length === 0 ? {} : { vaultId: fixture.vault.id }),
    } as const;
    if (state === 'staging') return backupRestoreStatusSchema.parse(common);
    return backupRestoreStatusSchema.parse({
      ...common,
      vaultId: fixture.vault.id,
      summary: frozenStatusSummary(),
      sealedAt: CREATED_AT,
      ...(state === 'published' ? { publishedAt: CREATED_AT } : {}),
    });
  };

  const stager: BackupRestoreStager = {
    write(entry): Promise<void> {
      events.push(`write:${entry.kind}`);
      if (options.failWrite === true) {
        return Promise.reject(
          new BackupError('BACKUP_INCOMPLETE', 'KAVRIX_STORAGE_CREDENTIAL_CANARY', {
            cause: new Error('KAVRIX_STORAGE_CAUSE_CANARY'),
          }),
        );
      }
      const existing = staged[writeOrdinal];
      if (existing !== undefined && canonicalJson(existing) !== canonicalJson(entry)) {
        throw new Error('KAVRIX_PREFIX_CANARY');
      }
      if (writeOrdinal === staged.length) staged.push(entry);
      writeOrdinal += 1;
      return Promise.resolve();
    },
    seal(candidate): Promise<void> {
      events.push(`seal:${String(candidate.recordCount)}`);
      if (options.failSeal === true) {
        state = options.sealFailureState ?? state;
        if (state === 'sealed') summary = candidate;
        return Promise.reject(new Error('KAVRIX_SEAL_CANARY'));
      }
      summary = candidate;
      state = 'sealed';
      return Promise.resolve();
    },
    readSealed(candidate): AsyncIterable<EncryptedBackupEntry> {
      if (
        summary === undefined ||
        canonicalJson(candidate) !== canonicalJson(summary)
      ) {
        throw new Error('KAVRIX_SUMMARY_CANARY');
      }
      events.push('readSealed');
      let index = 0;
      return {
        [Symbol.asyncIterator](): AsyncIterator<EncryptedBackupEntry> {
          return {
            next(): Promise<IteratorResult<EncryptedBackupEntry>> {
              if (options.failNext === true) {
                return Promise.reject(new Error('KAVRIX_NEXT_CANARY'));
              }
              const value = staged[index++];
              if (value === undefined) {
                events.push('readSealed:eof');
                return Promise.resolve({ done: true, value: undefined });
              }
              return Promise.resolve({ done: false, value });
            },
            return(): Promise<IteratorResult<EncryptedBackupEntry>> {
              events.push('readSealed:return');
              if (options.failReturn === true) {
                return Promise.reject(new Error('KAVRIX_RETURN_CANARY'));
              }
              return Promise.resolve({ done: true, value: undefined });
            },
          };
        },
      };
    },
    publish(candidate, receipt): Promise<void> {
      if (
        summary === undefined ||
        canonicalJson(candidate) !== canonicalJson(summary)
      ) {
        return Promise.reject(new Error('KAVRIX_SUMMARY_CANARY'));
      }
      restoreKnownRecordsVerificationV1Schema.parse(receipt);
      events.push('publish');
      if (
        options.failPublish === true &&
        publishFailures < (options.failPublishCount ?? Number.POSITIVE_INFINITY)
      ) {
        publishFailures += 1;
        state = options.publishFailureState ?? state;
        if (state === 'published') publishedReceipt = receipt;
        return Promise.reject(new Error('KAVRIX_PUBLISH_CANARY'));
      }
      state = 'published';
      publishedReceipt = receipt;
      return Promise.resolve();
    },
    finalize(candidate, receipt): Promise<void> {
      if (
        summary === undefined ||
        canonicalJson(candidate) !== canonicalJson(summary)
      ) {
        return Promise.reject(new Error('KAVRIX_SUMMARY_CANARY'));
      }
      restoreKnownRecordsVerificationV1Schema.parse(receipt);
      if (
        publishedReceipt !== undefined &&
        canonicalJson(receipt) !== canonicalJson(publishedReceipt)
      ) {
        return Promise.reject(new Error('KAVRIX_RECEIPT_REUSE_CANARY'));
      }
      publishedReceipt ??= receipt;
      events.push('finalize');
      if (options.failFinalize === true) {
        state = options.finalizeFailureState ?? state;
        return Promise.reject(new Error('KAVRIX_FINALIZE_CANARY'));
      }
      state = 'committed';
      return Promise.resolve();
    },
    status(): Promise<BackupRestoreStatus> {
      statusCalls += 1;
      if (options.failStatus === true && statusCalls > (options.failStatusAfter ?? 0)) {
        return Promise.reject(new Error('KAVRIX_STATUS_CANARY'));
      }
      return Promise.resolve(
        options.rawStatus === undefined
          ? status()
          : (options.rawStatus as BackupRestoreStatus),
      );
    },
    abort(): Promise<void> {
      events.push('abort');
      if (options.abortRaceState !== undefined) {
        state = options.abortRaceState;
        return Promise.reject(new Error('KAVRIX_ABORT_RACE_CANARY'));
      }
      if (options.failAbort === true) {
        return Promise.reject(new Error('KAVRIX_ABORT_CANARY'));
      }
      state = 'aborted';
      staged.length = 0;
      return Promise.resolve();
    },
  };

  const store: BackupRestoreStore = {
    open(id, resolved): Promise<BackupRestoreStager> {
      restoreSessionId = id;
      if (options.persistedLimits === undefined) limits = resolved;
      return Promise.resolve(stager);
    },
  };
  const factory: RestoreVerificationSessionFactory = () =>
    Promise.resolve({
      vaultRootKey: rootKey,
      selectedSlot: effectiveSelectedSlot,
      async verify(entries, candidate) {
        if (options.verifierFailure !== undefined) {
          if (options.verifierFailure === 'unknown') {
            throw new Error('KAVRIX_VERIFIER_CANARY');
          }
          const error = new Error(
            'Encrypted backup decryptability verification failed.',
          ) as Error & {
            name: string;
            safe: true;
            kind: 'invalid' | 'unsupported';
          };
          error.name = 'RestoreKnownRecordsVerificationError';
          error.safe = true;
          error.kind = options.verifierFailure;
          throw error;
        }
        const verifiedEntries: EncryptedBackupEntry[] = [];
        for await (const entry of entries) {
          verifiedEntries.push(entry);
          if (options.verifierReturnsEarly === true) break;
        }
        events.push('verify');
        const counts = verifiedCounts(verifiedEntries);
        const receipt = restoreKnownRecordsVerificationV1Schema.parse({
          version: 1,
          scope: 'known-v1-records',
          vaultId: fixture.vault.id,
          vaultRevision: fixture.vault.revision,
          restoreSessionId: candidate.restoreSessionId,
          transcriptSha256: candidate.transcriptSha256,
          canonicalEntriesSha256: candidate.canonicalEntriesSha256,
          recordCount: candidate.recordCount,
          selectedSlot: effectiveSelectedSlot,
          verified: counts,
        });
        return (options.mutateReceipt?.(receipt) ??
          receipt) as RestoreKnownRecordsVerificationV1;
      },
      close() {
        zeroize(rootKey);
        if (options.closeFailure === true) throw new Error('KAVRIX_CLOSE_CANARY');
      },
    });
  return {
    store,
    factory,
    staged,
    events,
    publishedReceipt: () => publishedReceipt,
    state: () => state,
  };
}

function verifiedCounts(
  entries: readonly EncryptedBackupEntry[],
): RestoreKnownRecordsVerificationV1['verified'] {
  const count = (kind: EncryptedBackupEntry['kind']): number =>
    entries.filter((entry) => entry.kind === kind).length;
  const predecessors = entries.filter(
    (
      entry,
    ): entry is Extract<EncryptedBackupEntry, { kind: 'tombstone-predecessor' }> =>
      entry.kind === 'tombstone-predecessor',
  );
  return {
    vaults: 1,
    groups: count('group'),
    items: count('item'),
    attachments: count('attachment'),
    attachmentHeaders: count('attachment-header'),
    attachmentChunks: count('attachment-chunk'),
    tombstonePredecessors: {
      groups: predecessors.filter((entry) => entry.entityType === 'group').length,
      items: predecessors.filter((entry) => entry.entityType === 'item').length,
      attachments: predecessors.filter((entry) => entry.entityType === 'attachment')
        .length,
    },
    tombstones: count('tombstone'),
    histories: 0,
    audits: 0,
  };
}

async function captureError(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
    throw new Error('Expected operation to fail.');
  } catch (error) {
    return error;
  }
}

function errorText(error: unknown): string {
  if (error instanceof AggregateError) {
    return [
      error.name,
      error.message,
      ...error.errors.map((entry) => errorText(entry)),
    ].join(' ');
  }
  if (error instanceof Error) {
    const cause = error.cause instanceof Error ? errorText(error.cause) : '';
    return `${error.name} ${error.message} ${cause}`;
  }
  return String(error);
}

function createAttachmentGraph(): {
  item: EncryptedItemRecord;
  attachment: EncryptedAttachmentRecord;
  header: PersistedAttachmentHeaderRecord;
  chunk: PersistedAttachmentChunkRecord;
} {
  const item = encryptedItemRecordSchema.parse({
    id: ITEM_ID,
    vaultId: VAULT_ID,
    groupId: GROUP_ID,
    schemaVersion: 1,
    wrappedItemKey: opaqueEnvelope('wrapped-item-key', ITEM_ID, GROUP_ID),
    encryptedPayload: opaqueEnvelope('item', ITEM_ID, GROUP_ID),
    recordRevision: 1,
    ciphertextHash: DIGEST,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });
  const attachment = encryptedAttachmentRecordSchema.parse({
    id: ATTACHMENT_ID,
    vaultId: VAULT_ID,
    groupId: GROUP_ID,
    itemId: ITEM_ID,
    schemaVersion: 1,
    wrappedAttachmentKey: opaqueEnvelope(
      'wrapped-attachment-key',
      ATTACHMENT_ID,
      GROUP_ID,
      ITEM_ID,
    ),
    encryptedManifest: opaqueEnvelope('attachment', ATTACHMENT_ID, GROUP_ID, ITEM_ID),
    chunkCount: 1,
    recordRevision: 1,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });
  const identity = {
    version: 1,
    algorithm: 'secretstream-xchacha20-poly1305',
    streamVersion: 1,
    schemaVersion: 1,
    keyVersion: 1,
    vaultId: VAULT_ID,
    groupId: GROUP_ID,
    itemId: ITEM_ID,
    attachmentId: ATTACHMENT_ID,
  } as const;
  const headerBase = persistedAttachmentHeaderRecordSchema.parse({
    entityType: 'attachment-header',
    record: {
      ...identity,
      recordType: 'header',
      header: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
    recordRevision: 1,
    contentHash: DIGEST,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });
  const header = persistedAttachmentHeaderRecordSchema.parse({
    ...headerBase,
    contentHash: attachmentHeaderContentHash(headerBase),
  });
  const chunkBase = persistedAttachmentChunkRecordSchema.parse({
    entityType: 'attachment-chunk',
    record: {
      ...identity,
      recordType: 'chunk',
      index: 0,
      ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAA',
      tag: 'final',
    },
    plaintextBytes: 0,
    recordRevision: 1,
    ciphertextHash: DIGEST,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  });
  const chunk = persistedAttachmentChunkRecordSchema.parse({
    ...chunkBase,
    ciphertextHash: attachmentChunkCiphertextHash(chunkBase),
  });
  return { item, attachment, header, chunk };
}

function opaqueEnvelope(
  entityType: 'item' | 'attachment' | 'wrapped-item-key' | 'wrapped-attachment-key',
  entityId: string,
  groupId: string,
  parentId?: string,
): Record<string, unknown> {
  const purposes = {
    item: 'item-payload',
    attachment: 'attachment-metadata',
    'wrapped-item-key': 'item-key',
    'wrapped-attachment-key': 'attachment-key',
  } as const;
  return {
    version: 1,
    algorithm: 'xchacha20-poly1305-ietf',
    nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ciphertext: 'AQID',
    authenticationTag: 'AAAAAAAAAAAAAAAAAAAAAA',
    aad: {
      version: 1,
      schemaVersion: 1,
      keyVersion: 1,
      vaultId: VAULT_ID,
      entityType,
      entityId,
      groupId,
      ...(parentId === undefined ? {} : { parentId }),
      purpose: purposes[entityType],
    },
    keyVersion: 1,
  };
}

function withCanonicalHeaderHash(value: unknown): PersistedAttachmentHeaderRecord {
  const parsed = persistedAttachmentHeaderRecordSchema.parse(value);
  return persistedAttachmentHeaderRecordSchema.parse({
    ...parsed,
    contentHash: attachmentHeaderContentHash(parsed),
  });
}

async function collect(source: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const values: Uint8Array[] = [];
  for await (const value of source) {
    values.push(value);
  }
  return Buffer.concat(values);
}

function chunks(
  value: Uint8Array,
  chunkSize = value.byteLength,
): AsyncIterable<Uint8Array> {
  const values: Uint8Array[] = [];
  for (let offset = 0; offset < value.byteLength; offset += chunkSize) {
    values.push(value.subarray(offset, Math.min(offset + chunkSize, value.byteLength)));
  }
  return asyncIterable(values);
}

function asyncIterable<Value>(values: readonly Value[]): AsyncIterable<Value> {
  return {
    [Symbol.asyncIterator](): AsyncIterator<Value> {
      let index = 0;
      return {
        next(): Promise<IteratorResult<Value>> {
          const value = values[index];
          index += 1;
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

function replaceFooterTag(bytes: Buffer): Buffer {
  const lines = bytes.toString('utf8').trimEnd().split('\n');
  const footer = JSON.parse(lines.at(-1) ?? '') as Record<string, unknown>;
  footer['authenticationTag'] = sha256DigestSchema.parse(
    Buffer.alloc(32).toString('base64url'),
  );
  lines[lines.length - 1] = JSON.stringify(footer);
  return Buffer.from(`${lines.join('\n')}\n`, 'utf8');
}

function authenticateMutatedArchive(
  bytes: Buffer,
  rootKey: Uint8Array,
  targetKind: EncryptedBackupEntry['kind'],
  mutate: (entry: EncryptedBackupEntry) => EncryptedBackupEntry,
): Buffer {
  const lines = bytes.toString('utf8').trimEnd().split('\n');
  const header = JSON.parse(lines[0] ?? '') as {
    authentication: { salt: string };
  };
  const targetIndex = lines.findIndex((line) => {
    const value = JSON.parse(line) as { kind?: string };
    return value.kind === targetKind;
  });
  if (targetIndex < 1) throw new Error(`Missing ${targetKind} backup entry.`);
  lines[targetIndex] = JSON.stringify(
    mutate(JSON.parse(lines[targetIndex] ?? '') as EncryptedBackupEntry),
  );

  const salt = Buffer.from(header.authentication.salt, 'base64url');
  const authenticationKey = new Uint8Array(
    hkdfSync(
      'sha256',
      rootKey,
      salt,
      Buffer.from('credvault/backup-authentication/v1', 'ascii'),
      32,
    ),
  );
  try {
    const digest = createHash('sha256');
    const authentication = createHmac('sha256', authenticationKey);
    for (const line of lines.slice(0, -1)) {
      const encoded = Buffer.from(line, 'utf8');
      const length = Buffer.allocUnsafe(4);
      length.writeUInt32BE(encoded.byteLength);
      digest.update(length).update(encoded);
      authentication.update(length).update(encoded);
      length.fill(0);
    }
    const footer = JSON.parse(lines.at(-1) ?? '') as Record<string, unknown>;
    footer['transcriptSha256'] = digest.digest('base64url');
    footer['authenticationTag'] = authentication.digest('base64url');
    lines[lines.length - 1] = JSON.stringify(footer);
    return Buffer.from(`${lines.join('\n')}\n`, 'utf8');
  } finally {
    zeroize(authenticationKey);
    salt.fill(0);
  }
}
