import {
  createPortableKeySlot,
  encryptPayload,
  generateGroupKey,
  generatePortableKey,
  generateVaultRootKey,
  wrapGroupKey,
  zeroize,
} from '@kavrix/crypto';
import {
  associatedDataSchema,
  contentHashForRecord,
  encryptedAttachmentRecordSchema,
  encryptedGroupRecordSchema,
  encryptedItemRecordSchema,
  groupIdSchema,
  persistedAttachmentChunkRecordSchema,
  persistedAttachmentHeaderRecordSchema,
  keySlotIdSchema,
  recordRevisionSchema,
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
} from '../src/index.js';

const CREATED_AT = timestampSchema.parse('2026-08-10T00:00:00.000Z');
const VAULT_ID = vaultIdSchema.parse('vault-1');
const OTHER_VAULT_ID = vaultIdSchema.parse('vault-2');
const GROUP_ID = groupIdSchema.parse('group-1');
const ITEM_ID = 'item-1';
const ATTACHMENT_ID = 'attachment-1';
const DIGEST = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
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
      const staged: EncryptedBackupEntry[] = [];
      let committed = false;
      let aborted = false;
      const stager: BackupRestoreStager = {
        write(entry): Promise<void> {
          staged.push(entry);
          return Promise.resolve();
        },
        commit(): Promise<void> {
          committed = true;
          return Promise.resolve();
        },
        status(): Promise<'staging'> {
          return Promise.resolve('staging');
        },
        abort(): Promise<void> {
          aborted = true;
          staged.length = 0;
          return Promise.resolve();
        },
      };

      await expect(
        restoreEncryptedBackup(
          chunks(tampered),
          fixture.rootKey,
          VAULT_ID,
          storeFor(stager),
        ),
      ).rejects.toBeInstanceOf(BackupError);
      expect({ aborted, committed, staged }).toEqual({
        aborted: true,
        committed: false,
        staged: [],
      });
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
      const staged: EncryptedBackupEntry[] = [];
      const events: string[] = [];
      await restoreEncryptedBackup(
        chunks(bytes, 1),
        fixture.rootKey,
        VAULT_ID,
        storeFor({
          write(entry): Promise<void> {
            events.push(`write:${entry.kind}`);
            staged.push(entry);
            return Promise.resolve();
          },
          commit(summary): Promise<void> {
            events.push(`commit:${String(summary.recordCount)}`);
            return Promise.resolve();
          },
          status(): Promise<'committed'> {
            return Promise.resolve('committed');
          },
          abort(): Promise<void> {
            events.push('abort');
            return Promise.resolve();
          },
        }),
      );

      expect(staged.map((entry) => entry.kind)).toEqual(['vault', 'group']);
      expect(events).toEqual(['write:vault', 'write:group', 'commit:2']);
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

      for (const records of [
        [
          { kind: 'group', record: fixture.group },
          { kind: 'item', record: graph.item },
          { kind: 'attachment', record: graph.attachment },
          {
            kind: 'attachment-header',
            record: persistedAttachmentHeaderRecordSchema.parse({
              ...graph.header,
              record: { ...graph.header.record, keyVersion: 2 },
            }),
          },
          { kind: 'attachment-chunk', record: graph.chunk },
        ],
        [
          { kind: 'group', record: fixture.group },
          { kind: 'item', record: graph.item },
          { kind: 'attachment', record: graph.attachment },
          { kind: 'attachment-header', record: graph.header },
          {
            kind: 'attachment-chunk',
            record: persistedAttachmentChunkRecordSchema.parse({
              ...graph.chunk,
              record: { ...graph.chunk.record, schemaVersion: 2 },
            }),
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
        ).rejects.toMatchObject({ code: 'BACKUP_INCOMPLETE' });
      }
    } finally {
      zeroize(fixture.rootKey);
    }
  });

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
      const staged: EncryptedBackupEntry[] = [];
      let aborted = false;
      const stager: BackupRestoreStager = {
        write(entry): Promise<void> {
          staged.push(entry);
          return Promise.resolve();
        },
        commit(): Promise<void> {
          return Promise.resolve();
        },
        status(): Promise<'staging'> {
          return Promise.resolve('staging');
        },
        abort(): Promise<void> {
          aborted = true;
          staged.length = 0;
          return Promise.resolve();
        },
      };

      await expect(
        restoreEncryptedBackup(
          chunks(bytes),
          fixture.rootKey,
          VAULT_ID,
          storeFor(stager),
          { maximumRecords: 1 },
        ),
      ).rejects.toMatchObject({ code: 'BACKUP_TOO_LARGE' });
      expect({ aborted, staged }).toEqual({ aborted: true, staged: [] });

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

  it('reconciles ambiguous commit outcomes with durable staging status', async () => {
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
      const stager = (status: 'staging' | 'committed'): BackupRestoreStager => ({
        write(): Promise<void> {
          return Promise.resolve();
        },
        commit(): Promise<never> {
          return Promise.reject(new Error('ambiguous transport failure'));
        },
        status(): Promise<'staging' | 'committed'> {
          return Promise.resolve(status);
        },
        abort(): Promise<void> {
          return Promise.resolve();
        },
      });

      await expect(
        restoreEncryptedBackup(
          chunks(bytes),
          fixture.rootKey,
          VAULT_ID,
          storeFor(stager('staging')),
        ),
      ).rejects.toMatchObject({ code: 'BACKUP_COMMIT_UNCERTAIN' });
      await expect(
        restoreEncryptedBackup(
          chunks(bytes),
          fixture.rootKey,
          VAULT_ID,
          storeFor(stager('committed')),
        ),
      ).resolves.toMatchObject({ recordCount: 2 });
    } finally {
      zeroize(fixture.rootKey);
    }
  });

  it('preserves staging failures and aborts hidden state before commit starts', async () => {
    const fixture = await createFixture();
    const storageFailure = new Error('storage unavailable');
    let aborted = false;
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
        restoreEncryptedBackup(
          chunks(bytes),
          fixture.rootKey,
          VAULT_ID,
          storeFor({
            write(): Promise<never> {
              return Promise.reject(storageFailure);
            },
            commit(): Promise<void> {
              return Promise.resolve();
            },
            status(): Promise<'staging'> {
              return Promise.resolve('staging');
            },
            abort(): Promise<void> {
              aborted = true;
              return Promise.resolve();
            },
          }),
        ),
      ).rejects.toBe(storageFailure);
      expect(aborted).toBe(true);
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

function storeFor(stager: BackupRestoreStager): BackupRestoreStore {
  return {
    open(): Promise<BackupRestoreStager> {
      return Promise.resolve(stager);
    },
  };
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
  const header = persistedAttachmentHeaderRecordSchema.parse({
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
  const chunk = persistedAttachmentChunkRecordSchema.parse({
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
