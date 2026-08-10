import { ValidationError } from '@kavrix/core';
import { changeRecordSchema, tombstoneRecordSchema } from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import {
  contentHashForRecord,
  expectedNextRevision,
  fromAttachmentDocument,
  fromChangeDocument,
  fromGroupDocument,
  fromItemDocument,
  fromSyncPulledChangeDocument,
  fromTombstoneDocument,
  fromVaultDocument,
  hashCanonical,
  makeStagedChunkDocument,
  parseMutation,
  synchronizeVaultRecordRevision,
  syncPushBatchDocumentId,
  syncPushBatchDocumentSchema,
  templateMigrationPublicationDocumentId,
  templateMigrationPublicationDocumentSchema,
  toAttachmentDocument,
  toChangeDocument,
  toGroupDocument,
  toItemDocument,
  toTombstoneDocument,
  toVaultDocument,
} from '../src/index.js';
import {
  attachmentChunk,
  attachmentFinalize,
  digest,
  groupRecord,
  itemRecord,
  later,
  plaintextCanary,
  timestamp,
  vaultRecord,
  mutation,
} from './fixtures.js';

describe('Mongo document boundaries', () => {
  it('round-trips canonical opaque entity records', () => {
    const vault = vaultRecord();
    const group = groupRecord();
    const item = itemRecord();
    const attachment = attachmentFinalize().record;

    expect(fromVaultDocument(toVaultDocument(vault))).toEqual(vault);
    expect(fromGroupDocument(toGroupDocument(group))).toEqual(group);
    expect(fromItemDocument(toItemDocument(item))).toEqual(item);
    expect(
      fromAttachmentDocument(toAttachmentDocument(attachment, 'staging.1')),
    ).toEqual(attachment);
  });

  it('stores the plaintext canary only as encoded ciphertext', () => {
    const document = toItemDocument(itemRecord());
    const serialized = JSON.stringify(document);
    expect(serialized).not.toContain(plaintextCanary);
    expect(document).not.toHaveProperty('title');
    expect(document.record).not.toHaveProperty('title');
    expect(document.record.encryptedPayload.ciphertext).toBe(
      Buffer.from(plaintextCanary).toString('base64url'),
    );
  });

  it('fails closed when a database document adds plaintext or changes identity', () => {
    const document = toItemDocument(itemRecord());
    expect(() => fromItemDocument({ ...document, title: plaintextCanary })).toThrow(
      ValidationError,
    );
    expect(() => fromItemDocument({ ...document, groupId: 'group.other' })).toThrow(
      ValidationError,
    );
    expect(() =>
      parseMutation({ ...mutation('item', itemRecord(), null), $where: 'unsafe' }),
    ).toThrow(ValidationError);
  });

  it('maps change, tombstone, and staged chunk records through strict schemas', () => {
    const change = changeRecordSchema.parse({
      id: 'change.1',
      vaultId: 'vault.1',
      serverSequence: 1,
      entityType: 'item',
      entityId: 'item.1',
      recordRevision: 1,
      operation: 'tombstone',
      ciphertextHash: digest,
      createdAt: timestamp,
    });
    const tombstone = tombstoneRecordSchema.parse({
      vaultId: 'vault.1',
      entityType: 'item',
      entityId: 'item.1',
      state: 'deleted',
      tombstoneRevision: 1,
      lastRecordRevision: 0,
      lastCiphertextHash: digest,
      deletedAt: timestamp,
    });
    const changeDocument = toChangeDocument(change, tombstone);
    expect(fromChangeDocument(changeDocument)).toEqual(change);
    expect(fromSyncPulledChangeDocument(changeDocument)).toEqual({
      change,
      record: tombstone,
    });
    expect(fromTombstoneDocument(toTombstoneDocument(tombstone))).toEqual(tombstone);
    expect(
      makeStagedChunkDocument('staging.1', attachmentChunk(0, 'final')),
    ).toMatchObject({
      stagingId: 'staging.1',
      chunkIndex: 0,
      attachmentId: 'attachment.1',
    });
  });
});

describe('deterministic commit metadata', () => {
  it('hashes object keys canonically and keeps array order significant', () => {
    expect(hashCanonical({ second: 2, first: 1 })).toBe(
      hashCanonical({ first: 1, second: 2 }),
    );
    expect(hashCanonical([1, 2])).not.toBe(hashCanonical([2, 1]));
  });

  it('derives canonical revisions and content hashes', () => {
    expect(expectedNextRevision(null)).toBe(0);
    expect(expectedNextRevision(4)).toBe(5);
    expect(contentHashForRecord(itemRecord())).toBe(digest);
    expect(contentHashForRecord(groupRecord())).toMatch(/^[A-Za-z0-9_-]{43}$/u);
  });

  it('advances the vault rollback anchor once without changing encrypted material', () => {
    const original = vaultRecord();
    const synchronized = synchronizeVaultRecordRevision(original, 1, later);
    expect(synchronized).toMatchObject({ revision: 1, updatedAt: later });
    expect(synchronized.encryptedPreferences).toEqual(original.encryptedPreferences);
    expect(synchronized.keySlots).toEqual(original.keySlots);
    expect(() => synchronizeVaultRecordRevision(original, 2, later)).toThrow(
      ValidationError,
    );

    const nonRegressing = synchronizeVaultRecordRevision(
      original,
      1,
      '2026-08-09T00:00:00.000Z',
    );
    expect(nonRegressing.updatedAt).toBe(original.updatedAt);
  });

  it('binds durable sync push checkpoints to their exact progress', () => {
    const batchIdempotencyKey = 'sync-push-batch-0001';
    const running = {
      _id: syncPushBatchDocumentId('vault.1', batchIdempotencyKey),
      vaultId: 'vault.1',
      batchIdempotencyKey,
      requestHash: 'a'.repeat(64),
      mutationCount: 2,
      state: 'running',
      nextMutationIndex: 0,
      results: [],
      createdAt: timestamp,
      updatedAt: timestamp,
    };
    expect(syncPushBatchDocumentSchema.safeParse(running).success).toBe(true);
    expect(
      syncPushBatchDocumentSchema.safeParse({
        ...running,
        nextMutationIndex: 1,
      }).success,
    ).toBe(false);
    expect(
      syncPushBatchDocumentSchema.safeParse({
        ...running,
        _id: 'vault.1|batch|wrong',
      }).success,
    ).toBe(false);
  });

  it('binds a durable template migration receipt to its request key and vault', () => {
    const batchIdempotencyKey = 'template-migration-batch-0001';
    const change = changeRecordSchema.parse({
      id: 'change.template.group',
      vaultId: 'vault.1',
      serverSequence: 4,
      entityType: 'group',
      entityId: 'group.1',
      recordRevision: 1,
      operation: 'upsert',
      ciphertextHash: contentHashForRecord(groupRecord(1)),
      createdAt: later,
    });
    const document = {
      _id: templateMigrationPublicationDocumentId('vault.1', batchIdempotencyKey),
      vaultId: 'vault.1',
      batchIdempotencyKey,
      requestHash: 'b'.repeat(64),
      response: {
        vaultId: 'vault.1',
        batchIdempotencyKey,
        serverVaultRevision: 4,
        results: [{ idempotencyKey: 'template-group-item-0001', change }],
      },
      committedAt: later,
    };
    expect(templateMigrationPublicationDocumentSchema.parse(document)).toEqual(
      document,
    );
    expect(
      templateMigrationPublicationDocumentSchema.safeParse({
        ...document,
        response: { ...document.response, vaultId: 'vault.other' },
      }).success,
    ).toBe(false);
  });
});
