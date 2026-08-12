import { ValidationError } from '@kavrix/core';
import {
  backupVerificationSchema,
  canonicalJson,
  sha256DigestSchema,
} from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import {
  backupRestoreEntryDocumentSchema,
  backupRestoreSessionDocumentSchema,
  backupRestoreStatusFromDocument,
  makeRestoreEntryDocument,
  parseRestoreEntryDocument,
  parseRestoreSessionDocument,
  restoreEntryDocumentId,
  restoreEntryIdentity,
} from '../src/index.js';
import { groupRecord, timestamp, vaultRecord } from './fixtures.js';

const restoreSessionId = sha256DigestSchema.parse(
  'AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
);
const summary = backupVerificationSchema.parse({
  header: {
    type: 'header',
    format: 'kavrix-encrypted-backup',
    version: 1,
    vaultId: vaultRecord().id,
    schemaVersion: 1,
    createdAt: timestamp,
    authentication: {
      algorithm: 'hkdf-sha256+hmac-sha256',
      salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
  },
  restoreSessionId,
  recordCount: 1,
  transcriptSha256: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  canonicalEntriesSha256: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
});

describe('Mongo encrypted-backup staging documents', () => {
  it('binds staged entries to session, ordinal, canonical identity, and hash', () => {
    const entry = { kind: 'group' as const, record: groupRecord() };
    const bytes = Buffer.byteLength(canonicalJson(entry), 'utf8') + 1;
    const document = makeRestoreEntryDocument(restoreSessionId, 1, bytes, entry);

    expect(document).toMatchObject({
      _id: restoreEntryDocumentId(restoreSessionId, 'group:group.1'),
      restoreSessionId,
      ordinal: 1,
      identity: restoreEntryIdentity(entry),
      vaultId: 'vault.1',
      bytes,
    });
    expect(parseRestoreEntryDocument(document)).toEqual(document);
    expect(() =>
      parseRestoreEntryDocument({
        ...document,
        entry: { ...entry, record: { ...entry.record, recordRevision: 1 } },
      }),
    ).toThrow(ValidationError);
    expect(() =>
      parseRestoreEntryDocument({ ...document, restoreSessionId: 'A'.repeat(43) }),
    ).toThrow(ValidationError);
    expect(() =>
      parseRestoreEntryDocument({ ...document, bytes: document.bytes + 1 }),
    ).toThrow(ValidationError);
  });

  it('rejects a raw unknown key-slot field through vault restore entries', () => {
    const entry = { kind: 'vault' as const, record: vaultRecord() };
    const document = makeRestoreEntryDocument(
      restoreSessionId,
      1,
      Buffer.byteLength(canonicalJson(entry), 'utf8') + 1,
      entry,
    );
    const keySlot = entry.record.keySlots[0];
    expect(keySlot).toBeDefined();
    if (keySlot === undefined) return;
    expect(backupRestoreEntryDocumentSchema.safeParse(document).success).toBe(true);

    expect(
      backupRestoreEntryDocumentSchema.safeParse({
        ...document,
        entry: {
          ...entry,
          record: {
            ...entry.record,
            keySlots: [{ ...keySlot, unexpectedMetadata: 'opaque' }],
          },
        },
      }).success,
    ).toBe(false);
  });

  it('accepts every exact protocol-v2 durable branch', () => {
    const progress = {
      _id: restoreSessionId,
      protocolVersion: 2,
      restoreSessionId,
      maximumBytes: 1_048_576,
      maximumRecords: 10,
      stagedBytes:
        Buffer.byteLength(
          canonicalJson({ kind: 'vault', record: vaultRecord() }),
          'utf8',
        ) + 1,
      stagedRecords: 1,
      vaultId: vaultRecord().id,
      createdAt: timestamp,
      updatedAt: timestamp,
    } as const;
    const documents = [
      { ...progress, state: 'staging' },
      { ...progress, state: 'sealed', summary, sealedAt: timestamp },
      {
        ...progress,
        state: 'published',
        summary,
        sealedAt: timestamp,
        publishedAt: timestamp,
      },
      {
        _id: restoreSessionId,
        state: 'committed',
        protocolVersion: 2,
        restoreSessionId,
        summary,
        committedAt: timestamp,
      },
      {
        _id: restoreSessionId,
        state: 'aborted',
        protocolVersion: 2,
        restoreSessionId,
        abortedAt: timestamp,
      },
    ] as const;

    for (const document of documents) {
      expect(parseRestoreSessionDocument(document)).toEqual(document);
      const { _id: documentId, ...status } = document;
      void documentId;
      expect(backupRestoreStatusFromDocument(document)).toEqual(status);
      expect(backupRestoreStatusFromDocument(document)).not.toHaveProperty('_id');
      expect(
        backupRestoreSessionDocumentSchema.safeParse({
          ...document,
          unexpected: 'closed',
        }).success,
      ).toBe(false);
    }
  });

  it('rejects legacy, crossed, mismatched, and impossible durable states', () => {
    const stagedBytes =
      Buffer.byteLength(
        canonicalJson({ kind: 'vault', record: vaultRecord() }),
        'utf8',
      ) + 1;
    const staging = backupRestoreSessionDocumentSchema.parse({
      _id: restoreSessionId,
      protocolVersion: 2,
      restoreSessionId,
      maximumBytes: 1_048_576,
      maximumRecords: 10,
      state: 'staging',
      stagedBytes,
      stagedRecords: 1,
      vaultId: vaultRecord().id,
      createdAt: timestamp,
      updatedAt: timestamp,
    });

    for (const invalid of [
      { ...staging, protocolVersion: undefined },
      { ...staging, protocolVersion: 1 },
      { ...staging, _id: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
      { ...staging, stagedBytes: 0 },
      { ...staging, stagedRecords: 0 },
      { ...staging, vaultId: undefined },
      { ...staging, stagedBytes: 0, stagedRecords: 0 },
      {
        ...staging,
        stagedBytes: 0,
        stagedRecords: 0,
        vaultId: vaultRecord().id,
      },
      { ...staging, maximumRecords: 0 },
      { ...staging, committedAt: timestamp },
      {
        ...staging,
        state: 'sealed',
        vaultId: 'vault.other',
        summary,
        sealedAt: timestamp,
      },
      {
        ...staging,
        state: 'published',
        vaultId: 'vault.other',
        summary,
        sealedAt: timestamp,
        publishedAt: timestamp,
      },
      {
        ...staging,
        state: 'published',
        summary,
        sealedAt: timestamp,
      },
      {
        ...staging,
        state: 'published',
        summary,
        sealedAt: timestamp,
        publishedAt: timestamp,
        abortedAt: timestamp,
      },
      {
        ...staging,
        state: 'sealed',
        summary: {
          ...summary,
          restoreSessionId: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        },
        sealedAt: timestamp,
      },
      {
        ...staging,
        state: 'sealed',
        summary: { ...summary, recordCount: 2 },
        sealedAt: timestamp,
      },
      {
        _id: restoreSessionId,
        state: 'committed',
        protocolVersion: 2,
        restoreSessionId,
        summary: {
          ...summary,
          restoreSessionId: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        },
        committedAt: timestamp,
      },
      {
        _id: restoreSessionId,
        state: 'aborted',
        protocolVersion: 2,
        restoreSessionId,
        abortedAt: timestamp,
        vaultId: vaultRecord().id,
      },
    ]) {
      expect(backupRestoreSessionDocumentSchema.safeParse(invalid).success).toBe(false);
    }

    expect(() =>
      parseRestoreSessionDocument({ ...staging, maximumRecords: 0 }),
    ).toThrow(ValidationError);
  });
});
