import { ValidationError } from '@kavrix/core';
import { sha256DigestSchema } from '@kavrix/schemas';
import { describe, expect, it } from 'vitest';

import {
  backupRestoreEntryDocumentSchema,
  backupRestoreSessionDocumentSchema,
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

describe('Mongo encrypted-backup staging documents', () => {
  it('binds staged entries to session, ordinal, canonical identity, and hash', () => {
    const entry = { kind: 'group' as const, record: groupRecord() };
    const document = makeRestoreEntryDocument(restoreSessionId, 1, 1_024, entry);

    expect(document).toMatchObject({
      _id: restoreEntryDocumentId(restoreSessionId, 'group:group.1'),
      restoreSessionId,
      ordinal: 1,
      identity: restoreEntryIdentity(entry),
      vaultId: 'vault.1',
      bytes: 1_024,
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
  });

  it('rejects a raw unknown key-slot field through vault restore entries', () => {
    const entry = { kind: 'vault' as const, record: vaultRecord() };
    const document = makeRestoreEntryDocument(restoreSessionId, 1, 1_024, entry);
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

  it('requires exact durable state and zero retained counters after close', () => {
    const staging = backupRestoreSessionDocumentSchema.parse({
      _id: restoreSessionId,
      restoreSessionId,
      maximumBytes: 1_048_576,
      maximumRecords: 10,
      state: 'staging',
      stagedBytes: 1_024,
      stagedRecords: 1,
      vaultId: vaultRecord().id,
      createdAt: timestamp,
      updatedAt: timestamp,
    });
    expect(parseRestoreSessionDocument(staging)).toEqual(staging);
    expect(
      backupRestoreSessionDocumentSchema.safeParse({
        ...staging,
        state: 'aborted',
        abortedAt: timestamp,
      }).success,
    ).toBe(false);
    expect(() =>
      parseRestoreSessionDocument({ ...staging, maximumRecords: 0 }),
    ).toThrow(ValidationError);
  });
});
