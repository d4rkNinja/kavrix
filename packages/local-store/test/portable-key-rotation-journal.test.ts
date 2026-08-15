import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  deviceIdSchema,
  keySlotIdSchema,
  keySlotSchema,
  portableKeyRotationCheckpointSchema,
  vaultIdSchema,
  vaultRevisionSchema,
} from '@kavrix/schemas';
import {
  lifecycleOperationIdSchema,
  parsePortableKeyRotationJournalRecord,
  type PortableKeyRotationJournalRecord,
} from '@kavrix/client';
import { afterEach, describe, expect, it } from 'vitest';

import { setWindowsUserOnlyAcl } from '../../../packages/key-files/src/windows-acl.js';
import {
  openSqlitePortableKeyRotationJournal,
  type SqlitePortableKeyRotationJournal,
} from '../src/index.js';
import { digest } from './fixtures.js';

const VAULT_ID = vaultIdSchema.parse('vault.portable.rotation.sqlite');
const DEVICE_ID = deviceIdSchema.parse('device.portable.rotation.sqlite');
const SOURCE_SLOT_ID = keySlotIdSchema.parse('slot.rotation.sqlite.source');
const REPLACEMENT_SLOT_ID = keySlotIdSchema.parse('slot.rotation.sqlite.replace');
const OPERATION_ID = lifecycleOperationIdSchema.parse('operation.rotation.sqlite.0001');
const CREATED_AT = '2026-08-14T00:00:00.000Z';
const UPDATED_AT = '2026-08-14T00:01:00.000Z';

const openJournals: SqlitePortableKeyRotationJournal[] = [];
const roots: string[] = [];

afterEach(async () => {
  await Promise.allSettled(openJournals.splice(0).map((journal) => journal.close()));
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe('SqlitePortableKeyRotationJournal', () => {
  it('persists exact checkpoint transitions and reopens completed operations', async () => {
    const root = await mkdtemp(join(tmpdir(), 'kavrix-portable-rotation-journal-'));
    roots.push(root);
    if (process.platform === 'win32') await setWindowsUserOnlyAcl(root);
    const journal = await openJournal(join(root, 'rotation.sqlite'));
    const record = rotationRecord();

    await journal.createPrepared(record);
    await journal.createPrepared(record);
    expect(await journal.load(OPERATION_ID)).toEqual(record);

    const pendingCheckpoint = checkpoint('pending-published', 1);
    await journal.markPendingPublished(OPERATION_ID, UPDATED_AT, pendingCheckpoint);
    expect((await journal.load(OPERATION_ID))?.state).toBe('pending-published');

    const activeCheckpoint = checkpoint('active-published', 2);
    await journal.markActivePublished(OPERATION_ID, UPDATED_AT, activeCheckpoint);
    const completedCheckpoint = checkpoint('completed', 3);
    await journal.complete(OPERATION_ID, UPDATED_AT, completedCheckpoint);
    await journal.complete(OPERATION_ID, UPDATED_AT, completedCheckpoint);
    expect(await journal.load(OPERATION_ID)).toMatchObject({ state: 'completed' });

    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);
    const reopened = await openJournal(join(root, 'rotation.sqlite'));
    expect(await reopened.load(OPERATION_ID)).toMatchObject({
      state: 'completed',
      checkpoint: completedCheckpoint,
    });
  });
});

async function openJournal(path: string): Promise<SqlitePortableKeyRotationJournal> {
  const journal = await openSqlitePortableKeyRotationJournal({ path });
  openJournals.push(journal);
  return journal;
}

function rotationRecord(): PortableKeyRotationJournalRecord {
  const sourceSlot = keySlot('active', SOURCE_SLOT_ID);
  const replacementSlot = keySlot('pending', REPLACEMENT_SLOT_ID);
  return parsePortableKeyRotationJournalRecord({
    version: 1,
    kind: 'portable-key-rotation',
    operationId: OPERATION_ID,
    vaultId: VAULT_ID,
    deviceId: DEVICE_ID,
    state: 'prepared',
    sourceKind: 'imported-file',
    sourceSlot,
    replacementSlot,
    sourceRevision: 0,
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
    checkpoint: checkpoint('prepared', 0),
  });
}

function keySlot(
  state: 'active' | 'pending',
  id: ReturnType<typeof keySlotIdSchema.parse>,
): ReturnType<typeof keySlotSchema.parse> {
  return keySlotSchema.parse({
    slotVersion: 1,
    id,
    type: 'portable-key',
    state,
    keyVersion: 1,
    derivation: {
      algorithm: 'hkdf-sha256',
      version: 1,
      salt: 'A'.repeat(43),
      context: 'credvault/v1/portable-key-wrap',
      outputLength: 32,
    },
    wrappedRootKey: {
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: 'A'.repeat(32),
      ciphertext: 'A'.repeat(43),
      authenticationTag: 'A'.repeat(22),
      aad: {
        version: 1,
        schemaVersion: 1,
        keyVersion: 1,
        vaultId: VAULT_ID,
        entityType: 'wrapped-root-key',
        entityId: id,
        purpose: 'vrk-slot',
      },
      keyVersion: 1,
    },
    createdAt: CREATED_AT,
  });
}

function checkpoint(
  state: 'prepared' | 'pending-published' | 'active-published' | 'completed',
  remoteRevision: number,
): ReturnType<typeof portableKeyRotationCheckpointSchema.parse> {
  return portableKeyRotationCheckpointSchema.parse({
    payload: {
      version: 1,
      vaultId: VAULT_ID,
      operationId: OPERATION_ID,
      sourceSlotId: SOURCE_SLOT_ID,
      replacementSlotId: REPLACEMENT_SLOT_ID,
      sourceRevision: vaultRevisionSchema.parse(0),
      remoteRevision: vaultRevisionSchema.parse(remoteRevision),
      sourceSlotDigest: 'A'.repeat(43),
      replacementSlotDigest: digest,
      transcriptDigest: digest,
      state,
    },
    authenticationTag: digest,
  });
}
