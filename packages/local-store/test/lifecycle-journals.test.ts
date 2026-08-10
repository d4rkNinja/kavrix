import { spawn, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readFile, realpath, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { afterEach, describe, expect, it } from 'vitest';

import {
  initializationJournalRecordSchema,
  joinPreparedJournalRecordSchema,
  lifecycleOperationIdSchema,
  type InitializationActiveJournalRecord,
  type JoinPreparedJournalRecord,
} from '@kavrix/client';
import { NativeJoinJournalSecrets, type NativeEntryFactory } from '@kavrix/keychain';
import { aeadEnvelopeSchema } from '@kavrix/schemas';
import { SyncLocalStateError } from '@kavrix/sync';

import {
  openSqliteInitializationJournal,
  openSqliteJoinLifecycleJournal,
  type SqliteInitializationJournal,
  type SqliteJoinLifecycleJournal,
  type SqliteLifecycleJournalOptions,
} from '../src/index.js';

const NOW = '2026-08-10T00:00:00.000Z';
const TEST_TMPDIR = await realpath(tmpdir());
const LEASE_CHILD_MODULE = new URL('../dist/index.js', import.meta.url).href;
const LEASE_CHILD_SOURCE = `
  import { writeFile } from 'node:fs/promises';
  const [moduleUrl, leasePath, readyPath, mode] = process.argv.slice(1);
  const { acquireLocalWriterLease } = await import(moduleUrl);
  await acquireLocalWriterLease(leasePath);
  await writeFile(readyPath, 'ready', { flag: 'wx' });
  if (mode === 'crash') process.exit(0);
  setInterval(() => {}, 1000);
`;
const roots: string[] = [];
const openJournals: (SqliteInitializationJournal | SqliteJoinLifecycleJournal)[] = [];

afterEach(async () => {
  await Promise.allSettled(openJournals.splice(0).map((journal) => journal.close()));
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { force: true, recursive: true })),
  );
});

class TestNativeEntries {
  readonly values = new Map<string, Uint8Array>();
  setFailure: 'before' | 'after' | null = null;
  deleteFailure: 'before' | 'after' | null = null;

  readonly createEntry: NativeEntryFactory = (service, account) => {
    const key = `${service}/${account}`;
    return {
      setSecret: (value): Promise<void> => {
        const failure = this.setFailure;
        this.setFailure = null;
        if (failure === 'before') return Promise.reject(new Error('native-canary'));
        this.values.set(key, Uint8Array.from(value));
        return failure === 'after'
          ? Promise.reject(new Error('native-canary'))
          : Promise.resolve();
      },
      getSecret: (): Promise<Uint8Array | undefined> => {
        const value = this.values.get(key);
        return Promise.resolve(
          value === undefined ? undefined : Uint8Array.from(value),
        );
      },
      deleteCredential: (): Promise<boolean> => {
        const failure = this.deleteFailure;
        this.deleteFailure = null;
        if (failure === 'before') return Promise.reject(new Error('native-canary'));
        const deleted = this.values.delete(key);
        return failure === 'after'
          ? Promise.reject(new Error('native-canary'))
          : Promise.resolve(deleted);
      },
    };
  };
}

describe('SqliteInitializationJournal', () => {
  it('persists exact records with CAS transitions and atomically drops active locators', async () => {
    const fixture = journalPath('initialization.sqlite');
    let journal = await openInitialization(fixture.path);
    const prepared = initializationRecord('operation.init.sqlite.0001');

    await journal.createPrepared(prepared);
    await journal.createPrepared(prepared);
    expect(await journal.listOperationIds()).toEqual([prepared.operationId]);
    expect(await journal.load(prepared.operationId)).toEqual(prepared);
    await journal.markNetworkAttempted(prepared.operationId);
    await journal.markNetworkAttempted(prepared.operationId);
    expect(await journal.load(prepared.operationId)).toMatchObject({
      state: 'network-attempted',
    });
    await journal.commit(
      prepared.operationId,
      { vaultId: prepared.request.vault.id, deviceId: prepared.request.device.id },
      prepared.profile,
      NOW,
    );
    await journal.commit(
      prepared.operationId,
      { vaultId: prepared.request.vault.id, deviceId: prepared.request.device.id },
      prepared.profile,
      NOW,
    );
    const committed = {
      version: 1,
      kind: 'vault-initialization',
      operationId: prepared.operationId,
      state: 'committed',
      receipt: {
        vaultId: prepared.request.vault.id,
        deviceId: prepared.request.device.id,
      },
      profile: prepared.profile,
      committedAt: NOW,
    } as const;
    expect(await journal.load(prepared.operationId)).toEqual(committed);
    await expect(journal.deletePrepared(prepared.operationId)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );

    const database = new DatabaseSync(fixture.path, { readOnly: true });
    try {
      const row = database
        .prepare(
          `SELECT device_locator_json, session_locator_json
             FROM initialization_journal WHERE operation_id = ?`,
        )
        .get(prepared.operationId) as Record<string, unknown>;
      expect(row).toEqual({
        device_locator_json: null,
        session_locator_json: null,
      });
    } finally {
      database.close();
    }
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);
    journal = await openInitialization(fixture.path);
    expect(await journal.load(prepared.operationId)).toEqual(committed);
  });

  it('rejects operation and locator collisions while deleting only prepared records', async () => {
    const { path } = journalPath('initialization.sqlite');
    const journal = await openInitialization(path);
    const first = initializationRecord('operation.init.sqlite.0001');
    await journal.createPrepared(first);
    await expect(
      journal.createPrepared({
        ...first,
        request: {
          ...first.request,
          vault: {
            ...first.request.vault,
            encryptedPreferences: {
              ...first.request.vault.encryptedPreferences,
              ciphertext: 'B'.repeat(43),
            },
          },
        },
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    const collision = initializationJournalRecordSchema.parse({
      ...first,
      operationId: 'operation.init.sqlite.0002',
    });
    await expect(journal.createPrepared(collision as never)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await journal.deletePrepared(first.operationId);
    await expect(journal.load(first.operationId)).resolves.toBeNull();
  }, 30_000);

  it('survives close/reopen and enforces lexical bounded operation lists', async () => {
    const { path } = journalPath('initialization.sqlite');
    let journal = await openInitialization(path, { maxOperations: 2 });
    const second = initializationRecord(
      'operation.init.sqlite.0002',
      'vault.init.2',
      'device.init.2',
      'slot.init.2',
    );
    const first = initializationRecord('operation.init.sqlite.0001');
    await journal.createPrepared(second);
    await journal.createPrepared(first);
    expect(await journal.listOperationIds()).toEqual([
      first.operationId,
      second.operationId,
    ]);
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);

    journal = await openInitialization(path, { maxOperations: 2 });
    expect(await journal.load(second.operationId)).toEqual(second);
    const third = initializationRecord(
      'operation.init.sqlite.0003',
      'vault.init.3',
      'device.init.3',
      'slot.init.3',
    );
    await expect(journal.createPrepared(third)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
  });

  it('rejects canonical-name schema weakening and corrupt canonical rows on reopen', async () => {
    const first = journalPath('weakened.sqlite');
    let journal = await openInitialization(first.path);
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);
    const weakened = new DatabaseSync(first.path);
    weakened.exec(`
      DROP TABLE initialization_journal;
      CREATE TABLE initialization_journal (
        operation_id TEXT PRIMARY KEY,
        state TEXT,
        record_json TEXT,
        serialized_bytes INTEGER,
        device_locator_json TEXT,
        session_locator_json TEXT
      ) STRICT;
    `);
    weakened.close();
    await expect(
      openSqliteInitializationJournal({ path: first.path }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);

    const second = journalPath('corrupt.sqlite');
    journal = await openInitialization(second.path);
    const prepared = initializationRecord('operation.init.sqlite.0001');
    await journal.createPrepared(prepared);
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);
    const corrupt = new DatabaseSync(second.path);
    corrupt
      .prepare(
        `UPDATE initialization_journal
            SET record_json = '{"version":1}', serialized_bytes = 13`,
      )
      .run();
    corrupt.close();
    await expect(
      openSqliteInitializationJournal({ path: second.path }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  }, 30_000);

  it('uses initialization format v2 and refuses the earlier format without migration', async () => {
    const fixture = journalPath('initialization.sqlite');
    const journal = await openInitialization(fixture.path);
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);

    const oldFormat = new DatabaseSync(fixture.path);
    expect(oldFormat.prepare('PRAGMA user_version').get()).toEqual({ user_version: 2 });
    expect(
      oldFormat
        .prepare(`SELECT value FROM lifecycle_metadata WHERE key = 'format'`)
        .get(),
    ).toEqual({ value: 'kavrix-initialization-journal-v2' });
    oldFormat.exec('PRAGMA user_version = 1');
    oldFormat
      .prepare(`UPDATE lifecycle_metadata SET value = ? WHERE key = 'format'`)
      .run('kavrix-initialization-journal-v1');
    oldFormat.close();

    await expect(
      openSqliteInitializationJournal({ path: fixture.path }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  });

  it('holds a cross-process-style writer lease for the journal lifetime', async () => {
    const { path } = journalPath('initialization.sqlite');
    const journal = await openInitialization(path);
    await expect(openSqliteInitializationJournal({ path })).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);
    const reopened = await openInitialization(path);
    await expect(reopened.listOperationIds()).resolves.toEqual([]);
  });

  it('rejects impossible limits, unknown options, and noncanonical paths', async () => {
    const invalidOptions: unknown[] = [
      { path: 'relative.sqlite' },
      { path: journalPath('state.sqlite').path, unknown: true },
      { path: journalPath('state.sqlite').path, maxOperations: 0 },
      { path: journalPath('state.sqlite').path, maxOperations: 257 },
      { path: journalPath('state.sqlite').path, maxSerializedBytes: 1_023 },
      { path: journalPath('state.sqlite').path, maxSerializedBytes: 33_554_433 },
      { path: journalPath('state.sqlite').path, maxDatabaseBytes: 1_048_575 },
      { path: journalPath('state.sqlite').path, maxDatabaseBytes: 536_870_913 },
    ];
    for (const options of invalidOptions) {
      await expect(
        openSqliteInitializationJournal(options as SqliteLifecycleJournalOptions),
      ).rejects.toBeInstanceOf(SyncLocalStateError);
    }
  });

  it('rejects out-of-order and incompatible initialization CAS targets', async () => {
    const { path } = journalPath('initialization.sqlite');
    const journal = await openInitialization(path);
    const prepared = initializationRecord('operation.init.cas-errors.0001');
    await journal.createPrepared(prepared);
    await expect(
      journal.commit(
        prepared.operationId,
        { vaultId: prepared.request.vault.id, deviceId: prepared.request.device.id },
        prepared.profile,
        NOW,
      ),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      journal.createPrepared({ ...prepared, state: 'network-attempted' }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await journal.markNetworkAttempted(prepared.operationId);
    await journal.commit(
      prepared.operationId,
      { vaultId: prepared.request.vault.id, deviceId: prepared.request.device.id },
      prepared.profile,
      NOW,
    );
    await expect(
      journal.commit(
        prepared.operationId,
        { vaultId: prepared.request.vault.id, deviceId: prepared.request.device.id },
        prepared.profile,
        '2026-08-10T00:00:01.000Z',
      ),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      journal.commit(
        prepared.operationId,
        { vaultId: prepared.request.vault.id, deviceId: prepared.request.device.id },
        { ...prepared.profile, serverUrl: 'https://other.example/' },
        NOW,
      ),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  }, 30_000);

  it('recovers a dead child lease before reopening durable journal state', async () => {
    const fixture = journalPath('initialization.sqlite');
    let journal = await openInitialization(fixture.path);
    const prepared = initializationRecord('operation.init.child-crash.0001');
    await journal.createPrepared(prepared);
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);

    const child = await startLeaseChild(`${fixture.path}.writer.lock`, 'crash');
    await expectChildExit(child, 0);

    journal = await openInitialization(fixture.path);
    await expect(journal.load(prepared.operationId)).resolves.toEqual(prepared);
  }, 30_000);

  it('rejects a competing live child and never mistakes it for a stale owner', async () => {
    const fixture = journalPath('initialization.sqlite');
    const child = await startLeaseChild(`${fixture.path}.writer.lock`, 'live');
    try {
      await expect(
        openSqliteInitializationJournal({ path: fixture.path }),
      ).rejects.toBeInstanceOf(SyncLocalStateError);
    } finally {
      child.kill();
      await waitForChildExit(child);
    }

    const journal = await openInitialization(fixture.path);
    await expect(journal.listOperationIds()).resolves.toEqual([]);
  }, 30_000);
});

describe('SqliteJoinLifecycleJournal', () => {
  it('rejects invalid adapter composition and out-of-order join transitions', async () => {
    const fixture = journalPath('join.sqlite');
    await expect(
      openSqliteJoinLifecycleJournal({
        path: fixture.path,
        protectedSecrets: {} as NativeJoinJournalSecrets,
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);

    const native = new TestNativeEntries();
    const journal = await openJoin(fixture.path, native);
    const prepared = joinRecord('operation.join.cas-errors.0001');
    await journal.createPrepared(prepared);
    await expect(
      journal.markCompletionAttempted(prepared.operationId),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      journal.commit(
        prepared.operationId,
        prepared.expectedVaultId,
        prepared.deviceId,
        NOW,
      ),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    const incompatible = joinPreparedJournalRecordSchema.parse({
      ...prepared,
      inviteBearer: bearer('DIFFERENT_INVITE'),
    });
    await expect(journal.createPrepared(incompatible)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await journal.markRedeemAttempted(prepared.operationId);
    await expect(journal.deletePrepared(prepared.operationId)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
  }, 30_000);

  it('persists only a public mirror and recovers active bytes from native storage', async () => {
    const fixture = journalPath('join.sqlite');
    const native = new TestNativeEntries();
    let journal = await openJoin(fixture.path, native);
    const prepared = joinRecord('operation.join.sqlite.0001');
    await journal.createPrepared(prepared);
    await journal.createPrepared(prepared);
    prepared.inviteBearer.fill(99);
    prepared.enrollmentSuccessor.fill(99);
    prepared.sessionSuccessor.fill(99);

    let loaded = await journal.load(
      lifecycleOperationIdSchema.parse('operation.join.sqlite.0001'),
    );
    expect(loaded).toMatchObject({ state: 'prepared' });
    if (loaded === null || loaded.state === 'committed') throw new Error('fixture');
    expect(loaded.inviteBearer).toEqual(bearer('INVITE_CANARY'));
    wipe(loaded);

    await journal.markRedeemAttempted(
      lifecycleOperationIdSchema.parse('operation.join.sqlite.0001'),
    );
    await journal.markRedeemAttempted(
      lifecycleOperationIdSchema.parse('operation.join.sqlite.0001'),
    );
    await journal.markCompletionAttempted(
      lifecycleOperationIdSchema.parse('operation.join.sqlite.0001'),
    );
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);
    journal = await openJoin(fixture.path, native);
    loaded = await journal.load(
      lifecycleOperationIdSchema.parse('operation.join.sqlite.0001'),
    );
    expect(loaded).toMatchObject({ state: 'completion-attempted' });
    wipe(loaded?.state === 'committed' ? undefined : (loaded ?? undefined));

    const disk = await sqliteBytes(fixture.path);
    expect(disk).not.toContain('INVITE_CANARY');
    expect(disk).not.toContain('ENROLL_CANARY');
    expect(disk).not.toContain('SESSION_CANARY');
  });

  it('commits by deleting native bearer bytes and retaining a non-secret receipt', async () => {
    const { path } = journalPath('join.sqlite');
    const native = new TestNativeEntries();
    const journal = await openJoin(path, native);
    const prepared = joinRecord('operation.join.sqlite.0001');
    await journal.createPrepared(prepared);
    await journal.markRedeemAttempted(prepared.operationId);
    await journal.markCompletionAttempted(prepared.operationId);
    await journal.commit(
      prepared.operationId,
      prepared.expectedVaultId,
      prepared.deviceId,
      NOW,
    );
    await journal.commit(
      prepared.operationId,
      prepared.expectedVaultId,
      prepared.deviceId,
      NOW,
    );

    expect(native.values.size).toBe(0);
    expect(await journal.load(prepared.operationId)).toEqual({
      version: 1,
      kind: 'vault-join',
      operationId: prepared.operationId,
      state: 'committed',
      vaultId: prepared.expectedVaultId,
      deviceId: prepared.deviceId,
      committedAt: NOW,
    });
    await expect(journal.deletePrepared(prepared.operationId)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
  });

  it('rejects conflicting committed retries and a missing transition secret', async () => {
    const committedFixture = journalPath('committed-conflict.sqlite');
    const committedNative = new TestNativeEntries();
    const committedJournal = await openJoin(committedFixture.path, committedNative);
    const committed = joinRecord('operation.join.committed-conflict.0001');
    await committedJournal.createPrepared(committed);
    await committedJournal.markRedeemAttempted(committed.operationId);
    await committedJournal.markCompletionAttempted(committed.operationId);
    await committedJournal.commit(
      committed.operationId,
      committed.expectedVaultId,
      committed.deviceId,
      NOW,
    );

    await expect(
      committedJournal.commit(
        committed.operationId,
        committed.expectedVaultId,
        committed.deviceId,
        '2026-08-10T00:00:00.001Z',
      ),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(committedJournal.createPrepared(committed)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );

    const missingFixture = journalPath('missing-transition-secret.sqlite');
    const missingNative = new TestNativeEntries();
    const missingJournal = await openJoin(missingFixture.path, missingNative);
    const missing = joinRecord('operation.join.missing-transition-secret.0001');
    await missingJournal.createPrepared(missing);
    missingNative.values.clear();
    await expect(
      missingJournal.markRedeemAttempted(missing.operationId),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  });

  it('rejects cross-operation session reservation collisions', async () => {
    const { path } = journalPath('join.sqlite');
    const native = new TestNativeEntries();
    const journal = await openJoin(path, native);
    const first = joinRecord('operation.join.sqlite.0001');
    const collision = joinPreparedJournalRecordSchema.parse({
      ...joinRecord('operation.join.sqlite.0002'),
      expectedVaultId: first.expectedVaultId,
      deviceId: first.deviceId,
      completionRequest: first.completionRequest,
      sessionLocator: first.sessionLocator,
    });
    await journal.createPrepared(first);
    await expect(journal.createPrepared(collision)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    expect(native.values.size).toBe(1);
  }, 30_000);

  it('reconciles reservation failures before and after the native write', async () => {
    const beforeFixture = journalPath('before.sqlite');
    const beforeNative = new TestNativeEntries();
    let journal = await openJoin(beforeFixture.path, beforeNative);
    beforeNative.setFailure = 'before';
    await expect(
      journal.createPrepared(joinRecord('operation.join.before.0001')),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);
    journal = await openJoin(beforeFixture.path, beforeNative);
    await expect(journal.listOperationIds()).resolves.toEqual([]);

    const afterFixture = journalPath('after.sqlite');
    const afterNative = new TestNativeEntries();
    journal = await openJoin(afterFixture.path, afterNative);
    afterNative.setFailure = 'after';
    const after = joinRecord('operation.join.after.0001');
    await expect(journal.createPrepared(after)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);
    journal = await openJoin(afterFixture.path, afterNative);
    const loaded = await journal.load(after.operationId);
    expect(loaded).toMatchObject({ state: 'prepared' });
    wipe(loaded?.state === 'committed' ? undefined : (loaded ?? undefined));
  }, 30_000);

  it('reconciles transition, commit, and deletion failures after native mutation', async () => {
    const transitionFixture = journalPath('transition.sqlite');
    const transitionNative = new TestNativeEntries();
    let journal = await openJoin(transitionFixture.path, transitionNative);
    const transition = joinRecord('operation.join.transition.0001');
    await journal.createPrepared(transition);
    transitionNative.setFailure = 'after';
    await expect(
      journal.markRedeemAttempted(transition.operationId),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);
    journal = await openJoin(transitionFixture.path, transitionNative);
    const loaded = await journal.load(transition.operationId);
    expect(loaded).toMatchObject({ state: 'redeem-attempted' });
    wipe(loaded?.state === 'committed' ? undefined : (loaded ?? undefined));

    await journal.markCompletionAttempted(transition.operationId);
    transitionNative.deleteFailure = 'after';
    await expect(
      journal.commit(
        transition.operationId,
        transition.expectedVaultId,
        transition.deviceId,
        NOW,
      ),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);
    journal = await openJoin(transitionFixture.path, transitionNative);
    expect(await journal.load(transition.operationId)).toMatchObject({
      state: 'committed',
    });

    const deleteFixture = journalPath('delete.sqlite');
    const deleteNative = new TestNativeEntries();
    journal = await openJoin(deleteFixture.path, deleteNative);
    const deletion = joinRecord('operation.join.delete.0001');
    await journal.createPrepared(deletion);
    deleteNative.deleteFailure = 'after';
    await expect(journal.deletePrepared(deletion.operationId)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);
    journal = await openJoin(deleteFixture.path, deleteNative);
    await expect(journal.load(deletion.operationId)).resolves.toBeNull();
  }, 60_000);

  it('retries transition, commit, and deletion after pre-mutation native failures', async () => {
    const transitionFixture = journalPath('transition-before.sqlite');
    const transitionNative = new TestNativeEntries();
    let journal = await openJoin(transitionFixture.path, transitionNative);
    const transition = joinRecord('operation.join.transition-before.0001');
    await journal.createPrepared(transition);
    transitionNative.setFailure = 'before';
    await expect(
      journal.markRedeemAttempted(transition.operationId),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);
    journal = await openJoin(transitionFixture.path, transitionNative);
    const redeemed = await journal.load(transition.operationId);
    expect(redeemed).toMatchObject({ state: 'redeem-attempted' });
    wipe(redeemed?.state === 'committed' ? undefined : (redeemed ?? undefined));

    await journal.markCompletionAttempted(transition.operationId);
    transitionNative.deleteFailure = 'before';
    await expect(
      journal.commit(
        transition.operationId,
        transition.expectedVaultId,
        transition.deviceId,
        NOW,
      ),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);
    journal = await openJoin(transitionFixture.path, transitionNative);
    await expect(journal.load(transition.operationId)).resolves.toMatchObject({
      state: 'committed',
    });

    const deletionFixture = journalPath('delete-before.sqlite');
    const deletionNative = new TestNativeEntries();
    journal = await openJoin(deletionFixture.path, deletionNative);
    const deletion = joinRecord('operation.join.delete-before.0001');
    await journal.createPrepared(deletion);
    deletionNative.deleteFailure = 'before';
    await expect(journal.deletePrepared(deletion.operationId)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);
    journal = await openJoin(deletionFixture.path, deletionNative);
    await expect(journal.load(deletion.operationId)).resolves.toBeNull();
  }, 60_000);

  it('rejects corrupted mirrors and enforces the operation capacity', async () => {
    const capacity = journalPath('capacity.sqlite');
    const native = new TestNativeEntries();
    const journal = await openJoin(capacity.path, native, { maxOperations: 1 });
    await journal.createPrepared(joinRecord('operation.join.capacity.0001'));
    await expect(
      journal.createPrepared(
        joinRecord('operation.join.capacity.0002', 'vault.join.2', 'device.join.2'),
      ),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await journal.close();
    openJournals.splice(openJournals.indexOf(journal), 1);

    const corrupt = new DatabaseSync(capacity.path);
    corrupt
      .prepare(`UPDATE join_journal SET expected_vault_id = 'vault.crossed'`)
      .run();
    corrupt.close();
    await expect(
      openSqliteJoinLifecycleJournal({
        path: capacity.path,
        maxOperations: 1,
        protectedSecrets: new NativeJoinJournalSecrets(native.createEntry),
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  });
});

async function openInitialization(
  path: string,
  options: Readonly<{ maxOperations?: number }> = {},
): Promise<SqliteInitializationJournal> {
  const journal = await openSqliteInitializationJournal({ path, ...options });
  openJournals.push(journal);
  return journal;
}

async function openJoin(
  path: string,
  native: TestNativeEntries,
  options: Readonly<{ maxOperations?: number }> = {},
): Promise<SqliteJoinLifecycleJournal> {
  const journal = await openSqliteJoinLifecycleJournal({
    path,
    ...options,
    protectedSecrets: new NativeJoinJournalSecrets(native.createEntry),
  });
  openJournals.push(journal);
  return journal;
}

function journalPath(filename: string): Readonly<{ root: string; path: string }> {
  const root = join(
    TEST_TMPDIR,
    `kavrix-lifecycle-${randomUUID().replaceAll('-', '')}`,
  );
  roots.push(root);
  return { root, path: join(root, filename) };
}

function initializationRecord(
  operationIdInput: string,
  vaultId = 'vault.init.1',
  deviceId = 'device.init.1',
  slotId = 'slot.init.1',
): InitializationActiveJournalRecord {
  const operationId = lifecycleOperationIdSchema.parse(operationIdInput);
  const envelope = (
    entityType: 'wrapped-root-key' | 'vault-preferences',
    entityId: string,
    purpose: 'vrk-slot' | 'vault-preferences',
  ): ReturnType<typeof aeadEnvelopeSchema.parse> =>
    aeadEnvelopeSchema.parse({
      version: 1,
      algorithm: 'xchacha20-poly1305-ietf',
      nonce: 'A'.repeat(32),
      ciphertext: 'A'.repeat(43),
      authenticationTag: 'A'.repeat(22),
      aad: {
        version: 1,
        schemaVersion: 1,
        keyVersion: 1,
        vaultId,
        entityType,
        entityId,
        purpose,
      },
      keyVersion: 1,
    });
  const parsed = initializationJournalRecordSchema.parse({
    version: 1,
    kind: 'vault-initialization',
    operationId,
    state: 'prepared',
    request: {
      vault: {
        id: vaultId,
        schemaVersion: 1,
        cryptographicVersion: 1,
        keySlots: [
          {
            slotVersion: 1,
            id: slotId,
            type: 'device-key',
            state: 'active',
            keyVersion: 1,
            derivation: {
              algorithm: 'hkdf-sha256',
              version: 1,
              salt: 'A'.repeat(43),
              context: 'credvault/v1/device-key-wrap',
              outputLength: 32,
              provider: 'test-native-provider',
            },
            wrappedRootKey: envelope('wrapped-root-key', slotId, 'vrk-slot'),
            createdAt: NOW,
            deviceId,
          },
        ],
        currentKeyVersion: 1,
        revision: 0,
        encryptedPreferences: envelope(
          'vault-preferences',
          vaultId,
          'vault-preferences',
        ),
        createdAt: NOW,
        updatedAt: NOW,
      },
      device: { id: deviceId, schemaVersion: 1 },
    },
    deviceLocator: { version: 1, vaultId, deviceId, keySlotId: slotId },
    sessionLocator: {
      version: 1,
      vaultId,
      deviceId,
      purpose: 'api-session',
    },
    profile: {
      version: 1,
      serverUrl: 'https://vault.example/',
      vaultId,
      deviceId,
      deviceLocator: { version: 1, vaultId, deviceId, keySlotId: slotId },
      sessionLocator: {
        version: 1,
        vaultId,
        deviceId,
        purpose: 'api-session',
      },
    },
  });
  if (parsed.state === 'committed') throw new Error('Invalid test fixture');
  return parsed;
}

function joinRecord(
  operationIdInput: string,
  vaultId = 'vault.join.1',
  deviceId = 'device.join.1',
): JoinPreparedJournalRecord {
  return joinPreparedJournalRecordSchema.parse({
    version: 1,
    kind: 'vault-join',
    operationId: lifecycleOperationIdSchema.parse(operationIdInput),
    state: 'prepared',
    expectedVaultId: vaultId,
    deviceId,
    completionRequest: { vaultId, deviceId, schemaVersion: 1 },
    sessionLocator: {
      version: 1,
      vaultId,
      deviceId,
      purpose: 'api-session',
    },
    inviteBearer: bearer('INVITE_CANARY'),
    enrollmentSuccessor: bearer('ENROLL_CANARY'),
    sessionSuccessor: bearer('SESSION_CANARY'),
  });
}

function bearer(label: string): Uint8Array {
  const result = new Uint8Array(32);
  result.set(new TextEncoder().encode(label));
  return result;
}

function wipe(
  record:
    | {
        inviteBearer: Uint8Array;
        enrollmentSuccessor: Uint8Array;
        sessionSuccessor: Uint8Array;
      }
    | undefined,
): void {
  record?.inviteBearer.fill(0);
  record?.enrollmentSuccessor.fill(0);
  record?.sessionSuccessor.fill(0);
}

async function sqliteBytes(path: string): Promise<string> {
  const buffers: Buffer[] = [];
  for (const candidate of [path, `${path}-wal`, `${path}-shm`, `${path}-journal`]) {
    try {
      buffers.push(await readFile(candidate));
    } catch (error) {
      if (
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        error.code === 'ENOENT'
      ) {
        continue;
      }
      throw error;
    }
  }
  try {
    return Buffer.concat(buffers).toString('latin1');
  } finally {
    for (const buffer of buffers) buffer.fill(0);
  }
}

async function startLeaseChild(
  leasePath: string,
  mode: 'crash' | 'live',
): Promise<ChildProcess> {
  const readyPath = `${leasePath}.${randomUUID()}.ready`;
  const child = spawn(
    process.execPath,
    [
      '--input-type=module',
      '--eval',
      LEASE_CHILD_SOURCE,
      LEASE_CHILD_MODULE,
      leasePath,
      readyPath,
      mode,
    ],
    {
      shell: false,
      windowsHide: true,
      stdio: 'ignore',
      env: process.platform === 'win32' ? { SystemRoot: 'C:\\Windows' } : {},
    },
  );
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try {
      await readFile(readyPath);
      return child;
    } catch (error) {
      if (!(
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        error.code === 'ENOENT'
      )) {
        throw error;
      }
    }
    if (child.exitCode !== null) {
      throw new Error(`Lease child exited before readiness: ${String(child.exitCode)}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  child.kill();
  throw new Error('Lease child did not become ready');
}

function expectChildExit(
  child: ChildProcess,
  expectedCode: number | null,
): Promise<void> {
  if (child.exitCode !== null) {
    expect(child.exitCode).toBe(expectedCode);
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code) => {
      try {
        expect(code).toBe(expectedCode);
        resolve();
      } catch (error) {
        reject(error instanceof Error ? error : new Error('Child assertion failed'));
      }
    });
  });
}

function waitForChildExit(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null) return Promise.resolve();
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', () => {
      resolve();
    });
  });
}
