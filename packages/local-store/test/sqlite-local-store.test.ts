import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { chmod, link, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  changeRecordSchema,
  encryptedGroupRecordSchema,
  syncCursorSchema,
  type EncryptedGroupRecord,
} from '@kavrix/schemas';
import { SyncLocalStateError, type ApplyPullPageInput } from '@kavrix/sync';
import { afterEach, describe, expect, it } from 'vitest';

import { openSqliteSyncLocalStore, type SqliteSyncLocalStore } from '../src/index.js';
import {
  groupRecord,
  mutation,
  otherVaultId,
  plaintextCanary,
  pullPage,
  vaultId,
} from './fixtures.js';

const WINDOWS_POWERSHELL =
  'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
const roots: string[] = [];
const stores: SqliteSyncLocalStore[] = [];

afterEach(async () => {
  for (const store of stores.splice(0)) {
    try {
      store.close();
    } catch {
      // The test may deliberately force the adapter closed on a security failure.
    }
  }
  for (const root of roots.splice(0)) {
    if (
      dirname(root) !== tmpdir() ||
      !root.startsWith(join(tmpdir(), 'kavrix-local-store-test-'))
    ) {
      throw new Error('Refusing to remove an unverified test directory');
    }
    await rm(root, { recursive: true, force: true });
  }
});

describe('SqliteSyncLocalStore', () => {
  it('atomically applies and idempotently replays canonical opaque pull pages', async () => {
    const { path, store } = await createStore();
    const page = pullPage([groupRecord()]);

    await store.applyPullPage(page);
    await expect(store.applyPullPage(page)).resolves.toBeUndefined();

    expect(await store.loadCursor(vaultId)).toEqual(page.cursor);
    expect(await store.loadOpaqueRecord(vaultId, 'group', 'group.1')).toEqual(
      page.changes[0]?.record,
    );
    expect(await store.listOpaqueRecords(vaultId)).toEqual([page.changes[0]?.record]);
    store.close();

    const bytes = await readFile(path);
    expect(bytes.includes(Buffer.from(plaintextCanary))).toBe(false);
    bytes.fill(0);
  });

  it('applies monotonic updates and deletes without accepting record rollback', async () => {
    const { store } = await createStore();
    await store.applyPullPage(groupChangePage(1, groupRecord()));
    await expect(
      store.applyPullPage(groupChangePage(2, groupRecord())),
    ).resolves.toBeUndefined();

    const conflicting = encryptedGroupRecordSchema.parse({
      ...groupRecord(),
      templateVersion: 2,
    });
    await expect(
      store.applyPullPage(groupChangePage(3, conflicting)),
    ).rejects.toBeInstanceOf(SyncLocalStateError);

    const updated = groupRecord('group.1', 1);
    await store.applyPullPage(groupChangePage(3, updated));
    await expect(
      store.applyPullPage(groupChangePage(4, groupRecord())),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await store.applyPullPage(groupChangePage(4, null, 2));
    expect(await store.loadOpaqueRecord(vaultId, 'group', 'group.1')).toBeNull();
  });

  it('rejects cursor gaps, same-sequence changes, and empty advancing pages', async () => {
    const { store } = await createStore();
    await store.applyPullPage(groupChangePage(1, groupRecord()));
    await store.applyPullPage({
      vaultId,
      changes: [],
      cursor: syncCursorSchema.parse({
        vaultId,
        serverSequence: 1,
        highestSeenVaultRevision: 2,
      }),
    });

    await expect(
      store.applyPullPage(groupChangePage(1, groupRecord('group.2'))),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      store.applyPullPage({
        vaultId,
        changes: [],
        cursor: syncCursorSchema.parse({
          vaultId,
          serverSequence: 2,
          highestSeenVaultRevision: 2,
        }),
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      store.applyPullPage(groupChangePage(3, groupRecord('group.2'))),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      store.applyPullPage({
        ...groupChangePage(2, groupRecord('group.2')),
        cursor: syncCursorSchema.parse({
          vaultId,
          serverSequence: 3,
          highestSeenVaultRevision: 3,
        }),
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  });

  it('reopens committed WAL state without relying on graceful close', async () => {
    const fixture = await createStore();
    const pending = mutation('mutation-key-0001', groupRecord('group.2'));
    const batch = {
      vaultId,
      batchIdempotencyKey: 'batch-key-0000001',
      mutationIdempotencyKeys: [pending.idempotencyKey],
    } as const;
    await fixture.store.applyPullPage(pullPage([groupRecord()]));
    await fixture.store.enqueueMutation(vaultId, pending);
    await fixture.store.saveActivePushBatch(batch);

    const reopened = await openSqliteSyncLocalStore({ path: fixture.path });
    stores.push(reopened);
    expect(await reopened.loadCursor(vaultId)).toEqual(
      syncCursorSchema.parse({
        vaultId,
        serverSequence: 1,
        highestSeenVaultRevision: 1,
      }),
    );
    expect(await reopened.listPendingMutations(vaultId)).toEqual([pending]);
    expect(await reopened.loadActivePushBatch(vaultId)).toEqual(batch);
  });

  it('rolls back records and cursor when a later statement in the page fails', async () => {
    const fixture = await createStore();
    const raw = new DatabaseSync(fixture.path);
    raw.exec(`
      CREATE TRIGGER abort_second_record
      BEFORE INSERT ON opaque_records
      WHEN NEW.entity_id = 'group.2'
      BEGIN
        SELECT RAISE(ABORT, 'hidden-trigger-canary');
      END;
    `);
    raw.close();

    const operation = fixture.store.applyPullPage(
      pullPage([groupRecord('group.1'), groupRecord('group.2')]),
    );
    await expect(operation).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(operation).rejects.not.toThrow(/hidden-trigger-canary/u);
    expect(await fixture.store.loadCursor(vaultId)).toBeNull();
    expect(
      await fixture.store.loadOpaqueRecord(vaultId, 'group', 'group.1'),
    ).toBeNull();
    fixture.store.close();
    await expect(
      openSqliteSyncLocalStore({ path: fixture.path }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  });

  it('persists, resumes, acknowledges, and idempotently completes active batches', async () => {
    const fixture = await createStore();
    const first = mutation('mutation-key-0001');
    const second = mutation('mutation-key-0002', groupRecord('group.2'));
    const batch = {
      vaultId,
      batchIdempotencyKey: 'batch-key-0000001',
      mutationIdempotencyKeys: [first.idempotencyKey, second.idempotencyKey],
    } as const;
    await fixture.store.enqueueMutation(vaultId, first);
    await fixture.store.enqueueMutation(vaultId, second);
    await fixture.store.saveActivePushBatch(batch);
    await expect(fixture.store.saveActivePushBatch(batch)).resolves.toBeUndefined();
    fixture.store.close();

    const reopened = await openSqliteSyncLocalStore({ path: fixture.path });
    stores.push(reopened);
    expect(await reopened.loadActivePushBatch(vaultId)).toEqual(batch);
    const completion = {
      vaultId,
      batchIdempotencyKey: batch.batchIdempotencyKey,
      acknowledgedIdempotencyKeys: [first.idempotencyKey],
    } as const;
    await reopened.completePushBatch(completion);
    await expect(reopened.completePushBatch(completion)).resolves.toBeUndefined();
    expect(await reopened.loadActivePushBatch(vaultId)).toBeNull();
    expect(await reopened.listPendingMutations(vaultId)).toEqual([second]);
    await expect(
      reopened.completePushBatch({
        ...completion,
        acknowledgedIdempotencyKeys: [second.idempotencyKey],
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(reopened.saveActivePushBatch(batch)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
  });

  it('rejects active-batch collisions and invalid acknowledgements', async () => {
    const { store } = await createStore();
    const first = mutation('mutation-key-0001');
    const second = mutation('mutation-key-0002', groupRecord('group.2'));
    await expect(store.enqueueMutation(vaultId, first)).resolves.toBe('queued');
    await expect(store.enqueueMutation(vaultId, first)).resolves.toBe('duplicate');
    await store.enqueueMutation(vaultId, second);
    const batch = {
      vaultId,
      batchIdempotencyKey: 'batch-key-0000001',
      mutationIdempotencyKeys: [first.idempotencyKey],
    } as const;
    await store.saveActivePushBatch(batch);

    await expect(
      store.saveActivePushBatch({
        ...batch,
        batchIdempotencyKey: 'batch-key-0000002',
        mutationIdempotencyKeys: [second.idempotencyKey],
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      store.completePushBatch({
        vaultId,
        batchIdempotencyKey: batch.batchIdempotencyKey,
        acknowledgedIdempotencyKeys: [second.idempotencyKey],
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      store.completePushBatch({
        vaultId,
        batchIdempotencyKey: 'batch-key-0000002',
        acknowledgedIdempotencyKeys: [],
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  });

  it('rejects cross-vault data and global idempotency collisions', async () => {
    const { store } = await createStore();
    const first = mutation('mutation-key-0001');
    await store.enqueueMutation(vaultId, first);
    await expect(store.enqueueMutation(otherVaultId, first)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await expect(
      store.enqueueMutation(
        otherVaultId,
        mutation(first.idempotencyKey, groupRecord('group.2', 0, otherVaultId)),
      ),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      store.applyPullPage({
        ...pullPage([groupRecord()]),
        vaultId: otherVaultId,
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  });

  it('enforces row limits transactionally', async () => {
    const fixture = await createStore({ maxRecords: 1, maxPendingMutations: 1 });
    await fixture.store.enqueueMutation(vaultId, mutation('mutation-key-0001'));
    await expect(
      fixture.store.enqueueMutation(
        otherVaultId,
        mutation('mutation-key-0002', groupRecord('group.2', 0, otherVaultId)),
      ),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(await fixture.store.listPendingMutations(vaultId)).toHaveLength(1);

    await expect(
      fixture.store.applyPullPage(
        pullPage([groupRecord('group.1'), groupRecord('group.2')]),
      ),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    expect(await fixture.store.loadCursor(vaultId)).toBeNull();
    expect(await fixture.store.listOpaqueRecords(vaultId)).toEqual([]);
  });

  it('rejects malformed persisted JSON and exact-shape violations', async () => {
    const fixture = await createStore();
    await fixture.store.applyPullPage(pullPage([groupRecord()]));
    fixture.store.close();
    const raw = new DatabaseSync(fixture.path);
    raw
      .prepare(`UPDATE sync_cursors SET cursor_json = ? WHERE vault_id = ?`)
      .run('{"vaultId":"vault.1"}', vaultId);
    raw.close();

    const reopened = await openSqliteSyncLocalStore({ path: fixture.path });
    stores.push(reopened);
    await expect(reopened.loadCursor(vaultId)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await expect(
      reopened.applyPullPage({
        ...pullPage([]),
        unexpected: true,
      } as never),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  });

  it('parses every persisted row again and rejects cross-table corruption', async () => {
    const fixture = await createStore();
    const pending = mutation('mutation-key-0001', groupRecord('group.2'));
    await fixture.store.applyPullPage(groupChangePage(1, groupRecord()));
    await fixture.store.enqueueMutation(vaultId, pending);

    const raw = new DatabaseSync(fixture.path);
    raw.exec(`UPDATE opaque_records SET revision = revision + 1`);
    await expect(fixture.store.listOpaqueRecords(vaultId)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    raw.exec(`UPDATE opaque_records SET revision = revision - 1`);
    raw.exec(`UPDATE pending_mutations SET serialized_bytes = serialized_bytes + 1`);
    await expect(fixture.store.listPendingMutations(vaultId)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    raw.exec(`UPDATE pending_mutations SET serialized_bytes = serialized_bytes - 1`);
    raw.close();

    const batch = {
      vaultId,
      batchIdempotencyKey: 'batch-key-0000001',
      mutationIdempotencyKeys: [pending.idempotencyKey],
    } as const;
    await fixture.store.saveActivePushBatch(batch);
    const deletePending = new DatabaseSync(fixture.path);
    deletePending.exec(`DELETE FROM pending_mutations`);
    deletePending.close();
    await expect(fixture.store.loadActivePushBatch(vaultId)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
  });

  it('rejects invalid options and malformed public inputs generically', async () => {
    const root = testRoot();
    const path = join(root, 'state.sqlite');
    for (const options of [
      { path, unexpected: true },
      { path, maxVaults: 0 },
      { path, maxRecordBytes: 1_023 },
      { path, maxPendingBytes: 1_023 },
      { path, maxSerializedRowBytes: 2_048, maxRecordBytes: 1_024 },
    ]) {
      await expect(openSqliteSyncLocalStore(options as never)).rejects.toBeInstanceOf(
        SyncLocalStateError,
      );
    }
    await expect(
      openSqliteSyncLocalStore({ path: 'relative.sqlite' }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);

    const { store } = await createStore();
    await expect(store.loadCursor('' as never)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await expect(store.listPendingMutations('' as never)).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await expect(
      store.loadOpaqueRecord(vaultId, 'invalid' as never, 'group.1'),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(store.loadOpaqueRecord(vaultId, 'group', '')).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
    await expect(
      store.enqueueMutation(vaultId, mutation('mutation-key-0001', groupRecord(), 2)),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      store.saveActivePushBatch({
        vaultId,
        batchIdempotencyKey: 'short',
        mutationIdempotencyKeys: [],
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
    await expect(
      store.completePushBatch({
        vaultId,
        batchIdempotencyKey: 'batch-key-0000001',
        acknowledgedIdempotencyKeys: ['duplicate-key-0001', 'duplicate-key-0001'],
      }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  });

  it('rejects same-name schemas with weakened constraints', async () => {
    const fixture = await createStore();
    fixture.store.close();
    const raw = new DatabaseSync(fixture.path);
    raw.exec(`
      DROP TABLE opaque_records;
      CREATE TABLE opaque_records (
        vault_id TEXT,
        entity_type TEXT,
        entity_id TEXT,
        revision INTEGER,
        record_json TEXT,
        serialized_bytes INTEGER
      );
    `);
    raw.close();

    await expect(
      openSqliteSyncLocalStore({ path: fixture.path }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  });

  it('rejects hardlinked database files', async () => {
    const fixture = await createStore();
    fixture.store.close();
    const linkedPath = join(dirname(fixture.path), 'linked.sqlite');
    await link(fixture.path, linkedPath);

    await expect(openSqliteSyncLocalStore({ path: linkedPath })).rejects.toBeInstanceOf(
      SyncLocalStateError,
    );
  });

  it('rejects unsafe parent permissions or DACL inheritance', async () => {
    const root = testRoot();
    await mkdir(root, { recursive: true });
    if (process.platform !== 'win32') await chmod(root, 0o755);

    await expect(
      openSqliteSyncLocalStore({ path: join(root, 'state.sqlite') }),
    ).rejects.toBeInstanceOf(SyncLocalStateError);
  });

  for (const suffix of [null, '-wal', '-shm', '-journal'] as const) {
    it.runIf(process.platform === 'win32')(
      `rejects an explicit broad grant on an existing ${suffix ?? 'database'} leaf`,
      async () => {
        const fixture = await createStore();
        fixture.store.close();
        const unsafePath = suffix === null ? fixture.path : `${fixture.path}${suffix}`;
        if (suffix !== null) await writeFile(unsafePath, new Uint8Array(32));
        grantEveryone(unsafePath);
        await expect(
          openSqliteSyncLocalStore({ path: fixture.path }),
        ).rejects.toBeInstanceOf(SyncLocalStateError);
      },
    );
  }

  it.runIf(process.platform === 'win32')(
    'protects live DB/WAL/SHM leaves',
    async () => {
      const fixture = await createStore();
      await fixture.store.applyPullPage(pullPage([groupRecord()]));
      for (const path of [fixture.path, `${fixture.path}-wal`, `${fixture.path}-shm`]) {
        expectCurrentUserOnly(path);
      }
    },
  );

  it.runIf(process.platform === 'win32')(
    'fails closed when the live database gains a broad grant',
    async () => {
      const fixture = await createStore();
      await fixture.store.applyPullPage(pullPage([groupRecord()]));
      grantEveryone(fixture.path);
      await expect(
        fixture.store.enqueueMutation(
          vaultId,
          mutation('mutation-key-0001', groupRecord('group.2')),
        ),
      ).rejects.toBeInstanceOf(SyncLocalStateError);
      await expect(fixture.store.loadCursor(vaultId)).rejects.toBeInstanceOf(
        SyncLocalStateError,
      );
    },
  );

  it.each(['-wal', '-shm'] as const)(
    'fails closed when live %s gains a broad grant',
    async (suffix) => {
      if (process.platform !== 'win32') return;
      const fixture = await createStore();
      await fixture.store.applyPullPage(pullPage([groupRecord()]));
      grantEveryone(`${fixture.path}${suffix}`);
      await expect(
        fixture.store.enqueueMutation(
          vaultId,
          mutation('mutation-key-0001', groupRecord('group.2')),
        ),
      ).rejects.toBeInstanceOf(SyncLocalStateError);
      await expect(fixture.store.loadCursor(vaultId)).rejects.toBeInstanceOf(
        SyncLocalStateError,
      );
    },
  );

  it.runIf(process.platform === 'win32')(
    'closes if a live side file is hardlinked',
    async () => {
      const fixture = await createStore();
      await fixture.store.applyPullPage(pullPage([groupRecord()]));
      await link(`${fixture.path}-wal`, `${fixture.path}-wal-linked`);
      await expect(
        fixture.store.enqueueMutation(
          vaultId,
          mutation('mutation-key-0001', groupRecord('group.2')),
        ),
      ).rejects.toBeInstanceOf(SyncLocalStateError);
      await expect(fixture.store.loadCursor(vaultId)).rejects.toBeInstanceOf(
        SyncLocalStateError,
      );
    },
  );

  it('fails closed after explicit close', async () => {
    const { store } = await createStore();
    store.close();
    store.close();
    await expect(store.loadCursor(vaultId)).rejects.toBeInstanceOf(SyncLocalStateError);
  });
});

function groupChangePage(
  serverSequence: number,
  record: EncryptedGroupRecord | null,
  deletedRevision = record?.recordRevision ?? 0,
): ApplyPullPageInput {
  const identity = record?.id ?? 'group.1';
  const canonicalRecord = record ?? groupRecord(identity, deletedRevision);
  const baseChange = pullPage([canonicalRecord]).changes[0]?.change;
  if (baseChange === undefined) throw new Error('Fixture construction failed');
  return {
    vaultId,
    changes: [
      {
        change: changeRecordSchema.parse({
          ...baseChange,
          id: `change.${String(serverSequence)}`,
          serverSequence,
          recordRevision: deletedRevision,
          operation: record === null ? 'purge' : 'upsert',
        }),
        record,
      },
    ],
    cursor: syncCursorSchema.parse({
      vaultId,
      serverSequence,
      highestSeenVaultRevision: serverSequence,
    }),
  };
}

async function createStore(
  limits: Readonly<{
    maxRecords?: number;
    maxPendingMutations?: number;
  }> = {},
): Promise<Readonly<{ path: string; store: SqliteSyncLocalStore }>> {
  const root = testRoot();
  const path = join(root, 'state.sqlite');
  const store = await openSqliteSyncLocalStore({
    path,
    ...limits,
    ...(limits.maxRecords === undefined ? {} : { maxRecordBytes: 1024 * 1024 }),
    ...(limits.maxPendingMutations === undefined
      ? {}
      : { maxPendingBytes: 1024 * 1024 }),
    ...(Object.keys(limits).length === 0 ? {} : { maxSerializedRowBytes: 1024 * 1024 }),
  });
  stores.push(store);
  return { path, store };
}

function testRoot(): string {
  const root = join(
    tmpdir(),
    `kavrix-local-store-test-${randomUUID().replaceAll('-', '')}`,
  );
  roots.push(root);
  return root;
}

function grantEveryone(path: string): void {
  const script = [
    "$ErrorActionPreference='Stop'",
    '$path=[Console]::In.ReadToEnd()',
    '$item=Get-Item -LiteralPath $path -Force',
    "$acl=$item.GetAccessControl('Access,Owner')",
    '$world=New-Object Security.Principal.SecurityIdentifier("S-1-1-0")',
    '$allow=[Security.AccessControl.AccessControlType]::Allow',
    '$full=[Security.AccessControl.FileSystemRights]::FullControl',
    '$rule=New-Object Security.AccessControl.FileSystemAccessRule($world,$full,$allow)',
    '[void]$acl.AddAccessRule($rule)',
    '$acl.SetAccessRuleProtection($true,$true)',
    '$item.SetAccessControl($acl)',
  ].join(';');
  execFileSync(
    WINDOWS_POWERSHELL,
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-Sta', '-Command', script],
    {
      env: { SystemRoot: 'C:\\Windows' },
      input: path,
      maxBuffer: 4_096,
      timeout: 5_000,
      windowsHide: true,
    },
  );
}

function expectCurrentUserOnly(path: string): void {
  const script = [
    "$ErrorActionPreference='Stop'",
    '$path=[Console]::In.ReadToEnd()',
    '$item=Get-Item -LiteralPath $path -Force',
    "$acl=$item.GetAccessControl('Access,Owner')",
    '$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User',
    'if(-not $acl.AreAccessRulesProtected){exit 41}',
    'if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value){exit 42}',
    '$rules=$acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])',
    'if($rules.Count -ne 1){exit 43}',
    '$rule=$rules[0]',
    'if($rule.IsInherited){exit 44}',
    'if($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow){exit 45}',
    'if($rule.IdentityReference.Value -ne $sid.Value){exit 46}',
    "[Console]::Out.Write('OK')",
  ].join(';');
  const output = execFileSync(
    WINDOWS_POWERSHELL,
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-Sta', '-Command', script],
    {
      env: { SystemRoot: 'C:\\Windows' },
      input: path,
      maxBuffer: 4_096,
      timeout: 5_000,
      windowsHide: true,
    },
  );
  try {
    expect(output.toString('utf8')).toBe('OK');
  } finally {
    output.fill(0);
  }
}
