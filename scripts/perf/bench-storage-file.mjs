/**
 * Measures the local-file datastore against real filesystems with real ACL
 * enforcement, importing the same sources the CLI compiles from.
 *
 * Fixtures are synthetic and non-secret, created under a temporary directory
 * that is removed when the run finishes. On Windows every protected-path
 * assertion crosses a platform boundary, which is why `openAndClose` dominates
 * this benchmark rather than the JSON work.
 */
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { setWindowsUserOnlyAcl } from '../../packages/key-files/src/windows-acl.ts';
import {
  FileEncryptedDatabaseStore,
  FileLocalVaultStore,
} from '../../packages/storage/src/index.ts';
import {
  databaseDocument,
  databaseRevision,
  makeDatabaseId,
  makeVaultId,
  vaultDocument,
  vaultRevision,
} from '../../packages/storage/test/database-store-fixtures.ts';

import { parseArgs, timeRepeatedly } from './harness.mjs';

const iterations = Number.parseInt(parseArgs(process.argv).iterations ?? '6', 10);
const vaultCounts = (parseArgs(process.argv).vaults ?? '0,8,64').split(',').map(Number);

const databaseId = makeDatabaseId('database-00000000-0000-4000-8000-000000000000');
let counter = 0;

const results = { platform: process.platform, iterations, scenarios: {} };
for (const vaultCount of vaultCounts) {
  results.scenarios[`vaults-${vaultCount}`] = await measureContainer(vaultCount);
}
results.emptyLocalVault = await measureLocalVault();
console.log(JSON.stringify(results, null, 2));

async function measureContainer(vaultCount) {
  const directory = await createWorkspace();
  try {
    const target = join(directory, 'container.json');
    const populated = await FileEncryptedDatabaseStore.open(target);
    try {
      await populated.createDatabase(databaseDocument(databaseId, databaseRevision(0)));
      for (let index = 0; index < vaultCount; index += 1) {
        const expected = databaseRevision(index);
        const database = databaseDocument(databaseId, databaseRevision(index + 1));
        await populated.createVault({
          database,
          expectedDatabaseRevision: expected,
          vault: vaultDocument(
            databaseId,
            makeVaultId(`vault-${String(index).padStart(4, '0')}`),
            database.revision,
            vaultRevision(0),
          ),
        });
      }
    } finally {
      await populated.close();
    }

    const openAndClose = async () => {
      const opened = await FileEncryptedDatabaseStore.open(target);
      await opened.close();
    };

    const listVaults = async () => {
      const opened = await FileEncryptedDatabaseStore.open(target);
      try {
        return await opened.listVaults(databaseId);
      } finally {
        await opened.close();
      }
    };

    /**
     * A full mutation cycle: create a vault, which advances the database
     * revision, then delete it, which advances it again. This is the write path
     * that re-serializes every vault on every publish.
     */
    const createAndDelete = async () => {
      const opened = await FileEncryptedDatabaseStore.open(target);
      try {
        const current = await opened.getDatabase(databaseId);
        if (current === null) throw new Error('benchmark container lost its database');
        const created = databaseDocument(
          databaseId,
          databaseRevision(current.revision + 1),
        );
        const id = makeVaultId(`vault-t-${String(counter++).padStart(6, '0')}`);
        await opened.createVault({
          database: created,
          expectedDatabaseRevision: current.revision,
          vault: vaultDocument(databaseId, id, created.revision, vaultRevision(0)),
        });
        await opened.deleteVault({
          database: databaseDocument(
            databaseId,
            databaseRevision(created.revision + 1),
          ),
          expectedDatabaseRevision: created.revision,
          vaultId: id,
          expectedVaultRevision: vaultRevision(0),
        });
      } finally {
        await opened.close();
      }
    };

    return {
      openAndClose: await timeRepeatedly(openAndClose, { iterations, warmup: 1 }),
      listVaults: await timeRepeatedly(listVaults, { iterations, warmup: 1 }),
      createAndDelete: await timeRepeatedly(createAndDelete, {
        iterations: Math.min(iterations, 4),
        warmup: 1,
      }),
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function measureLocalVault() {
  const directory = await createWorkspace();
  try {
    const target = join(directory, 'local-vault.json');
    return {
      openAndClose: await timeRepeatedly(
        async () => {
          const store = await FileLocalVaultStore.open(target);
          await store.close();
        },
        { iterations, warmup: 1 },
      ),
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

async function createWorkspace() {
  const directory = await mkdtemp(join(tmpdir(), 'kavrix-perf-storage-'));
  if (process.platform === 'win32') await setWindowsUserOnlyAcl(directory);
  return directory;
}
