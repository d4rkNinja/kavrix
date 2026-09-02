import { access, readFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { FileEncryptedDatabaseStore } from '@kavrix/storage';

import { DatabaseSession, DatabaseSessionError } from '../src/database-session.js';
import {
  DatastoreProfileError,
  DatastoreProfileRegistry,
} from '../src/datastore-profiles.js';
import {
  executeGuidedLocalOnboarding,
  GuidedLocalOnboardingError,
  preflightGuidedLocalOnboarding,
} from '../src/local-database-onboarding.js';
import { createSecureTestDirectory as mkdtemp } from '../../../packages/key-files/test/secure-temporary-directory.js';

const OWNER_PASSPHRASE = Buffer.from('owner correct horse battery staple', 'utf8');
const RECOVERY_PASSPHRASE = Buffer.from(
  'recovery correct horse battery staple',
  'utf8',
);
const integrationTimeoutMs = process.platform === 'win32' ? 600_000 : 45_000;
const directories = new Set<string>();

afterEach(async () => {
  vi.restoreAllMocks();
  const owned = [...directories];
  directories.clear();
  await Promise.all(
    owned.map((directory) => rm(directory, { force: true, recursive: true })),
  );
});

describe('guided local database onboarding', () => {
  it(
    'creates one selected vault and verifies recovery without plaintext artifacts',
    async () => {
      const target = await createTarget('complete');

      await preflightGuidedLocalOnboarding(target.destinations);
      const receipt = await executeGuidedLocalOnboarding({
        ...target.destinations,
        databaseLabel: 'database-label-canary',
        ownerPassphrase: OWNER_PASSPHRASE,
        vaultLabel: 'vault-label-canary',
        recoveryPassphrase: RECOVERY_PASSPHRASE,
      });

      expect(receipt).toMatchObject({
        profileId: 'default',
        dataFile: target.dataFile,
        keyFile: target.keyFile,
        recoveryFile: target.recoveryFile,
        recoveryReady: true,
      });
      await expect(access(target.dataFile)).resolves.toBeUndefined();
      await expect(access(target.keyFile)).resolves.toBeUndefined();
      await expect(access(target.recoveryFile)).resolves.toBeUndefined();

      const registry = await DatastoreProfileRegistry.open({
        configDirectory: target.configDirectory,
      });
      const current = await registry.current();
      expect(current).toMatchObject({
        id: 'default',
        datastore: 'file',
        databaseId: receipt.databaseId,
        defaultVaultId: receipt.vaultId,
      });

      const store = await FileEncryptedDatabaseStore.open(target.dataFile);
      const session = await DatabaseSession.open({
        store,
        keyFile: target.keyFile,
        passphrase: OWNER_PASSPHRASE,
        expectedDatabaseId: receipt.databaseId,
      });
      expect(session.listVaults()).toEqual([
        expect.objectContaining({
          id: receipt.vaultId,
          label: 'vault-label-canary',
        }),
      ]);
      expect(session.recoveryStatus()).toEqual({ active: 1, revoked: 0 });
      await session.close();
      await store.close();

      const serialized = (
        await Promise.all([
          readFile(target.dataFile, 'utf8'),
          readFile(target.keyFile, 'utf8'),
          readFile(target.recoveryFile, 'utf8'),
          readFile(join(target.configDirectory, 'datastore-profiles.json'), 'utf8'),
        ])
      ).join('\n');
      expect(serialized).not.toContain('database-label-canary');
      expect(serialized).not.toContain('vault-label-canary');
      expect(serialized).not.toContain(OWNER_PASSPHRASE.toString('utf8'));
      expect(serialized).not.toContain(RECOVERY_PASSPHRASE.toString('utf8'));
    },
    integrationTimeoutMs,
  );

  it('rejects colliding destinations during preflight', async () => {
    const target = await createTarget('collision');
    await expect(
      preflightGuidedLocalOnboarding({
        ...target.destinations,
        recoveryFile: target.keyFile,
      }),
    ).rejects.toMatchObject({ code: 'invalid' });
  });

  it('rejects database lock, registry, and reserved-path collisions', async () => {
    const target = await createTarget('internal-collisions');
    await expect(
      preflightGuidedLocalOnboarding({
        ...target.destinations,
        recoveryFile: target.dataFile + '.lock',
      }),
    ).rejects.toMatchObject({ code: 'invalid' });
    await expect(
      preflightGuidedLocalOnboarding({
        ...target.destinations,
        dataFile: join(target.configDirectory, 'datastore-profiles.json'),
      }),
    ).rejects.toMatchObject({ code: 'invalid' });
    await expect(
      preflightGuidedLocalOnboarding({
        ...target.destinations,
        reservedPaths: [target.keyFile],
      }),
    ).rejects.toMatchObject({ code: 'invalid' });
  });

  it.runIf(process.platform !== 'win32')(
    'rejects destinations aliased through a symbolic-link parent',
    async () => {
      const target = await createTarget('symlink-alias');
      const alias = join(dirname(target.keyFile), 'alias');
      await symlink(dirname(target.keyFile), alias, 'dir');

      await expect(
        preflightGuidedLocalOnboarding({
          ...target.destinations,
          recoveryFile: join(alias, 'owner.key'),
        }),
      ).rejects.toMatchObject({ code: 'invalid' });
    },
  );

  it('conservatively rejects case-only destination aliases on every platform', async () => {
    const target = await createTarget('case-alias');
    await expect(
      preflightGuidedLocalOnboarding({
        ...target.destinations,
        recoveryFile: target.keyFile.toUpperCase(),
      }),
    ).rejects.toMatchObject({ code: 'invalid' });
  });

  it('does not clone passphrases when registry opening fails', async () => {
    const target = await createTarget('registry-open-failure');
    const copies = vi.spyOn(Uint8Array, 'from');
    vi.spyOn(DatastoreProfileRegistry, 'open').mockRejectedValueOnce(
      new Error('registry unavailable'),
    );

    await expect(
      executeGuidedLocalOnboarding({
        ...target.destinations,
        databaseLabel: 'database',
        ownerPassphrase: OWNER_PASSPHRASE,
        vaultLabel: 'vault',
        recoveryPassphrase: RECOVERY_PASSPHRASE,
      }),
    ).rejects.toThrow('registry unavailable');
    expect(
      copies.mock.calls.some(
        ([input]) => input === OWNER_PASSPHRASE || input === RECOVERY_PASSPHRASE,
      ),
    ).toBe(false);
  });

  it('reports an uncertain initial route publication without creating artifacts', async () => {
    const target = await createTarget('route-publication-uncertain');
    vi.spyOn(
      DatastoreProfileRegistry.prototype,
      'addForInitialization',
    ).mockResolvedValueOnce({
      status: 'publication-uncertain',
      error: new DatastoreProfileError('PROFILE_UNSAFE'),
    });

    const failure = await executeGuidedLocalOnboarding({
      ...target.destinations,
      databaseLabel: 'database',
      ownerPassphrase: OWNER_PASSPHRASE,
      vaultLabel: 'vault',
      recoveryPassphrase: RECOVERY_PASSPHRASE,
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(GuidedLocalOnboardingError);
    expect(failure).toMatchObject({
      phase: 'profile-added',
      profileId: 'default',
    });
    expect((failure as Error).message).toContain('publication may be uncertain');
    await expect(access(target.dataFile)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(access(target.keyFile)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(access(target.recoveryFile)).rejects.toMatchObject({
      code: 'ENOENT',
    });
  });

  it('keeps an unselected route after a post-publication failure', async () => {
    const target = await createTarget('rollback');
    vi.spyOn(DatabaseSession, 'initialize').mockRejectedValueOnce(
      new DatabaseSessionError('operation'),
    );

    const failure = await executeGuidedLocalOnboarding({
      ...target.destinations,
      databaseLabel: 'database',
      ownerPassphrase: OWNER_PASSPHRASE,
      vaultLabel: 'vault',
      recoveryPassphrase: RECOVERY_PASSPHRASE,
    }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(GuidedLocalOnboardingError);
    expect(failure).toMatchObject({
      phase: 'profile-added',
      profileId: 'default',
    });
    expect((failure as Error).message).toContain('kavrix db profile list');
    expect((failure as Error).message).not.toContain('database');
    expect((failure as Error).message).not.toContain('vault');
    expect((failure as Error).message).not.toContain(OWNER_PASSPHRASE.toString('utf8'));

    const registry = await DatastoreProfileRegistry.open({
      configDirectory: target.configDirectory,
    });
    expect(await registry.list()).toEqual([
      expect.objectContaining({ id: 'default', datastore: 'file' }),
    ]);
    expect(await registry.current()).toBeNull();
  });

  it('retains the route and reports partial state after an ambiguous commit', async () => {
    const target = await createTarget('ambiguous');
    vi.spyOn(DatabaseSession, 'initialize').mockRejectedValueOnce(
      new DatabaseSessionError('ambiguous-commit'),
    );

    await expect(
      executeGuidedLocalOnboarding({
        ...target.destinations,
        databaseLabel: 'database',
        ownerPassphrase: OWNER_PASSPHRASE,
        vaultLabel: 'vault',
        recoveryPassphrase: RECOVERY_PASSPHRASE,
      }),
    ).rejects.toBeInstanceOf(GuidedLocalOnboardingError);

    const registry = await DatastoreProfileRegistry.open({
      configDirectory: target.configDirectory,
    });
    expect(await registry.list()).toEqual([
      expect.objectContaining({ id: 'default', datastore: 'file' }),
    ]);
    expect(await registry.current()).toBeNull();
  });
});

async function createTarget(label: string): Promise<
  Readonly<{
    dataFile: string;
    keyFile: string;
    recoveryFile: string;
    configDirectory: string;
    destinations: Readonly<{
      profileId: string;
      dataFile: string;
      keyFile: string;
      recoveryFile: string;
      registryOptions: Readonly<{ configDirectory: string }>;
    }>;
  }>
> {
  const directory = await mkdtemp(join(tmpdir(), `kavrix-guided-onboarding-${label}-`));
  directories.add(directory);
  const dataFile = join(directory, 'database.kavrix');
  const keyFile = join(directory, 'owner.key');
  const recoveryFile = join(directory, 'recovery.kavrix');
  const configDirectory = join(directory, 'config');
  return {
    dataFile,
    keyFile,
    recoveryFile,
    configDirectory,
    destinations: {
      profileId: 'default',
      dataFile,
      keyFile,
      recoveryFile,
      registryOptions: { configDirectory },
    },
  };
}
