import {
  access,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

import { vaultProfileSchema, type VaultProfile } from '@kavrix/client';
import { SealedSecretStore, sealedEntryFactory } from '@kavrix/key-files';
import { NativeProtectedSyncState } from '@kavrix/keychain';
import {
  acquireLocalWriterLease,
  openSqliteSyncLocalStore,
  openSqliteVaultProfileStore,
} from '@kavrix/local-store';
import { protectedLocalDeviceStateSchema } from '@kavrix/schemas';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { CliUsageError } from '../src/errors.js';
import {
  openProductionStatusEnvironment,
  type ProductionStatusEnvironmentDependencies,
} from '../src/production/environment.js';
import { resolveCliDataPaths } from '../src/production/paths.js';
import { ensureDataDirectory } from '../src/production/runtime-adapters.js';
import type { SecretBackend } from '../src/production/secret-backend.js';
import {
  runProductionStatus,
  type ProductionStatusDependencies,
} from '../src/production/status.js';
import { acquiredSecretSchema, type SecretInputPort } from '../src/secret-input.js';

const TEST_TMPDIR = await realpath(tmpdir());
const PASSPHRASE = 'status-passphrase-canary-4b';
const UPDATED_AT = '2026-08-10T01:02:03.000Z';
const roots: string[] = [];

afterEach(async () => {
  vi.unstubAllGlobals();
  await Promise.all(
    roots.splice(0).map(async (root) => {
      if (
        dirname(root) !== TEST_TMPDIR ||
        !root.startsWith(join(TEST_TMPDIR, 'kavrix-production-status-'))
      ) {
        throw new Error('Refusing unsafe production-status test cleanup');
      }
      await rm(root, { recursive: true, force: true });
    }),
  );
});

describe('production status composition', () => {
  it('reads canonical local state as locked/offline without network or plaintext', async () => {
    const fixture = await statusFixture();
    const fetch = vi.fn(() => Promise.reject(new Error('network-must-not-run')));
    vi.stubGlobal('fetch', fetch);

    const { status, read } = await readStatus(fixture.home);

    expect(status).toEqual({
      vaultState: 'locked',
      vaultId: fixture.profile.vaultId,
      deviceId: fixture.profile.deviceId,
      syncState: 'offline',
      pendingChanges: 0,
      lastSyncAt: UPDATED_AT,
    });
    expect(read).toHaveBeenCalledExactlyOnceWith({
      kind: 'passphrase',
      fromStdin: true,
    });
    expect(fetch).not.toHaveBeenCalled();
    expect(JSON.stringify(status)).not.toContain(PASSPHRASE);
    expect(await treeContains(fixture.home, PASSPHRASE)).toBe(false);
    expect(await writerLocks(fixture.home)).toEqual([]);
    await expect(access(fixture.paths.initializationJournal)).rejects.toBeDefined();
    await expect(access(fixture.paths.joinJournal)).rejects.toBeDefined();
  });

  it('rejects zero or multiple profiles before protected secret input', async () => {
    const emptyHome = await temporaryHome();
    const empty = secretPort(PASSPHRASE);
    await expect(
      runProductionStatus({
        environment: { CREDS_HOME: emptyHome },
        secrets: empty.port,
        backendPolicy: { kind: 'sealed-file', passphraseFromStdin: true },
      }),
    ).rejects.toThrow('No vault profile is enrolled in this data home.');
    expect(empty.read).not.toHaveBeenCalled();
    expect(await writerLocks(emptyHome)).toEqual([]);

    const multipleHome = await temporaryHome();
    const paths = resolveCliDataPaths({ CREDS_HOME: multipleHome });
    await ensureDataDirectory(multipleHome);
    const profiles = await openSqliteVaultProfileStore({ path: paths.profileStore });
    await profiles.store(profileRecord('primary'));
    await profiles.store(profileRecord('secondary'));
    await profiles.close();
    const multiple = secretPort(PASSPHRASE);
    await expect(
      runProductionStatus({
        environment: { CREDS_HOME: multipleHome },
        secrets: multiple.port,
        backendPolicy: { kind: 'sealed-file', passphraseFromStdin: false },
      }),
    ).rejects.toThrow(/More than one vault is enrolled/u);
    expect(multiple.read).not.toHaveBeenCalled();
    expect(await writerLocks(multipleHome)).toEqual([]);
    await expect(access(paths.sealedSecrets)).rejects.toBeDefined();
  });

  it('ignores unrelated corrupt lifecycle journals without opening them', async () => {
    const fixture = await statusFixture();
    const initBytes = Buffer.from('corrupt-init-journal-canary');
    const joinBytes = Buffer.from('corrupt-join-journal-canary');
    await writeFile(fixture.paths.initializationJournal, initBytes);
    await writeFile(fixture.paths.joinJournal, joinBytes);

    await expect(
      readStatus(fixture.home).then(({ status }) => status),
    ).resolves.toMatchObject({ vaultState: 'locked', syncState: 'offline' });
    expect(await readFile(fixture.paths.initializationJournal)).toEqual(initBytes);
    expect(await readFile(fixture.paths.joinJournal)).toEqual(joinBytes);
    expect(await writerLocks(fixture.home)).toEqual([]);
  });

  it('rejects relative homes and corrupt profile or sync stores fail closed', async () => {
    const relative = secretPort(PASSPHRASE);
    const relativeHome = `relative-status-${randomUUID()}`;
    const accidentalHome = resolve(relativeHome);
    await expect(access(accidentalHome)).rejects.toBeDefined();
    await expect(
      runProductionStatus({
        environment: { CREDS_HOME: relativeHome },
        secrets: relative.port,
        backendPolicy: { kind: 'sealed-file', passphraseFromStdin: true },
      }),
    ).rejects.toBeInstanceOf(CliUsageError);
    expect(relative.read).not.toHaveBeenCalled();
    await expect(access(accidentalHome)).rejects.toBeDefined();

    const profileHome = await temporaryHome();
    await ensureDataDirectory(profileHome);
    const profilePaths = resolveCliDataPaths({ CREDS_HOME: profileHome });
    await writeFile(profilePaths.profileStore, 'corrupt-profile-store');
    const profileSecrets = secretPort(PASSPHRASE);
    await expect(
      runProductionStatus({
        environment: { CREDS_HOME: profileHome },
        secrets: profileSecrets.port,
        backendPolicy: { kind: 'sealed-file', passphraseFromStdin: true },
      }),
    ).rejects.toBeDefined();
    expect(profileSecrets.read).not.toHaveBeenCalled();
    expect(await writerLocks(profileHome)).toEqual([]);

    const syncFixture = await statusFixture();
    await writeFile(syncFixture.paths.vaultStore(syncFixture.profile.vaultId), 'bad');
    const syncSecrets = secretPort(PASSPHRASE);
    await expect(
      runProductionStatus({
        environment: { CREDS_HOME: syncFixture.home },
        secrets: syncSecrets.port,
        backendPolicy: { kind: 'sealed-file', passphraseFromStdin: true },
      }),
    ).rejects.toBeDefined();
    expect(syncSecrets.read).not.toHaveBeenCalled();
    expect(await writerLocks(syncFixture.home)).toEqual([]);
  });

  it('keeps wrong and corrupt protected material generic and releases its lease', async () => {
    const wrongFixture = await statusFixture();
    const wrong = secretPort('wrong-status-passphrase-canary');
    const wrongOperation = runProductionStatus({
      environment: { CREDS_HOME: wrongFixture.home },
      secrets: wrong.port,
      backendPolicy: { kind: 'sealed-file', passphraseFromStdin: true },
    });
    await expect(wrongOperation).rejects.toBeDefined();
    await expect(wrongOperation).rejects.not.toThrow(/passphrase-canary/u);
    expect(await writerLocks(wrongFixture.home)).toEqual([]);

    const corruptFixture = await statusFixture();
    const [sealedFile] = await regularFiles(corruptFixture.paths.sealedSecrets);
    if (sealedFile === undefined) throw new Error('Missing sealed-state fixture');
    const bytes = await readFile(sealedFile);
    const lastIndex = bytes.length - 1;
    const lastByte = bytes[lastIndex];
    if (lastByte === undefined) throw new Error('Empty sealed-state fixture');
    bytes[lastIndex] = lastByte ^ 0xff;
    await writeFile(sealedFile, bytes);
    const corruptOperation = readStatus(corruptFixture.home);
    await expect(corruptOperation).rejects.toBeDefined();
    await expect(corruptOperation).rejects.not.toThrow(/passphrase-canary/u);
    expect(await writerLocks(corruptFixture.home)).toEqual([]);
  });

  it('fails under a live global lease, then succeeds after the owner releases it', async () => {
    const fixture = await statusFixture();
    const lease = await acquireLocalWriterLease(fixture.paths.writerLease);
    const blocked = secretPort(PASSPHRASE);
    try {
      await expect(
        runProductionStatus({
          environment: { CREDS_HOME: fixture.home },
          secrets: blocked.port,
          backendPolicy: { kind: 'sealed-file', passphraseFromStdin: true },
        }),
      ).rejects.toBeDefined();
      expect(blocked.read).not.toHaveBeenCalled();
      await expect(access(fixture.paths.writerLease)).resolves.toBeUndefined();
    } finally {
      await lease.release();
    }
    expect(await writerLocks(fixture.home)).toEqual([]);
    await expect(
      readStatus(fixture.home).then(({ status }) => status),
    ).resolves.toMatchObject({ vaultState: 'locked', syncState: 'offline' });
    expect(await writerLocks(fixture.home)).toEqual([]);
  });

  it('acquires only status resources, owns backend rollback, and rejects reuse', async () => {
    const events: string[] = [];
    const dependencies = statusEnvironmentDependencies(events);
    const backend = fakeBackend(events);
    const environment = await openProductionStatusEnvironment(
      resolveCliDataPaths({ CREDS_HOME: join(TEST_TMPDIR, 'status-fake-home') }),
      backend,
      dependencies,
    );

    expect(events).toEqual(['secure-directory', 'lease', 'profiles']);
    await environment.close();
    expect(events).toEqual([
      'secure-directory',
      'lease',
      'profiles',
      'profiles-close',
      'backend-close',
      'lease-release',
    ]);
    await expect(
      environment.openSyncStore(profileRecord('primary')),
    ).rejects.toBeInstanceOf(CliUsageError);

    const openFailure = new Error('profile-open-canary');
    const backendFailure = new Error('backend-close-canary');
    const failureEvents: string[] = [];
    const failedBackend = fakeBackend(failureEvents, () => {
      failureEvents.push('backend-close');
      return Promise.reject(backendFailure);
    });
    await expect(
      openProductionStatusEnvironment(
        resolveCliDataPaths({ CREDS_HOME: join(TEST_TMPDIR, 'status-fake-fail') }),
        failedBackend,
        statusEnvironmentDependencies(failureEvents, {
          openProfiles: () => Promise.reject(openFailure),
        }),
      ),
    ).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof AggregateError &&
        error.errors[0] === openFailure &&
        error.errors[1] === backendFailure &&
        !error.message.includes('canary'),
    );
    expect(failureEvents).toEqual([
      'secure-directory',
      'lease',
      'backend-close',
      'lease-release',
    ]);
  });

  it('retains operation and cleanup failures in order and surfaces cleanup-only failure', async () => {
    const profile = profileRecord('primary');
    const primary = new Error('status-primary-canary');
    const cleanup = new Error('status-cleanup-canary');
    const close = vi.fn(() => Promise.reject(cleanup));
    const dependencies = compositionDependencies(profile, close, () =>
      Promise.reject(primary),
    );

    await expect(
      runProductionStatus(
        {
          environment: { CREDS_HOME: join(TEST_TMPDIR, 'status-compose-fake') },
          secrets: secretPort(PASSPHRASE).port,
          backendPolicy: { kind: 'native' },
        },
        dependencies,
      ),
    ).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof AggregateError &&
        error.errors[0] === primary &&
        error.errors[1] === cleanup &&
        !error.message.includes('canary'),
    );
    expect(close).toHaveBeenCalledOnce();

    const cleanupOnly = new Error('cleanup-only-canary');
    await expect(
      runProductionStatus(
        {
          environment: { CREDS_HOME: join(TEST_TMPDIR, 'status-compose-cleanup') },
          secrets: secretPort(PASSPHRASE).port,
          backendPolicy: { kind: 'native' },
        },
        compositionDependencies(
          profile,
          () => Promise.reject(cleanupOnly),
          () =>
            Promise.resolve({
              vaultState: 'locked',
              vaultId: profile.vaultId,
              deviceId: profile.deviceId,
              syncState: 'offline',
              pendingChanges: 0,
            }),
        ),
      ),
    ).rejects.toBe(cleanupOnly);
  });
});

async function statusFixture(): Promise<
  Readonly<{
    home: string;
    paths: ReturnType<typeof resolveCliDataPaths>;
    profile: VaultProfile;
  }>
> {
  const home = await temporaryHome();
  await ensureDataDirectory(home);
  const paths = resolveCliDataPaths({ CREDS_HOME: home });
  const profile = profileRecord('primary');
  const profiles = await openSqliteVaultProfileStore({ path: paths.profileStore });
  await profiles.store(profile);
  await profiles.close();
  const sync = await openSqliteSyncLocalStore({
    path: paths.vaultStore(profile.vaultId),
  });
  sync.close();

  const store = new SealedSecretStore({
    directory: paths.sealedSecrets,
    passphrase: () => Promise.resolve(Buffer.from(PASSPHRASE, 'utf8')),
  });
  const protectedState = new NativeProtectedSyncState(sealedEntryFactory(store));
  await protectedState.save(
    protectedLocalDeviceStateSchema.parse({
      vaultId: profile.vaultId,
      deviceId: profile.deviceId,
      highestSeenVaultRevision: 7,
      updatedAt: UPDATED_AT,
    }),
  );
  await store.close();
  return { home, paths, profile };
}

async function readStatus(home: string): Promise<
  Readonly<{
    status: Awaited<ReturnType<typeof runProductionStatus>>;
    read: ReturnType<typeof vi.fn<SecretInputPort['read']>>;
  }>
> {
  const secrets = secretPort(PASSPHRASE);
  const status = await runProductionStatus({
    environment: { CREDS_HOME: home, CREDS_SERVER_URL: 'https://ignored.invalid/' },
    secrets: secrets.port,
    backendPolicy: { kind: 'sealed-file', passphraseFromStdin: true },
  });
  return { status, read: secrets.read };
}

function profileRecord(suffix: string): VaultProfile {
  const vaultId = `vault.${suffix}`;
  const deviceId = `device.${suffix}`;
  return vaultProfileSchema.parse({
    version: 1,
    serverUrl: 'https://sync.example/',
    vaultId,
    deviceId,
    deviceLocator: {
      version: 1,
      vaultId,
      deviceId,
      keySlotId: `slot.${suffix}`,
    },
    sessionLocator: { version: 1, vaultId, deviceId, purpose: 'api-session' },
  });
}

function secretPort(value: string): Readonly<{
  port: SecretInputPort;
  read: ReturnType<typeof vi.fn<SecretInputPort['read']>>;
}> {
  const read = vi.fn<SecretInputPort['read']>(() =>
    Promise.resolve(acquiredSecretSchema.parse(value)),
  );
  return {
    read,
    port: {
      read,
      readBatch: () => Promise.reject(new Error('unexpected secret batch read')),
    },
  };
}

async function temporaryHome(): Promise<string> {
  const root = await mkdtemp(join(TEST_TMPDIR, 'kavrix-production-status-'));
  roots.push(root);
  return root;
}

async function regularFiles(root: string): Promise<string[]> {
  const files: string[] = [];
  const visit = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) files.push(path);
    }
  };
  await visit(root);
  return files.sort();
}

async function writerLocks(root: string): Promise<string[]> {
  return (await regularFiles(root)).filter((path) => path.endsWith('.writer.lock'));
}

async function treeContains(root: string, value: string): Promise<boolean> {
  const needle = Buffer.from(value, 'utf8');
  for (const path of await regularFiles(root)) {
    if ((await readFile(path)).includes(needle)) return true;
  }
  return false;
}

function fakeBackend(
  events: string[],
  close: () => Promise<void> = () => {
    events.push('backend-close');
    return Promise.resolve();
  },
): SecretBackend {
  return {
    kind: 'native',
    keychain: {} as never,
    sessions: {} as never,
    protectedSyncState: {} as never,
    joinJournalSecrets: {} as never,
    close,
  };
}

function statusEnvironmentDependencies(
  events: string[],
  overrides: Partial<ProductionStatusEnvironmentDependencies> = {},
): ProductionStatusEnvironmentDependencies {
  return {
    ensureDataDirectory: () => {
      events.push('secure-directory');
      return Promise.resolve();
    },
    acquireLease: () => {
      events.push('lease');
      return Promise.resolve({
        path: 'lease',
        release: () => {
          events.push('lease-release');
          return Promise.resolve();
        },
      });
    },
    recoverLease: () => Promise.resolve('absent'),
    openProfiles: () => {
      events.push('profiles');
      return Promise.resolve({
        close: () => {
          events.push('profiles-close');
          return Promise.resolve();
        },
      } as never);
    },
    openSyncStore: () => Promise.resolve({ close: () => undefined } as never),
    ...overrides,
  };
}

function compositionDependencies(
  profile: VaultProfile,
  close: () => Promise<void>,
  readStatus: ProductionStatusDependencies['readStatus'],
): Partial<ProductionStatusDependencies> {
  return {
    createBackend: () => Promise.resolve(fakeBackend([])),
    openEnvironment: () =>
      Promise.resolve({
        profiles: {} as never,
        openSyncStore: () => Promise.reject(new Error('unexpected sync open')),
        close,
      }),
    resolveProfile: () => Promise.resolve(profile),
    readStatus,
  };
}
